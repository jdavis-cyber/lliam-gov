"""File deletes require consent even inside an ordinary working directory."""

import json
import shlex
import sys

import pytest

from lliam_constants import get_lliam_home
from tools import approval


@pytest.mark.parametrize("command,expected_description", [
    ('rm -- scratch/throwaway-file-n.txt', 'file/directory delete'),
    ('rm scratch/file.txt', 'file/directory delete'),
    ("rm -f 'scratch/file with spaces.txt'", 'file/directory delete'),
    ('/bin/rm -- scratch/file.txt', 'file/directory delete'),
    ('sudo rm scratch/file.txt', 'file/directory delete'),
    ('env rm scratch/file.txt', 'file/directory delete'),
    ('cd scratch && rm file.txt', 'file/directory delete'),
    ('true; rm scratch/file.txt', 'file/directory delete'),
    ('true\nrm scratch/file.txt', 'file/directory delete'),
    ('unlink scratch/file.txt', 'file/directory delete'),
    ('/usr/bin/unlink scratch/file.txt', 'file/directory delete'),
    ('rmdir scratch/empty', 'file/directory delete'),
    ("find scratch -name '*.txt' -delete", 'find -delete'),
    ('find scratch -exec unlink {} \\;', 'file/directory delete'),
    ('find scratch -type d -execdir rmdir {} \\;', 'file/directory delete'),
    ("printf '%s\\n' scratch/file.txt | xargs unlink", 'file/directory delete'),
    ('python3.11 -c "os.remove(\'scratch/file.txt\')"', 'script execution via -e/-c flag'),
    ('python3.11 -c "os . remove (\'scratch/file.txt\')"', 'script execution via -e/-c flag'),
    ('python3.11 -c "os.unlink(\'scratch/file.txt\')"', 'script execution via -e/-c flag'),
    ('python3.11 -c "os.rmdir(\'scratch/empty\')"', 'script execution via -e/-c flag'),
    ('python3.11 -c "os.removedirs(\'scratch/empty\')"', 'script execution via -e/-c flag'),
    ('python3.11 -c "from os import remove; remove(\'scratch/file.txt\')"', 'script execution via -e/-c flag'),
    ('python3.11 -c "from os import unlink; unlink(\'scratch/file.txt\')"', 'script execution via -e/-c flag'),
    ('python3.11 -c "Path(\'scratch/file.txt\').unlink()"', 'script execution via -e/-c flag'),
    ('python3.11 -c "pathlib.Path(\'scratch/empty\').rmdir()"', 'script execution via -e/-c flag'),
    ('python3.11 -c "shutil.rmtree(\'scratch/tree\')"', 'script execution via -e/-c flag'),
    ('python3.11 -c "from shutil import rmtree; rmtree(\'scratch/tree\')"', 'script execution via -e/-c flag'),
    ("python3 - <<'PY'\nimport os\nos.remove('scratch/file.txt')\nPY", 'script execution via heredoc'),
    ('python3.11 -c "import os; os.remove(\'scratch/file.txt\')"', 'script execution via -e/-c flag'),
])
def test_delete_detection_is_independent_of_target_path(command, expected_description):
    assert approval.detect_dangerous_command(command) == (True, expected_description, expected_description)


@pytest.mark.parametrize("command", [
    "ls scratch",
    "cat scratch/file.txt",
    "mkdir scratch/empty",
    "echo removal complete",
    "git status",
    "os.stat('scratch/file.txt')",
    "items.remove('scratch/file.txt')",
    "Path('scratch/file.txt').read_text()",
])
def test_non_delete_operations_remain_safe(command):
    assert approval.detect_dangerous_command(command) == (False, None, None)


@pytest.fixture
def desktop_terminal(tmp_path, monkeypatch):
    """Use the real local terminal and gateway guard with an isolated home."""
    from tools import terminal_tool

    assert get_lliam_home().is_relative_to(tmp_path.parent)
    assert approval._get_approval_mode() == "manual"
    monkeypatch.setenv("TERMINAL_ENV", "local")
    monkeypatch.setenv("TERMINAL_CWD", str(tmp_path))
    monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")
    session = f"file-delete-{tmp_path.name}"
    token = approval.set_current_session_key(session)
    try:
        yield terminal_tool, session
    finally:
        terminal_tool.cleanup_vm(session)
        approval.unregister_gateway_notify(session)
        approval.clear_session(session)
        approval.reset_current_session_key(token)


@pytest.mark.skipif(sys.platform == "win32", reason="Executes POSIX shell commands")
@pytest.mark.parametrize("operation,is_directory", [
    ("rm -- {path}", False),
    ("unlink {path}", False),
    ("rmdir {path}", True),
    ("find {path} -delete", False),
    ("{python} -c \"import os; os.remove('{path}')\"", False),
    ("{python} - <<'PY'\nimport os\nos.remove('{path}')\nPY", False),
    ("{python} - <<'PY'\nfrom os import remove\nremove('{path}')\nPY", False),
    ("{python} - <<'PY'\nimport os\nos.unlink('{path}')\nPY", False),
    ("{python} - <<'PY'\nfrom pathlib import Path\nPath('{path}').unlink()\nPY", False),
    ("{python} - <<'PY'\nfrom pathlib import Path\nPath('{path}').rmdir()\nPY", True),
    ("{python} - <<'PY'\nimport shutil\nshutil.rmtree('{path}')\nPY", True),
])
def test_terminal_delete_prompts_before_execution(
    desktop_terminal, tmp_path, operation, is_directory,
):
    terminal, session = desktop_terminal
    relative_path = "scratch/throwaway-file-n.txt"
    target = tmp_path / relative_path
    target.parent.mkdir()
    if is_directory:
        target.mkdir()
    else:
        target.write_bytes(b"keep until approved\n")
    sibling = target.parent / "keep.txt"
    sibling.write_bytes(b"untouched\n")
    # Use a stable interpreter command name even when the test runner's Python
    # executable has a vendor-specific basename.
    python = tmp_path / "python3"
    python.symlink_to(sys.executable)
    command = operation.format(path=relative_path, python=shlex.quote(str(python)))

    # Deny first, then approve the same command. No guard or executor is mocked.
    for choice in ("deny", "once"):
        requests = []

        def respond(data):
            requests.append(data)
            assert data["command"] == command
            assert relative_path in data["command"]
            assert target.exists(), "Delete ran before consent"
            assert "delete" in data["description"]
            assert data["allow_permanent"] is False
            assert data["allow_session"] is False
            assert approval.resolve_gateway_approval(session, choice) == 1

        approval.register_gateway_notify(session, respond)
        result = json.loads(terminal.terminal_tool(
            command, task_id=session, workdir=str(tmp_path), timeout=10,
        ))
        assert len(requests) == 1, result
        if choice == "deny":
            assert "BLOCKED" in result["error"]
            assert target.exists()
            if not is_directory:
                assert target.read_bytes() == b"keep until approved\n"
        else:
            assert result["exit_code"] == 0, result
            assert not target.exists()
            assert not approval.is_approved(session, requests[0]["pattern_key"])
        assert sibling.read_bytes() == b"untouched\n"


@pytest.mark.parametrize("choice", ["session", "always"])
@pytest.mark.parametrize("command", [
    "rm {path}",
    "python3.11 -c \"import os; os.remove('{path}')\"",
    "python3.11 -c \"from pathlib import Path; Path('{path}').unlink()\"",
])
def test_delete_approval_is_once_only(desktop_terminal, command, choice):
    _, session = desktop_terminal
    requests = []

    def respond(data):
        requests.append(data)
        approval.resolve_gateway_approval(session, choice)

    approval.register_gateway_notify(session, respond)
    for name in ("first.txt", "second.txt"):
        # Denied execution is tested above; here use the real guard to cover
        # persistence without depending on installed interpreter versions.
        result = approval.check_all_command_guards(command.format(path=name), "local")
        assert result["approved"], result
    assert len(requests) == 2
    for request in requests:
        assert request.get("allow_permanent") is False
        assert request.get("allow_session") is False
        assert not approval.is_approved(session, request["pattern_key"])
    assert not (get_lliam_home() / "config.yaml").exists()


def test_smart_delete_approval_does_not_cover_the_next_delete(desktop_terminal, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    _, session = desktop_terminal
    (get_lliam_home() / "config.yaml").write_text("approvals:\n  mode: smart\n", encoding="utf-8")
    llm = Mock(side_effect=[
        SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="APPROVE"))]),
        SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="ESCALATE"))]),
    ])
    monkeypatch.setattr("agent.auxiliary_client.call_llm", llm)
    requests = []

    def deny(data):
        requests.append(data)
        approval.resolve_gateway_approval(session, "deny")

    approval.register_gateway_notify(session, deny)
    assert approval.check_all_command_guards("rm first.txt", "local")["approved"]
    assert not approval.check_all_command_guards("rm second.txt", "local")["approved"]
    assert len(requests) == 1


@pytest.mark.parametrize("command,expected_description", [
    ("docker run --rm img", None),
    ("docker rm c1", None),
    ("npm rm pkg", None),
    ("echo 'rm notes'", None),
    ('git commit -m "rm stale file"', None),
    ("git rm file", "file/directory delete"),
    ("command rm f", "file/directory delete"),
    ("exec unlink f", "file/directory delete"),
    ("nohup rmdir d", "file/directory delete"),
    ("true & rm f", "file/directory delete"),
    ("true || rm f", "file/directory delete"),
    ("true | rm f", "file/directory delete"),
    ("echo $(rm f)", "file/directory delete"),
    ("echo `rm f`", "file/directory delete"),
])
def test_shell_delete_command_positions(command, expected_description):
    assert approval.detect_dangerous_command(command) == (
        expected_description is not None, expected_description, expected_description,
    )


@pytest.mark.parametrize("guard", [approval.check_all_command_guards, approval.check_dangerous_command])
@pytest.mark.parametrize("command,preapproved", [
    ("bash -c 'rm f'", "shell command via -c/-lc flag"),
    ('python3 -c "import os; os.remove(\'f\')"', "script execution via -e/-c flag"),
])
def test_preapproved_wrapper_still_prompts_for_delete(desktop_terminal, monkeypatch, guard, command, preapproved):
    _, session = desktop_terminal
    monkeypatch.delenv("HERMES_GATEWAY_SESSION")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    approval.approve_session(session, preapproved)
    requests = []

    def deny(cmd, description, **scope):
        requests.append((description, scope))
        return "deny"

    assert not guard(command, "local", approval_callback=deny)["approved"]
    assert len(requests) == 1
    assert "delete" in requests[0][0]
    assert requests[0][1] == {"allow_permanent": False, "allow_session": False}


@pytest.mark.parametrize("command", [
    'grep -n "remove(" f',
    r"rg 'unlink\('",
    'git commit -m "guard os.remove() calls"',
])
def test_python_delete_mentions_are_not_executed_code(command):
    assert approval.detect_dangerous_command(command) == (False, None, None)


@pytest.mark.parametrize("command,expected_description", [
    ('"rm" f', "file/directory delete"),
    ("'rm' f", "file/directory delete"),
    ('r"m" f', "file/directory delete"),
    ("`which rm` f", "file/directory delete"),
    ("$(which rm) f", "file/directory delete"),
    ("rm${IFS}f", "file/directory delete"),
    ("echo cm0gZg== | base64 -d | sh", "file/directory delete via decoded shell"),
    ("echo 726d2066 | xxd -r -p | bash", "file/directory delete via decoded shell"),
])
def test_obfuscated_delete_commands(command, expected_description):
    assert approval.detect_dangerous_command(command) == (True, expected_description, expected_description)


@pytest.mark.parametrize("command,delete_description", [
    ('python3.12 -c "import os; os.remove(\'f\')"', "file/directory delete via Python os"),
    ('python3.11 -c "import os as o; o.remove(\'f\')"', "file/directory delete via Python os"),
    ("python3 - <<EOF\nimport os as o\no.remove('f')\nEOF", "file/directory delete via Python os"),
    ('python3 -c "import os as o; o.removedirs(\'d\')"', "file/directory delete via Python os"),
    ('python3 -c "import os as o; o.unlink(\'f\')"', "file/directory delete via Python pathlib/os/shutil"),
    ('python3 -c "import os as o; o.rmdir(\'d\')"', "file/directory delete via Python pathlib/os/shutil"),
    ('python3 -c "import shutil as s; s.rmtree(\'d\')"', "file/directory delete via Python pathlib/os/shutil"),
    ('python3 -c "import os; getattr(os, \'remove\')(\'f\')"', "file/directory delete via Python os"),
    ('python3 -c "__import__(\'os\').remove(\'f\')"', "file/directory delete via Python os"),
    ('python3 -c "import subprocess; subprocess.run([\'rm\', \'f\'])"', "file/directory delete via Python os"),
])
def test_python_delete_variants_need_once_only_consent(desktop_terminal, command, delete_description):
    _, session = desktop_terminal
    approval.approve_session(session, "script execution via -e/-c flag")
    approval.approve_session(session, "script execution via heredoc")
    requests = []

    def deny(data):
        requests.append(data)
        approval.resolve_gateway_approval(session, "deny")

    approval.register_gateway_notify(session, deny)
    assert not approval.check_all_command_guards(command, "local")["approved"]
    assert len(requests) == 1
    assert delete_description in requests[0]["description"]
    assert requests[0]["allow_session"] is False
    assert requests[0]["allow_permanent"] is False


@pytest.mark.parametrize("command,expected_description", [
    ("node -e \"require('fs').rmSync('f')\"", "file/directory delete via Node.js"),
    ("node -e \"require('node:fs').unlinkSync('f')\"", "file/directory delete via Node.js"),
    ("node -p \"require('fs').rmdirSync('d')\"", "file/directory delete via Node.js"),
    ("node -e \"const {rmSync}=require('fs'); rmSync('f')\"", "file/directory delete via Node.js"),
    ("node --eval \"const {unlinkSync}=require('node:fs'); unlinkSync('f')\"", "file/directory delete via Node.js"),
    ("node --eval=\"const {rmdirSync}=require('fs'); rmdirSync('d')\"", "file/directory delete via Node.js"),
    ("node -e \"require('fs/promises').rm('f')\"", "file/directory delete via Node.js"),
    ("node -e \"import('fs/promises').then(m=>m.unlink('f'))\"", "file/directory delete via Node.js"),
    ("node -p \"require('node:fs/promises').rmdir('d')\"", "file/directory delete via Node.js"),
    ("node -e \"const {rm}=require('fs/promises'); rm('f')\"", "file/directory delete via Node.js"),
    ("node -e \"const {unlink}=require('node:fs'); unlink('f', ()=>{})\"", "file/directory delete via Node.js"),
    ("node -e \"const {rmdir}=require('fs'); rmdir('d', ()=>{})\"", "file/directory delete via Node.js"),
    ("node -e \"fs.rm('f', ()=>{})\"", "file/directory delete via Node.js"),
    ("node -e \"fs.unlink('f', ()=>{})\"", "file/directory delete via Node.js"),
    ("node -e \"fs.rmdir('d', ()=>{})\"", "file/directory delete via Node.js"),
    ("node <<'JS'\nconst {rmSync}=require('fs');\nrmSync('f')\nJS", "file/directory delete via Node.js"),
    ("node - <<'JS'\nimport {unlink} from 'node:fs/promises';\nunlink('f')\nJS", "file/directory delete via Node.js"),
    ("node -e \"const filesystem = require('fs'); filesystem.unlinkSync('f')\"", "file/directory delete via Node.js"),
    ("npm rm package", None),
    ("node -e \"console.log('npm rm')\"", None),
    ("node -e \"element.remove()\"", None),
    ("node -e \"require('fs'); element.remove()\"", None),
    ("node -e \"require('fs'); console.log('npm rm')\"", None),
    ("node -e \"require('other').rm('f')\"", None),
    ("node -e \"require('fs-extra').rm('f')\"", None),
    ("rg \"require('fs').rmSync('f')\"", None),
    ("node -e \"console.log('ok')\"; rg \"require('fs').rmSync('f')\"", None),
])
def test_node_delete_forms_have_a_distinct_approval_key(command, expected_description):
    matches = approval.detect_all_dangerous_commands(command)
    if expected_description is None:
        assert ("file/directory delete via Node.js", "file/directory delete via Node.js") not in matches
    else:
        assert (expected_description, expected_description) in matches


@pytest.mark.parametrize("command,delete_description", [
    ('node -e "fs.rmSync(\'f\')"', "file/directory delete via Node.js"),
    ('node -p "fs.unlinkSync(\'f\')"', "file/directory delete via Node.js"),
    ('node --eval "fs.rmdirSync(\'d\')"', "file/directory delete via Node.js"),
    ('node -e "fs.promises.rm(\'f\')"', "file/directory delete via Node.js"),
    ('node -e "fs.promises.unlink(\'f\')"', "file/directory delete via Node.js"),
    ('ruby -e "File.delete(\'f\')"', "file/directory delete via Ruby"),
    ('ruby -e"File.unlink(\'f\')"', "file/directory delete via Ruby"),
    ('ruby -e "FileUtils.rm(\'f\')"', "file/directory delete via Ruby"),
    ('ruby -e "FileUtils.rm_f(\'f\')"', "file/directory delete via Ruby"),
    ('ruby -e "FileUtils.rm_rf(\'d\')"', "file/directory delete via Ruby"),
    ('perl -e "unlink \'f\'"', "file/directory delete via Perl"),
    ('perl -e"unlink(\'f\')"', "file/directory delete via Perl"),
    ('perl -e "remove_tree(\'d\')"', "file/directory delete via Perl"),
    ('perl -e"remove_tree(\'d\')"', "file/directory delete via Perl"),
    ('deno eval "Deno.remove(\'f\')"', "file/directory delete via Deno"),
    ('deno eval "Deno.removeSync(\'d\')"', "file/directory delete via Deno"),
    ('shred -u f', "file/directory delete via shred"),
    ('rsync --delete src/ dst/', "file/directory delete via rsync"),
    ('rsync --remove-source-files src/ dst/', "file/directory delete via rsync"),
    ('tar --remove-files -cf archive.tar f', "file/directory delete via tar"),
])
def test_other_delete_tools_require_once_only_consent(desktop_terminal, command, delete_description):
    _, session = desktop_terminal
    approval.approve_session(session, "script execution via -e/-c flag")
    requests = []

    def respond(data):
        requests.append(data)
        approval.resolve_gateway_approval(session, "always")

    approval.register_gateway_notify(session, respond)
    for cmd in (command, command.replace("'f'", "'second'").replace("'d'", "'other'") + " "):
        assert approval.check_all_command_guards(cmd, "local")["approved"]
    assert len(requests) == 2
    for request in requests:
        assert delete_description in request["description"]
        assert request["allow_permanent"] is False
        assert request["allow_session"] is False


def test_find_delete_never_inherits_previous_consent(desktop_terminal):
    _, session = desktop_terminal
    requests = []

    def respond(data):
        requests.append(data)
        approval.resolve_gateway_approval(session, "session")

    approval.register_gateway_notify(session, respond)
    for path in ("first", "second"):
        assert approval.check_all_command_guards(f"find {path} -delete", "local")["approved"]
    assert len(requests) == 2
    assert all(r["allow_session"] is False for r in requests)


@pytest.mark.parametrize("command,expected_description", [
    ("echo 'sudo rm notes'", None),
    ('git commit -m "env rm oldfile"', None),
    ("sudo -u root rm f", "file/directory delete"),
    ("env KEEP=1 rm f", "file/directory delete"),
    ('sudo "rm" f', "file/directory delete"),
])
def test_delete_wrappers_are_commands_not_quoted_prose(command, expected_description):
    assert approval.detect_dangerous_command(command) == (
        expected_description is not None, expected_description, expected_description,
    )


@pytest.mark.parametrize("command,has_delete", [
    (r'''python3 -c "print(\"hi\"); import os; os.remove('f')"''', True),
    ('''python3 -c "print('hi')"; rg 'os.remove()' f''', False),
])
def test_python_code_boundaries_preserve_escaped_quotes(desktop_terminal, command, has_delete):
    _, session = desktop_terminal
    requests = []

    def deny(data):
        requests.append(data)
        approval.resolve_gateway_approval(session, "deny")

    approval.register_gateway_notify(session, deny)
    assert not approval.check_all_command_guards(command, "local")["approved"]
    assert len(requests) == 1
    assert ("delete" in requests[0]["description"]) is has_delete
    assert requests[0]["allow_session"] is not has_delete


@pytest.mark.parametrize("guard", [approval.check_all_command_guards, approval.check_dangerous_command])
@pytest.mark.parametrize("choice", ["session", "always"])
def test_cli_delete_answers_do_not_persist(desktop_terminal, monkeypatch, guard, choice):
    _, session = desktop_terminal
    monkeypatch.delenv("HERMES_GATEWAY_SESSION")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    requests = []

    def respond(command, description, **scope):
        requests.append(scope)
        return choice

    for command in ("rm first.txt", "rm second.txt"):
        assert guard(command, "local", approval_callback=respond)["approved"]
    assert requests == [{"allow_permanent": False, "allow_session": False}] * 2
    assert not approval.is_approved(session, "file/directory delete")
    assert not (get_lliam_home() / "config.yaml").exists()
