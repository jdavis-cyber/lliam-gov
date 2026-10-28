"""File deletes require consent even inside an ordinary working directory."""

import json
import shlex
import sys

import pytest

from lliam_constants import get_lliam_home
from tools import approval


@pytest.mark.parametrize("command", [
    "rm -- scratch/throwaway-file-n.txt",
    "rm scratch/file.txt",
    "rm -f 'scratch/file with spaces.txt'",
    "/bin/rm -- scratch/file.txt",
    "sudo rm scratch/file.txt",
    "env rm scratch/file.txt",
    "cd scratch && rm file.txt",
    "true; rm scratch/file.txt",
    "true\nrm scratch/file.txt",
    "unlink scratch/file.txt",
    "/usr/bin/unlink scratch/file.txt",
    "rmdir scratch/empty",
    "find scratch -name '*.txt' -delete",
    "find scratch -exec unlink {} \\;",
    "find scratch -type d -execdir rmdir {} \\;",
    "printf '%s\\n' scratch/file.txt | xargs unlink",
    "os.remove('scratch/file.txt')",
    "os . remove ('scratch/file.txt')",
    "os.unlink('scratch/file.txt')",
    "os.rmdir('scratch/empty')",
    "os.removedirs('scratch/empty')",
    "from os import remove; remove('scratch/file.txt')",
    "from os import unlink; unlink('scratch/file.txt')",
    "Path('scratch/file.txt').unlink()",
    "pathlib.Path('scratch/empty').rmdir()",
    "shutil.rmtree('scratch/tree')",
    "from shutil import rmtree; rmtree('scratch/tree')",
    "python3 - <<'PY'\nimport os\nos.remove('scratch/file.txt')\nPY",
    "python3.11 -c \"import os; os.remove('scratch/file.txt')\"",
])
def test_delete_detection_is_independent_of_target_path(command):
    dangerous, key, description = approval.detect_dangerous_command(command)
    assert dangerous, command
    assert key
    assert description


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
    command = operation.format(path=relative_path, python=shlex.quote(sys.executable))

    # Deny first, then approve the same command. No guard or executor is mocked.
    for choice in ("deny", "once"):
        requests = []

        def respond(data):
            requests.append(data)
            assert data["command"] == command
            assert relative_path in data["command"]
            assert target.exists(), "Delete ran before consent"
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
