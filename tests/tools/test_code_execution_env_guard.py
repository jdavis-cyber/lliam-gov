"""AI-1182: execute_code refuses Python-level writes to .env files.

The sandbox child installs an audit hook (via a staged ``sitecustomize``)
that applies the same predicate as the file tools: .env, .env.* and .envrc
are refused; .env.example and .env.sample stay writable.
"""

import json
import os
import subprocess
import sys
import textwrap
from unittest.mock import MagicMock, patch

import pytest

from tools.code_execution_tool import (
    SANDBOX_ALLOWED_TOOLS,
    _env_write_guard_source,
    _execute_remote,
    execute_code,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="UDS sandbox not available on Windows"
)


@pytest.fixture(autouse=True)
def _force_local_terminal(monkeypatch):
    monkeypatch.setenv("TERMINAL_ENV", "local")


def _run(code: str) -> dict:
    with patch("model_tools.handle_function_call", return_value="{}"), \
         patch("tools.code_execution_tool._load_config",
               return_value={"timeout": 30, "max_tool_calls": 5}):
        raw = execute_code(code, task_id="env-guard",
                           enabled_tools=list(SANDBOX_ALLOWED_TOOLS))
    return json.loads(raw)


# Each snippet tries one write route against TARGET; the script prints
# BLOCKED when the guard raises PermissionError.
BLOCKED_WRITES = {
    "open_w": "open(TARGET, 'w').write('API_KEY=x')",
    "open_append": "open(TARGET, 'a').write('API_KEY=x')",
    "pathlib_write_text": "pathlib.Path(TARGET).write_text('API_KEY=x')",
    "os_open_creat": "os.close(os.open(TARGET, os.O_WRONLY | os.O_CREAT))",
    "os_replace_into": (
        "open(os.path.join(D, 'staged.tmp'), 'w').close(); "
        "os.replace(os.path.join(D, 'staged.tmp'), TARGET)"
    ),
    "shutil_copy_into": (
        "open(os.path.join(D, 'src.txt'), 'w').close(); "
        "shutil.copy(os.path.join(D, 'src.txt'), TARGET)"
    ),
    "symlink_named_env": (
        "os.symlink(os.path.join(D, 'elsewhere'), TARGET)"
    ),
}


def _script(directory: str, name: str, body: str) -> str:
    return textwrap.dedent(f"""
        import os, pathlib, shutil
        D = {directory!r}
        TARGET = os.path.join(D, {name!r})
        try:
            {body}
            print("WROTE")
        except PermissionError as exc:
            print("BLOCKED", exc)
    """)


@pytest.mark.parametrize("route", sorted(BLOCKED_WRITES))
@pytest.mark.parametrize("name", [".env", ".env.local", ".envrc", ".ENV"])
def test_execute_code_refuses_env_writes(tmp_path, route, name):
    result = _run(_script(str(tmp_path), name, BLOCKED_WRITES[route]))
    assert result["status"] == "success", result
    assert "BLOCKED" in result["output"], result["output"]
    assert "protected environment file" in result["output"]
    assert not os.path.lexists(tmp_path / name)


@pytest.mark.parametrize("name", [".env.example", ".env.sample", "notes.txt"])
def test_execute_code_allows_example_shapes(tmp_path, name):
    result = _run(_script(str(tmp_path), name, BLOCKED_WRITES["open_w"]))
    assert result["status"] == "success", result
    assert "WROTE" in result["output"], result["output"]
    assert (tmp_path / name).read_text() == "API_KEY=x"


def test_execute_code_refuses_write_through_symlink_to_env(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=old")
    (tmp_path / "notes.txt").symlink_to(env_file)
    result = _run(_script(str(tmp_path), "notes.txt", BLOCKED_WRITES["open_w"]))
    assert "BLOCKED" in result["output"], result["output"]
    assert env_file.read_text() == "API_KEY=old"


def test_execute_code_refuses_moving_or_deleting_env(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=old")
    code = textwrap.dedent(f"""
        import os
        p = {str(env_file)!r}
        for label, op in (("rename", lambda: os.rename(p, p + ".bak")),
                          ("remove", lambda: os.remove(p)),
                          ("truncate", lambda: os.truncate(p, 0))):
            try:
                op()
                print(label, "WROTE")
            except PermissionError:
                print(label, "BLOCKED")
    """)
    result = _run(code)
    for label in ("rename", "remove", "truncate"):
        assert f"{label} BLOCKED" in result["output"], result["output"]
    assert env_file.read_text() == "API_KEY=old"


def test_execute_code_still_reads_env(tmp_path):
    """The guard is write-only; reads are out of scope for AI-1182."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=old")
    result = _run(f"print(open({str(env_file)!r}).read())")
    assert result["status"] == "success", result
    assert "API_KEY=old" in result["output"]


def test_uncaught_refusal_reports_error(tmp_path):
    target = tmp_path / ".env"
    result = _run(f"open({str(target)!r}, 'w').write('x')")
    assert result["status"] == "error"
    combined = result.get("error", "") + result.get("output", "")
    assert "PermissionError" in combined
    assert not target.exists()


def test_guard_chains_existing_sitecustomize(tmp_path):
    """The staged sitecustomize must not hide one already on sys.path."""
    guard_dir = tmp_path / "guard"
    other_dir = tmp_path / "other"
    guard_dir.mkdir()
    other_dir.mkdir()
    (guard_dir / "sitecustomize.py").write_text(_env_write_guard_source())
    (other_dir / "sitecustomize.py").write_text("print('OTHER_SITECUSTOMIZE')\n")
    target = tmp_path / ".env"
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = os.pathsep.join([str(guard_dir), str(other_dir)])
    proc = subprocess.run(
        [sys.executable, "-c", f"open({str(target)!r}, 'w')"],
        env=env, capture_output=True, text=True, cwd=str(tmp_path),
    )
    assert "OTHER_SITECUSTOMIZE" in proc.stdout
    assert proc.returncode != 0
    assert "protected environment file" in proc.stderr
    assert not target.exists()


def test_remote_ships_guard_and_puts_it_on_pythonpath():
    class FakeEnv:
        def __init__(self):
            self.commands = []

        def get_temp_dir(self):
            return "/tmp"

        def execute(self, command, cwd=None, timeout=None):
            self.commands.append(command)
            if "command -v python3" in command:
                return {"output": "OK\n"}
            if "python3 script.py" in command:
                return {"output": "hello\n", "returncode": 0}
            return {"output": ""}

    env = FakeEnv()
    shipped = {}

    def _ship(_env, path, content):
        shipped[path] = content

    with patch("tools.code_execution_tool._load_config",
               return_value={"timeout": 30, "max_tool_calls": 5}), \
         patch("tools.code_execution_tool._get_or_create_env",
               return_value=(env, "ssh")), \
         patch("tools.code_execution_tool._ship_file_to_remote", side_effect=_ship), \
         patch("tools.code_execution_tool.threading.Thread", return_value=MagicMock()):
        result = json.loads(_execute_remote("print('hello')", "task-1", ["terminal"]))

    assert result["status"] == "success"
    guard_paths = [p for p in shipped if p.endswith("/sitecustomize.py")]
    assert len(guard_paths) == 1
    assert shipped[guard_paths[0]] == _env_write_guard_source()
    sandbox_dir = guard_paths[0].rsplit("/", 1)[0]
    run_cmd = next(c for c in env.commands if "python3 script.py" in c)
    assert f"PYTHONPATH={sandbox_dir}" in run_cmd


# --- dir_fd-relative targets (Codex review on #141) -------------------------
#
# The "open" audit event carries no dir_fd, and the os.* events carry it as
# an fd. Relative names must be resolved against that directory, not the
# process CWD.


def _dir_fd_script(data_dir: str, cwd: str, body: str) -> str:
    return textwrap.dedent(f"""
        import os
        os.chdir({cwd!r})
        dfd = os.open({data_dir!r}, os.O_RDONLY)
        try:
            {body}
            print("WROTE")
        except PermissionError as exc:
            print("BLOCKED", exc)
    """)


def _data_with_env_symlink(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    env_file = data / ".env"
    env_file.write_text("API_KEY=old")
    (data / "notes.txt").symlink_to(".env")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    return data, env_file, elsewhere


def test_os_open_dir_fd_symlink_to_env_refused(tmp_path):
    """Exact repro: data/notes.txt -> .env opened relative to a dir_fd."""
    data, env_file, elsewhere = _data_with_env_symlink(tmp_path)
    body = "os.close(os.open('notes.txt', os.O_WRONLY | os.O_TRUNC, dir_fd=dfd))"
    result = _run(_dir_fd_script(str(data), str(elsewhere), body))
    assert "BLOCKED" in result["output"], result["output"]
    assert env_file.read_text() == "API_KEY=old"


def test_open_with_dir_fd_opener_refused(tmp_path):
    data, env_file, elsewhere = _data_with_env_symlink(tmp_path)
    body = ("open('notes.txt', 'w', opener=lambda p, f: os.open(p, f, dir_fd=dfd))"
            ".write('API_KEY=new')")
    result = _run(_dir_fd_script(str(data), str(elsewhere), body))
    assert "BLOCKED" in result["output"], result["output"]
    assert env_file.read_text() == "API_KEY=old"


def test_link_with_src_dir_fd_to_env_refused(tmp_path):
    data, env_file, elsewhere = _data_with_env_symlink(tmp_path)
    body = "os.link('notes.txt', 'hard.txt', src_dir_fd=dfd, dst_dir_fd=dfd)"
    result = _run(_dir_fd_script(str(data), str(elsewhere), body))
    assert "BLOCKED" in result["output"], result["output"]
    assert not (data / "hard.txt").exists()


def test_dir_fd_write_ignores_cwd_namesake(tmp_path):
    """A CWD notes.txt -> .env must not block a write to data/notes.txt."""
    data = tmp_path / "data"
    data.mkdir()
    (data / "notes.txt").write_text("plain")
    (data / "a.txt").write_text("a")
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    cwd_env = cwd / ".env"
    cwd_env.write_text("API_KEY=old")
    (cwd / "notes.txt").symlink_to(".env")
    body = (
        "fd = os.open('notes.txt', os.O_WRONLY | os.O_TRUNC, dir_fd=dfd); "
        "os.write(fd, b'new'); os.close(fd); "
        "os.rename('a.txt', 'notes.txt', src_dir_fd=dfd, dst_dir_fd=dfd)"
    )
    result = _run(_dir_fd_script(str(data), str(cwd), body))
    assert "WROTE" in result["output"], result["output"]
    assert (data / "notes.txt").read_text() == "a"
    assert cwd_env.read_text() == "API_KEY=old"


def test_unresolvable_dir_fd_write_fails_closed(tmp_path):
    body = "os.open('x.txt', os.O_WRONLY | os.O_CREAT, dir_fd=987654)"
    result = _run(_dir_fd_script(str(tmp_path), str(tmp_path), body))
    assert "BLOCKED" in result["output"], result["output"]
    assert not (tmp_path / "x.txt").exists()


def test_guarded_os_open_keeps_dir_fd_support():
    """shutil and others probe os.open in os.supports_dir_fd."""
    result = _run("import os; print('DIRFD', os.open in os.supports_dir_fd)")
    assert "DIRFD True" in result["output"], result["output"]
