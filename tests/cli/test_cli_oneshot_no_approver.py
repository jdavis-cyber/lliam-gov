"""AI-1172: a single-query run (`chat -q`) is not interactive.

cli.main used to set LLIAM_INTERACTIVE=1 unconditionally, so a -q run went
to the interactive prompt. With piped stdin that either stalled every
dangerous command until the approval timeout or, with input such as `once`,
approved it. A -q run now marks the process one-shot and dangerous commands
take the refusal path.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import tools.approval as approval_module

REPO_ROOT = Path(__file__).resolve().parents[2]


class _Stop(Exception):
    pass


@pytest.fixture(autouse=True)
def _reset_oneshot(monkeypatch):
    monkeypatch.setattr(approval_module, "_oneshot_process", False)
    monkeypatch.delenv("LLIAM_INTERACTIVE", raising=False)


def _run_main_until_cli_built(monkeypatch, **kwargs):
    import cli as cli_mod

    def _fake_cli(**_kw):
        raise _Stop

    monkeypatch.setattr(cli_mod, "LliamCLI", _fake_cli)
    with pytest.raises(_Stop):
        cli_mod.main(**kwargs)


@pytest.mark.parametrize("kwargs", [{"query": "hi"}, {"q": "hi"}])
def test_single_query_is_marked_oneshot_not_interactive(monkeypatch, kwargs):
    _run_main_until_cli_built(monkeypatch, **kwargs)
    assert approval_module._oneshot_process is True
    assert "LLIAM_INTERACTIVE" not in os.environ


def test_interactive_run_still_sets_interactive(monkeypatch):
    _run_main_until_cli_built(monkeypatch)
    assert approval_module._oneshot_process is False
    assert os.environ.get("LLIAM_INTERACTIVE") == "1"


_CHILD = textwrap.dedent(
    """
    import json, os, sys, time
    sys.path.insert(0, sys.argv[1])
    import tools.approval as a
    from tools.terminal_tool import terminal_tool
    from unittest.mock import MagicMock, patch

    a.mark_oneshot_process()
    env_config = {
        "env_type": "local", "timeout": 30, "cwd": "/tmp", "host_cwd": None,
        "modal_mode": "auto", "docker_image": "", "singularity_image": "",
        "modal_image": "", "daytona_image": "",
    }
    backend = MagicMock()
    backend.execute.return_value = {"output": "ran", "returncode": 0}
    start = time.monotonic()
    with patch("tools.terminal_tool._get_env_config", return_value=env_config), \\
         patch("tools.terminal_tool._start_cleanup_thread"), \\
         patch("tools.terminal_tool._active_environments", {"default": backend}), \\
         patch("tools.terminal_tool._last_activity", {"default": 0}):
        result = json.loads(terminal_tool(command="rm -rf ./build"))
    print(json.dumps({
        "executed": backend.execute.called,
        "error": result.get("error") or "",
        "seconds": time.monotonic() - start,
    }))
    """
)


@pytest.mark.parametrize("stdin_text", ["once\n", "a\n", ""])
def test_oneshot_piped_stdin_cannot_approve_or_stall(tmp_path, stdin_text):
    """Inherited interactive/exec-ask flags plus a piped 'once' still refuse."""
    import json

    env = {
        k: v for k, v in os.environ.items()
        if not k.startswith("LLIAM_")
    }
    env.update({
        "LLIAM_INTERACTIVE": "1",   # inherited from a parent process
        "LLIAM_EXEC_ASK": "1",
        "LLIAM_HOME": str(tmp_path),
        "PYTHONPATH": str(REPO_ROOT),
    })
    script = tmp_path / "child.py"
    script.write_text(_CHILD)
    proc = subprocess.run(
        [sys.executable, str(script), str(REPO_ROOT)],
        input=stdin_text, capture_output=True, text=True, timeout=60,
        cwd=str(tmp_path), env=env,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["executed"] is False
    assert "desktop app" in out["error"]
    assert out["seconds"] < 20
