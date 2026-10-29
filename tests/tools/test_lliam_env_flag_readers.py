"""AI-1187: surface-flag readers honour the current ``LLIAM_`` names.

The CLI, gateway, TUI gateway and cron scheduler set ``LLIAM_INTERACTIVE``,
``LLIAM_GATEWAY_SESSION`` and ``LLIAM_EXEC_ASK`` since the rename. These
readers used ``env_var_enabled`` on the legacy names only, so on a renamed
surface they behaved as if no surface were present. Each test below sets only
the ``LLIAM_`` name (the hermetic conftest already clears the legacy names).
"""

import json
from unittest.mock import MagicMock, patch

import pytest

import tools.cronjob_tools as cronjob_tools
import tools.skills_tool as skills_tool
import tools.terminal_tool as terminal_tool

_SURFACE_FLAGS = ("LLIAM_INTERACTIVE", "LLIAM_GATEWAY_SESSION", "LLIAM_EXEC_ASK")


@pytest.fixture(autouse=True)
def _clean_surface(monkeypatch):
    for name in _SURFACE_FLAGS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    terminal_tool._reset_cached_sudo_passwords()
    yield
    terminal_tool._reset_cached_sudo_passwords()


# --- tools/terminal_tool.py ---------------------------------------------


def test_sudo_failure_tip_reads_lliam_gateway_session(monkeypatch):
    output = "sudo: a password is required"
    assert terminal_tool._handle_sudo_failure(output, "local") == output

    monkeypatch.setenv("LLIAM_GATEWAY_SESSION", "1")
    assert "SUDO_PASSWORD" in terminal_tool._handle_sudo_failure(output, "local")


def test_sudo_prompt_reads_lliam_interactive(monkeypatch):
    monkeypatch.setattr(terminal_tool, "_sudo_nopasswd_works", lambda: False)
    prompts = []

    def _prompt(timeout_seconds=45):
        prompts.append(timeout_seconds)
        return "typed-pass"

    monkeypatch.setattr(terminal_tool, "_prompt_for_sudo_password", _prompt)

    transformed, sudo_stdin = terminal_tool._transform_sudo_command("sudo whoami")
    assert prompts == []
    assert sudo_stdin is None

    monkeypatch.setenv("LLIAM_INTERACTIVE", "1")
    transformed, sudo_stdin = terminal_tool._transform_sudo_command("sudo whoami")
    assert prompts == [45]
    assert transformed == "sudo -S -p '' whoami"
    assert sudo_stdin == "typed-pass\n"


def _run_sudo_with_rejected_cached_password():
    terminal_tool._set_cached_sudo_password("stale-pass")
    env_config = {
        "env_type": "local", "timeout": 30, "cwd": "/tmp", "host_cwd": None,
        "modal_mode": "auto", "docker_image": "", "singularity_image": "",
        "modal_image": "", "daytona_image": "",
    }
    backend = MagicMock()
    backend.execute.return_value = {
        "output": "sudo: 3 incorrect password attempts", "returncode": 1,
    }
    with patch("tools.terminal_tool._get_env_config", return_value=env_config), \
         patch("tools.terminal_tool._start_cleanup_thread"), \
         patch("tools.terminal_tool._check_all_guards",
               return_value={"approved": True, "message": None}), \
         patch("tools.terminal_tool._active_environments", {"default": backend}), \
         patch("tools.terminal_tool._last_activity", {"default": 0}):
        result = json.loads(terminal_tool.terminal_tool(command="sudo whoami"))
    assert backend.execute.called
    assert terminal_tool._get_cached_sudo_password() == ""
    return result["output"]


def test_sudo_cache_cleared_notice_reads_lliam_interactive(monkeypatch):
    assert "prompted again" not in _run_sudo_with_rejected_cached_password()

    monkeypatch.setenv("LLIAM_INTERACTIVE", "1")
    assert "prompted again" in _run_sudo_with_rejected_cached_password()


# --- tools/skills_tool.py -----------------------------------------------


def test_skills_gateway_surface_reads_lliam_gateway_session(monkeypatch):
    assert skills_tool._is_gateway_surface() is False

    monkeypatch.setenv("LLIAM_GATEWAY_SESSION", "1")
    assert skills_tool._is_gateway_surface() is True


def test_skills_secret_capture_reads_lliam_interactive(monkeypatch):
    monkeypatch.setenv("LLIAM_GATEWAY_SESSION", "1")
    captured = []

    def _capture(name, prompt, metadata):
        captured.append(name)
        return {"success": True, "stored_as": name, "validated": True, "skipped": False}

    monkeypatch.setattr(skills_tool, "_secret_capture_callback", _capture)
    missing = [{"name": "DEMO_API_KEY", "prompt": "Enter the demo key"}]

    # A messaging gateway cannot prompt: it returns the setup hint instead.
    result = skills_tool._capture_required_environment_variables("demo", missing)
    assert result["gateway_setup_hint"]
    assert captured == []

    # An interactive gateway surface (desktop app / TUI) prompts.
    monkeypatch.setenv("LLIAM_INTERACTIVE", "1")
    result = skills_tool._capture_required_environment_variables("demo", missing)
    assert result["gateway_setup_hint"] is None
    assert captured == ["DEMO_API_KEY"]


# --- tools/cronjob_tools.py ---------------------------------------------


@pytest.mark.parametrize("flag", _SURFACE_FLAGS)
def test_cronjob_requirements_read_lliam_surface_flags(monkeypatch, flag):
    assert cronjob_tools.check_cronjob_requirements() is False

    monkeypatch.setenv(flag, "1")
    assert cronjob_tools.check_cronjob_requirements() is True


@pytest.mark.parametrize("flag", _SURFACE_FLAGS)
def test_cronjob_requirements_reject_false_like_lliam_values(monkeypatch, flag):
    monkeypatch.setenv(flag, "0")
    assert cronjob_tools.check_cronjob_requirements() is False
