"""AI-1172 (DEF-015): no-approver sessions refuse dangerous commands.

A session with no approver present (one-shot runs with piped stdin, scripts,
batch jobs, library use: not interactive, not gateway, not cron) used to
auto-approve every dangerous command with a warning log line. It now fails
closed: the command is refused, nothing runs, and the message tells the
operator to run it from the desktop app.

The explicit opt-ins keep working unchanged: --yolo (process), /yolo
(session), approvals.mode=off, an operator's earlier "always"/session
approval, and approvals.cron_mode for cron sessions.

The surface flags are now read under their current LLIAM_ names (with the
legacy-name fallback). Before this change the approval module read only the
legacy names, so every producer that sets the LLIAM_ name (cli.py, the
gateway, the cron scheduler, the TUI gateway, ACP) was treated as a
no-approver session and silently auto-approved.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

import tools.approval as approval_module
from tools.approval import check_all_command_guards, check_dangerous_command

DANGEROUS = "rm -rf ./build"
_SURFACE_FLAGS = (
    "LLIAM_INTERACTIVE",
    "LLIAM_GATEWAY_SESSION",
    "LLIAM_EXEC_ASK",
    "LLIAM_CRON_SESSION",
    "LLIAM_YOLO_MODE",
    "LLIAM_SESSION_PLATFORM",
    "LLIAM_SESSION_KEY",
)


@pytest.fixture(autouse=True)
def _no_approver_env(monkeypatch):
    """No surface flags, low-side config (manual mode, not strict)."""
    for name in _SURFACE_FLAGS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: {"security": {}})
    monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", False)
    monkeypatch.setattr(approval_module, "_get_approval_config", lambda: {})
    approval_module._permanent_approved.clear()
    approval_module.clear_session("default")
    yield
    approval_module._permanent_approved.clear()
    approval_module.clear_session("default")


def _assert_refused(result):
    assert result["approved"] is False
    message = result.get("message") or ""
    assert "desktop app" in message
    assert "Nothing was run" in message
    assert result.get("status") != "approval_required"


# ---------------------------------------------------------------------------
# Refusal in the no-approver branch
# ---------------------------------------------------------------------------

class TestNoApproverRefuses:
    def test_terminal_guard_refuses_dangerous_command(self):
        result = check_all_command_guards(DANGEROUS, "local")
        _assert_refused(result)
        assert result["description"]

    def test_legacy_guard_refuses_dangerous_command(self):
        result = check_dangerous_command(DANGEROUS, "local")
        _assert_refused(result)

    def test_no_auto_approved_log_line(self, caplog):
        with caplog.at_level("WARNING", logger="tools.approval"):
            check_dangerous_command(DANGEROUS, "local")
            check_all_command_guards(DANGEROUS, "local")
        assert "AUTO-APPROVED" not in caplog.text

    def test_safe_command_still_runs(self):
        assert check_all_command_guards("ls -la", "local")["approved"] is True
        assert check_dangerous_command("ls -la", "local")["approved"] is True

    def test_container_backend_unchanged(self):
        assert check_all_command_guards(DANGEROUS, "docker")["approved"] is True

    def test_refusal_is_recorded_as_deny(self):
        with patch("tools.hitl_oversight.record_decision") as record:
            check_all_command_guards(DANGEROUS, "local")
        assert record.call_args.kwargs["decision"] == "deny"
        assert record.call_args.kwargs["gate"] == "shell.dangerous"

    def test_strict_posture_keeps_its_own_message(self, monkeypatch):
        monkeypatch.setattr(
            "lliam_cli.config.load_config",
            lambda *a, **kw: {"security": {"posture": "strict", "deny_on_no_approver": True}},
        )
        result = check_all_command_guards(DANGEROUS, "local")
        assert result["approved"] is False
        assert "fail-closed" in result["message"].lower()

    def test_terminal_tool_runs_nothing(self):
        """End to end through terminal_tool: the backend never executes."""
        from tools.terminal_tool import terminal_tool

        env_config = {
            "env_type": "local", "timeout": 180, "cwd": "/tmp", "host_cwd": None,
            "modal_mode": "auto", "docker_image": "", "singularity_image": "",
            "modal_image": "", "daytona_image": "",
        }
        backend = MagicMock()
        backend.execute.return_value = {"output": "ran", "returncode": 0}
        with patch("tools.terminal_tool._get_env_config", return_value=env_config), \
             patch("tools.terminal_tool._start_cleanup_thread"), \
             patch("tools.terminal_tool._active_environments", {"default": backend}), \
             patch("tools.terminal_tool._last_activity", {"default": 0}):
            result = json.loads(terminal_tool(command=DANGEROUS))

        backend.execute.assert_not_called()
        assert result["exit_code"] == -1
        assert "desktop app" in result["error"]


# ---------------------------------------------------------------------------
# Explicit opt-ins keep working exactly as before
# ---------------------------------------------------------------------------

class TestExplicitOptInStillApproves:
    def test_process_yolo(self, monkeypatch):
        monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", True)
        assert check_all_command_guards(DANGEROUS, "local")["approved"] is True
        assert check_dangerous_command(DANGEROUS, "local")["approved"] is True

    def test_session_yolo(self):
        token = approval_module.set_current_session_key("oneshot-yolo")
        try:
            approval_module.enable_session_yolo("oneshot-yolo")
            assert check_all_command_guards(DANGEROUS, "local")["approved"] is True
            assert check_dangerous_command(DANGEROUS, "local")["approved"] is True
        finally:
            approval_module.clear_session("oneshot-yolo")
            approval_module.reset_current_session_key(token)

    def test_approvals_mode_off(self, monkeypatch):
        monkeypatch.setattr(approval_module, "_get_approval_config", lambda: {"mode": "off"})
        assert check_all_command_guards(DANGEROUS, "local")["approved"] is True

    def test_permanent_approval_from_operator(self):
        _, pattern_key, _ = approval_module.detect_dangerous_command("chmod 777 ./x")
        approval_module.approve_permanent(pattern_key)
        assert check_all_command_guards("chmod 777 ./x", "local")["approved"] is True
        assert check_dangerous_command("chmod 777 ./x", "local")["approved"] is True

    def test_hardline_still_blocks_under_yolo(self, monkeypatch):
        monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", True)
        result = check_all_command_guards("rm -rf /", "local")
        assert result["approved"] is False
        assert result.get("hardline") is True


# ---------------------------------------------------------------------------
# Surfaces with their own approval mechanism are detected under LLIAM_ names
# ---------------------------------------------------------------------------

class TestSurfaceFlagsUnderCurrentNames:
    def test_cron_deny_mode_blocks_with_cron_message(self, monkeypatch):
        monkeypatch.setenv("LLIAM_CRON_SESSION", "1")
        monkeypatch.setattr("tools.approval._get_cron_approval_mode", lambda: "deny")
        for guard in (check_all_command_guards, check_dangerous_command):
            result = guard(DANGEROUS, "local")
            assert result["approved"] is False
            assert "cron_mode" in result["message"]

    def test_cron_approve_mode_still_approves(self, monkeypatch):
        monkeypatch.setenv("LLIAM_CRON_SESSION", "1")
        monkeypatch.setattr("tools.approval._get_cron_approval_mode", lambda: "approve")
        assert check_all_command_guards(DANGEROUS, "local")["approved"] is True
        assert check_dangerous_command(DANGEROUS, "local")["approved"] is True

    def test_interactive_flag_reaches_the_approval_callback(self, monkeypatch):
        monkeypatch.setenv("LLIAM_INTERACTIVE", "1")
        callback = MagicMock(return_value="deny")
        result = check_all_command_guards(DANGEROUS, "local", approval_callback=callback)
        callback.assert_called_once()
        assert result["approved"] is False
        assert "desktop app" not in (result.get("message") or "")

    def test_interactive_flag_once_approves(self, monkeypatch):
        monkeypatch.setenv("LLIAM_INTERACTIVE", "1")
        callback = MagicMock(return_value="once")
        result = check_all_command_guards(DANGEROUS, "local", approval_callback=callback)
        assert result["approved"] is True

    def test_exec_ask_flag_queues_for_approval(self, monkeypatch):
        monkeypatch.setenv("LLIAM_EXEC_ASK", "1")
        result = check_dangerous_command(DANGEROUS, "local")
        assert result["approved"] is False
        assert result.get("status") == "approval_required"

    def test_gateway_flag_is_a_gateway_context(self, monkeypatch):
        monkeypatch.setenv("LLIAM_GATEWAY_SESSION", "1")
        assert approval_module._is_gateway_approval_context() is True

    def test_cron_flag_overrides_gateway_flag(self, monkeypatch):
        monkeypatch.setenv("LLIAM_GATEWAY_SESSION", "1")
        monkeypatch.setenv("LLIAM_CRON_SESSION", "1")
        assert approval_module._is_gateway_approval_context() is False

    def test_flag_set_to_false_is_off(self, monkeypatch):
        monkeypatch.setenv("LLIAM_INTERACTIVE", "0")
        _assert_refused(check_all_command_guards(DANGEROUS, "local"))


# ---------------------------------------------------------------------------
# Cron marker: context-local, and it beats inherited exec-ask/interactive flags
# ---------------------------------------------------------------------------

class TestCronMarkerIsContextLocal:
    def _gateway_turn(self, monkeypatch):
        """A live gateway turn: process-wide exec-ask plus a bound platform."""
        from agent.session_context import set_session_vars

        monkeypatch.setenv("LLIAM_EXEC_ASK", "1")
        return set_session_vars(platform="telegram", chat_id="42")

    def test_marker_does_not_leak_out_of_the_job_context(self):
        import contextvars

        seen = {}

        def _job():
            token = approval_module.set_cron_session()
            try:
                seen["inside"] = approval_module._is_cron_session()
            finally:
                approval_module.reset_cron_session(token)

        contextvars.copy_context().run(_job)
        assert seen["inside"] is True
        assert approval_module._is_cron_session() is False

    @pytest.mark.parametrize("cron_mode", ["deny", "approve"])
    def test_gateway_execute_code_unaffected_by_a_cron_job_elsewhere(
        self, monkeypatch, cron_mode,
    ):
        """A cron job in another context must not turn a live gateway turn into cron."""
        import contextvars

        from agent.session_context import clear_session_vars

        monkeypatch.setattr("tools.approval._get_cron_approval_mode", lambda: cron_mode)
        contextvars.copy_context().run(approval_module.set_cron_session)
        tokens = self._gateway_turn(monkeypatch)
        try:
            result = approval_module.check_execute_code_guard("print(1)", "local")
        finally:
            clear_session_vars(tokens)
        assert result["approved"] is False
        assert result.get("status") == "pending_approval"

    @pytest.mark.parametrize("guard", [check_all_command_guards, check_dangerous_command])
    def test_cron_approve_beats_inherited_exec_ask(self, monkeypatch, guard):
        monkeypatch.setenv("LLIAM_EXEC_ASK", "1")
        monkeypatch.setenv("LLIAM_INTERACTIVE", "1")
        monkeypatch.setattr("tools.approval._get_cron_approval_mode", lambda: "approve")
        token = approval_module.set_cron_session()
        try:
            result = guard(DANGEROUS, "local")
        finally:
            approval_module.reset_cron_session(token)
        assert result["approved"] is True
        assert result.get("status") not in {"approval_required", "pending_approval"}

    @pytest.mark.parametrize("guard", [check_all_command_guards, check_dangerous_command])
    def test_cron_deny_beats_inherited_exec_ask(self, monkeypatch, guard):
        monkeypatch.setenv("LLIAM_EXEC_ASK", "1")
        monkeypatch.setenv("LLIAM_INTERACTIVE", "1")
        monkeypatch.setattr("tools.approval._get_cron_approval_mode", lambda: "deny")
        token = approval_module.set_cron_session()
        try:
            result = guard(DANGEROUS, "local")
        finally:
            approval_module.reset_cron_session(token)
        assert result["approved"] is False
        assert "cron_mode" in result["message"]
        assert result.get("status") not in {"approval_required", "pending_approval"}
