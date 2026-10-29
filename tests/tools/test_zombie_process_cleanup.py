"""Tests for zombie process cleanup — verifies processes spawned by tools
are properly reaped when agent sessions end.

Reproduction for issue #7131: zombie process accumulation on long-running
gateway deployments.
"""

import os
import signal
import subprocess
import sys
import threading


def _spawn_sleep(seconds: float = 60) -> subprocess.Popen:
    """Spawn a portable long-lived Python sleep process (no shell wrapper)."""
    return subprocess.Popen(
        [sys.executable, "-c", f"import time; time.sleep({seconds})"],
    )


def _pid_alive(pid: int) -> bool:
    """Return True if a process with the given PID is still running."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


class TestZombieReproduction:
    """Demonstrate that subprocesses survive when cleanup is not called."""

    def test_orphaned_processes_survive_without_cleanup(self):
        """REPRODUCTION: processes spawned directly survive if no one kills
        them — this models the gap that causes zombie accumulation when
        the gateway drops agent references without calling close()."""
        pids = []

        try:
            for _ in range(3):
                proc = _spawn_sleep(60)
                pids.append(proc.pid)

            for pid in pids:
                assert _pid_alive(pid), f"PID {pid} should be alive after spawn"

            # Simulate "session end" by just dropping the reference
            del proc  # noqa: F821

            # BUG: processes are still alive after reference is dropped
            for pid in pids:
                assert _pid_alive(pid), (
                    f"PID {pid} died after ref drop — "
                    f"expected it to survive (demonstrating the bug)"
                )
        finally:
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass

    def test_explicit_terminate_reaps_processes(self):
        """Explicitly terminating+waiting on Popen handles works.
        This models what ProcessRegistry.kill_process does internally."""
        procs = []

        try:
            for _ in range(3):
                proc = _spawn_sleep(60)
                procs.append(proc)

            for proc in procs:
                assert _pid_alive(proc.pid)

            for proc in procs:
                proc.terminate()
                proc.wait(timeout=5)

            for proc in procs:
                assert proc.returncode is not None, (
                    f"PID {proc.pid} should have exited after terminate+wait"
                )
        finally:
            for proc in procs:
                try:
                    proc.kill()
                    proc.wait(timeout=1)
                except Exception:
                    pass


class TestAgentCloseMethod:
    """Verify AIAgent.close() exists, is idempotent, and calls cleanup."""

    def test_close_calls_cleanup_functions(self):
        """close() should call kill_all, cleanup_vm, cleanup_browser."""
        from unittest.mock import patch

        with patch("run_agent.AIAgent.__init__", return_value=None):
            from run_agent import AIAgent
            agent = AIAgent.__new__(AIAgent)
            agent.session_id = "test-close-cleanup"
            agent._active_children = []
            agent._active_children_lock = threading.Lock()
            agent.client = None

            with patch("tools.process_registry.process_registry") as mock_registry, \
                 patch("run_agent.cleanup_vm") as mock_cleanup_vm, \
                 patch("run_agent.cleanup_browser") as mock_cleanup_browser:
                agent.close()

                mock_registry.kill_all.assert_called_once_with(
                    task_id="test-close-cleanup"
                )
                mock_cleanup_vm.assert_called_once_with("test-close-cleanup")
                mock_cleanup_browser.assert_called_once_with("test-close-cleanup")

    def test_close_cleans_owned_ssh_environment_without_secret_scope(
        self, monkeypatch,
    ):
        from unittest.mock import patch
        from tools import terminal_tool

        class FakeEnvironment:
            def __init__(self):
                self.cleaned = False

            def cleanup(self):
                self.cleaned = True

        raw_session = "test-unscoped-ssh-close"
        environment_key = "default::ssh:opaque"
        env = FakeEnvironment()
        monkeypatch.setenv("TERMINAL_ENV", "ssh")
        monkeypatch.setattr(
            terminal_tool, "_active_environments", {environment_key: env}
        )
        monkeypatch.setattr(
            terminal_tool, "_last_activity", {environment_key: 1.0}
        )
        monkeypatch.setattr(
            terminal_tool, "_creation_locks", {environment_key: threading.Lock()}
        )
        monkeypatch.setattr(
            terminal_tool,
            "_environment_keys_by_owner",
            {raw_session: {environment_key}},
        )
        monkeypatch.setattr(
            terminal_tool,
            "_environment_owners_by_key",
            {environment_key: {raw_session}},
        )

        with patch("run_agent.AIAgent.__init__", return_value=None):
            from run_agent import AIAgent
            agent = AIAgent.__new__(AIAgent)
            agent.session_id = raw_session
            agent._active_children = []
            agent._active_children_lock = threading.Lock()
            agent.client = None

            with patch("tools.process_registry.process_registry"), \
                 patch("run_agent.cleanup_browser"):
                agent.close()

        assert env.cleaned is True
        assert terminal_tool._active_environments == {}
        assert terminal_tool._environment_keys_by_owner == {}
        assert terminal_tool._environment_owners_by_key == {}

    def test_close_is_idempotent(self):
        """close() can be called multiple times without error."""
        from unittest.mock import patch

        with patch("run_agent.AIAgent.__init__", return_value=None):
            from run_agent import AIAgent
            agent = AIAgent.__new__(AIAgent)
            agent.session_id = "test-close-idempotent"
            agent._active_children = []
            agent._active_children_lock = threading.Lock()
            agent.client = None

            agent.close()
            agent.close()
            agent.close()

    def test_close_propagates_to_children(self):
        """close() should call close() on all active child agents."""
        from unittest.mock import MagicMock, patch

        with patch("run_agent.AIAgent.__init__", return_value=None):
            from run_agent import AIAgent
            agent = AIAgent.__new__(AIAgent)
            agent.session_id = "test-close-children"
            agent._active_children_lock = threading.Lock()
            agent.client = None

            child_1 = MagicMock()
            child_2 = MagicMock()
            agent._active_children = [child_1, child_2]

            agent.close()

            child_1.close.assert_called_once()
            child_2.close.assert_called_once()
            assert agent._active_children == []

    def test_close_ends_owned_session_row(self):
        """close() finalizes the agent's owned SQLite session row."""
        from unittest.mock import MagicMock, patch

        with patch("run_agent.AIAgent.__init__", return_value=None):
            from run_agent import AIAgent
            agent = AIAgent.__new__(AIAgent)
            agent.session_id = "test-close-session-row"
            agent._active_children = []
            agent._active_children_lock = threading.Lock()
            agent.client = None
            agent._end_session_on_close = True
            agent._session_db = MagicMock()

            agent.close()

            agent._session_db.end_session.assert_called_once_with(
                "test-close-session-row", "agent_close"
            )

    def test_close_skips_session_end_for_forwarded_continuation_agents(self):
        """Helper agents that handed session ownership forward opt out."""
        from unittest.mock import MagicMock, patch

        with patch("run_agent.AIAgent.__init__", return_value=None):
            from run_agent import AIAgent
            agent = AIAgent.__new__(AIAgent)
            agent.session_id = "test-close-forwarded-session"
            agent._active_children = []
            agent._active_children_lock = threading.Lock()
            agent.client = None
            agent._end_session_on_close = False
            agent._session_db = MagicMock()

            agent.close()

            agent._session_db.end_session.assert_not_called()

    def test_close_session_end_noops_without_session_db(self):
        """close() is a no-op for session finalization when no DB is wired in."""
        from unittest.mock import patch

        with patch("run_agent.AIAgent.__init__", return_value=None):
            from run_agent import AIAgent
            agent = AIAgent.__new__(AIAgent)
            agent.session_id = "test-close-no-db"
            agent._active_children = []
            agent._active_children_lock = threading.Lock()
            agent.client = None
            # No _session_db / _end_session_on_close attributes at all —
            # getattr defaults must keep close() from raising.
            agent.close()  # must not raise

    def test_close_survives_partial_failures(self):
        """close() continues cleanup even if one step fails."""
        from unittest.mock import patch

        with patch("run_agent.AIAgent.__init__", return_value=None):
            from run_agent import AIAgent
            agent = AIAgent.__new__(AIAgent)
            agent.session_id = "test-close-partial"
            agent._active_children = []
            agent._active_children_lock = threading.Lock()
            agent.client = None

            with patch(
                "tools.process_registry.process_registry"
            ) as mock_reg, patch(
                "run_agent.cleanup_vm"
            ) as mock_vm, patch(
                "run_agent.cleanup_browser"
            ) as mock_browser:
                mock_reg.kill_all.side_effect = RuntimeError("boom")

                agent.close()

                mock_vm.assert_called_once()
                mock_browser.assert_called_once()


class TestDelegationCleanup:
    """Verify subagent delegation cleans up child agents."""

    def test_run_single_child_calls_close(self):
        """_run_single_child finally block should call close() on child."""
        from unittest.mock import MagicMock
        from tools.delegate_tool import _run_single_child

        parent = MagicMock()
        parent._active_children = []
        parent._active_children_lock = threading.Lock()

        child = MagicMock()
        child._delegate_saved_tool_names = ["tool1"]
        child.run_conversation.side_effect = RuntimeError("test abort")

        parent._active_children.append(child)

        result = _run_single_child(
            task_index=0,
            goal="test goal",
            child=child,
            parent_agent=parent,
        )

        child.close.assert_called_once()
        assert child not in parent._active_children
        assert result["status"] == "error"
