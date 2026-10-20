"""Tests for cron/scheduler.py — origin resolution, delivery routing, and error logging."""

import json
import logging
from unittest.mock import patch, MagicMock

import pytest

from cron.scheduler import run_job, SILENT_MARKER, _build_job_prompt, _resolve_cron_enabled_toolsets, _merge_mcp_into_per_job_toolsets
from tools.env_passthrough import clear_env_passthrough
from tools.credential_files import clear_credential_files


class TestPerJobToolsetMcpMerge:
    """A per-job enabled_toolsets allowlist must not silently drop MCP servers."""

    CFG = {
        "mcp_servers": {
            "finnhub": {"enabled": True},
            "playwright": {"enabled": True},
            "disabled_one": {"enabled": False},
            "string_enabled": {"enabled": "true"},
            "not_a_dict": "ignored",
        }
    }

    def _enabled_names(self):
        return {"finnhub", "playwright", "string_enabled"}

    def test_native_only_list_gets_all_enabled_mcp_servers(self):
        result = _merge_mcp_into_per_job_toolsets(["web", "terminal"], self.CFG)
        assert result[:2] == ["web", "terminal"]
        assert set(result) == {"web", "terminal"} | self._enabled_names()

    def test_disabled_servers_are_not_added(self):
        result = _merge_mcp_into_per_job_toolsets(["web"], self.CFG)
        assert "disabled_one" not in result

    def test_explicit_mcp_name_is_treated_as_allowlist(self):
        # User named one server -> add nothing further.
        result = _merge_mcp_into_per_job_toolsets(["web", "finnhub"], self.CFG)
        assert result == ["web", "finnhub"]
        assert "playwright" not in result

    def test_no_mcp_sentinel_opts_out_and_is_stripped(self):
        result = _merge_mcp_into_per_job_toolsets(["web", "no_mcp"], self.CFG)
        assert result == ["web"]
        assert not (set(result) & self._enabled_names())

    def test_no_mcp_config_adds_nothing(self):
        result = _merge_mcp_into_per_job_toolsets(["web"], {})
        assert result == ["web"]

    def test_no_duplicate_when_listed_name_also_globally_enabled(self):
        result = _merge_mcp_into_per_job_toolsets(["finnhub", "finnhub"], self.CFG)
        assert result.count("finnhub") == 2  # input dups preserved, none added

    def test_resolver_uses_merge_for_per_job_lists(self):
        job = {"enabled_toolsets": ["web", "terminal"]}
        result = _resolve_cron_enabled_toolsets(job, self.CFG)
        assert set(result) == {"web", "terminal"} | self._enabled_names()

    def test_resolver_empty_per_job_falls_through_to_platform(self):
        # No per-job list -> must delegate to _get_platform_tools (the platform
        # fallback), NOT the per-job merge. Stub the platform resolver and assert
        # it is the path taken and its result is returned.
        job = {"enabled_toolsets": None}
        sentinel = ["web", "finnhub"]
        with patch("lliam_cli.tools_config._get_platform_tools",
                   return_value=set(sentinel)) as m_platform:
            result = _resolve_cron_enabled_toolsets(job, self.CFG)
        m_platform.assert_called_once()
        # _get_platform_tools args: (cfg, "cron")
        assert m_platform.call_args[0][1] == "cron"
        assert set(result) == set(sentinel)


class TestRunJobSessionPersistence:
    def test_run_job_passes_session_db_and_cron_platform(self, tmp_path):
        job = {
            "id": "test-job",
            "name": "test",
            "prompt": "hello",
        }
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "test-key",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent

            success, output, final_response, error = run_job(job)

        assert success is True
        assert error is None
        assert final_response == "ok"
        assert "ok" in output

        kwargs = mock_agent_cls.call_args.kwargs
        assert kwargs["session_db"] is fake_db
        assert kwargs["platform"] == "cron"
        assert kwargs["session_id"].startswith("cron_test-job_")
        fake_db.end_session.assert_called_once()
        call_args = fake_db.end_session.call_args
        assert call_args[0][0].startswith("cron_test-job_")
        assert call_args[0][1] == "cron_complete"
        fake_db.close.assert_called_once()
        mock_agent.close.assert_called_once()

    def test_run_job_suppresses_empty_turn_explainer(self, tmp_path):
        """An empty model turn becomes the '⚠️ No reply…' explainer (#34452).
        For cron, that abnormal-empty explainer must be treated as empty so it
        is suppressed instead of delivered (Manfredi's Telegram symptom)."""
        from run_agent import AIAgent
        explainer = AIAgent._format_turn_completion_explanation("empty_response_exhausted")
        assert explainer  # sanity: the explainer text exists
        job = {"id": "test-job", "name": "test", "prompt": "hello"}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "test-key",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent._format_turn_completion_explanation = (
                AIAgent._format_turn_completion_explanation
            )
            mock_agent.run_conversation.return_value = {
                "final_response": explainer,
                "turn_exit_reason": "empty_response_exhausted",
            }
            mock_agent_cls.return_value = mock_agent
            # Patch the class staticmethod the scheduler calls.
            mock_agent_cls._format_turn_completion_explanation = (
                AIAgent._format_turn_completion_explanation
            )

            success, output, final_response, error = run_job(job)

        # The explainer is stripped to empty inside run_job; the downstream
        # firing body (process_job) then suppresses delivery and marks the run
        # a soft failure via its empty-response guard.  Here we assert the
        # load-bearing transform: the "⚠️ No reply…" text never reaches delivery.
        assert final_response == ""

    def test_run_job_real_report_on_empty_reason_still_delivers(self, tmp_path):
        """Defensive: a real report must NOT be suppressed even if the result
        carries an abnormal turn_exit_reason — only the exact explainer text is."""
        from run_agent import AIAgent
        job = {"id": "test-job", "name": "test", "prompt": "hello"}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "test-key",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {
                "final_response": "Daily report: 4 PRs merged.",
                "turn_exit_reason": "empty_response_exhausted",
            }
            mock_agent_cls.return_value = mock_agent
            mock_agent_cls._format_turn_completion_explanation = (
                AIAgent._format_turn_completion_explanation
            )

            success, output, final_response, error = run_job(job)

        assert final_response == "Daily report: 4 PRs merged."
        assert success is True

    def test_run_job_titles_cron_session_from_job_not_important_hint(self, tmp_path):
        # The cron session's first message is the injected "[IMPORTANT: …]"
        # hint, which used to surface as the sidebar/history row label. run_job
        # must title the session from the job (name → short prompt → id).
        job = {
            "id": "test-job",
            "name": "Morning digest",
            "prompt": "summarize my inbox",
        }
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "test-key",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent

            run_job(job)

        fake_db.set_session_title.assert_called_once()
        sid, title = fake_db.set_session_title.call_args[0]
        assert sid.startswith("cron_test-job_")
        assert "IMPORTANT" not in title
        assert title.startswith("Morning digest")

    def test_run_job_closes_agent_on_failure_to_prevent_fd_leak(self, tmp_path):
        # Regression: if ``run_conversation`` raises, the ephemeral cron
        # agent was previously leaked — over days of ticks this accumulated
        # httpx transports and hit EMFILE / "too many open files".
        job = {
            "id": "failing-job",
            "name": "failing",
            "prompt": "hello",
        }
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "***",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.side_effect = RuntimeError("boom")
            mock_agent_cls.return_value = mock_agent

            success, output, final_response, error = run_job(job)

        assert success is False
        assert final_response == ""
        assert "RuntimeError: boom" in error
        mock_agent.close.assert_called_once()

    def test_run_job_reaps_stale_auxiliary_clients_per_tick(self, tmp_path):
        # Regression: auxiliary clients bound to the cron worker's dead
        # event loop must be reaped each tick. Without this, ``_client_cache``
        # holds onto transports whose underlying sockets can no longer be
        # closed (their loop is gone), leaking one fd batch per cron run.
        job = {
            "id": "aux-clean-job",
            "name": "aux-clean",
            "prompt": "hello",
        }
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "***",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("run_agent.AIAgent") as mock_agent_cls, \
             patch("agent.auxiliary_client.cleanup_stale_async_clients") as cleanup_mock:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent

            success, _output, _final_response, _error = run_job(job)

        assert success is True
        cleanup_mock.assert_called_once()

    def _make_run_job_patches(self, tmp_path):
        """Common patches for run_job tests."""
        fake_db = MagicMock()
        return fake_db, [
            patch("cron.scheduler._lliam_home", tmp_path),
            patch("dotenv.load_dotenv"),
            patch("lliam_state.SessionDB", return_value=fake_db),
            patch(
                "lliam_cli.runtime_provider.resolve_runtime_provider",
                return_value={
                    "api_key": "test-key",
                    "base_url": "https://example.invalid/v1",
                    "provider": "openrouter",
                    "api_mode": "chat_completions",
                },
            ),
        ]

    def test_run_job_passes_enabled_toolsets_to_agent(self, tmp_path):
        job = {
            "id": "toolset-job",
            "name": "test",
            "prompt": "hello",
            "enabled_toolsets": ["web", "terminal", "file"],
        }
        fake_db, patches = self._make_run_job_patches(tmp_path)
        with patches[0], patches[1], patches[2], patches[3], \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            run_job(job)

        kwargs = mock_agent_cls.call_args.kwargs
        assert kwargs["enabled_toolsets"] == ["web", "terminal", "file"]

    def test_run_job_disabled_toolsets_layer_user_config_on_baseline(self, tmp_path):
        """agent.disabled_toolsets must be honoured in cron — issue #25752.

        The bug: per-job enabled_toolsets was returned verbatim, letting an
        LLM-supplied cronjob() call re-enable tools the operator had globally
        disabled. The fix: ALWAYS include agent.disabled_toolsets in the
        disabled_toolsets passed to AIAgent, on top of the cron baseline
        (cronjob/messaging/clarify). AIAgent's disabled_toolsets takes
        precedence over enabled_toolsets, so this stops the bypass.
        """
        (tmp_path / "config.yaml").write_text(
            "agent:\n"
            "  disabled_toolsets:\n"
            "    - terminal\n"
            "    - file\n",
            encoding="utf-8",
        )
        job = {
            "id": "policy-job",
            "name": "test",
            "prompt": "hello",
            "enabled_toolsets": ["web", "terminal", "file"],
        }
        fake_db, patches = self._make_run_job_patches(tmp_path)
        with patches[0], patches[1], patches[2], patches[3], \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            run_job(job)

        kwargs = mock_agent_cls.call_args.kwargs
        assert set(kwargs["disabled_toolsets"]) >= {
            "cronjob", "messaging", "clarify", "terminal", "file",
        }

    def test_run_job_enabled_toolsets_resolves_from_platform_config_when_not_set(self, tmp_path):
        """When a job has no explicit enabled_toolsets, the scheduler now
        resolves them from ``lliam-gov tools`` platform config for ``cron``
        (PR #14xxx — blanket fix for Norbert's surprise ``moa`` run).

        The legacy "pass None → AIAgent loads full default" path is still
        reachable, but only when ``_get_platform_tools`` raises (safety net
        for any unexpected config shape).
        """
        job = {
            "id": "no-toolset-job",
            "name": "test",
            "prompt": "hello",
        }
        fake_db, patches = self._make_run_job_patches(tmp_path)
        with patches[0], patches[1], patches[2], patches[3], \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            run_job(job)

        kwargs = mock_agent_cls.call_args.kwargs
        # Resolution happened — not None, is a list.
        assert isinstance(kwargs["enabled_toolsets"], list)
        # The cron default is _HERMES_CORE_TOOLS with _DEFAULT_OFF_TOOLSETS
        # (``moa``, ``homeassistant``, ``rl``) removed. The most important
        # invariant: ``moa`` is NOT in the default cron toolset, so a cron
        # run cannot accidentally spin up frontier models.
        assert "moa" not in kwargs["enabled_toolsets"]

    def test_run_job_per_job_toolsets_win_over_platform_config(self, tmp_path):
        """Per-job enabled_toolsets (via cronjob tool) always take precedence
        over the platform-level ``lliam-gov tools`` config."""
        job = {
            "id": "override-job",
            "name": "test",
            "prompt": "hello",
            "enabled_toolsets": ["terminal"],
        }
        fake_db, patches = self._make_run_job_patches(tmp_path)
        # Even if the user has ``lliam-gov tools`` configured to enable web+file
        # for cron, the per-job override wins.
        with patches[0], patches[1], patches[2], patches[3], \
             patch("run_agent.AIAgent") as mock_agent_cls, \
             patch(
                 "lliam_cli.tools_config._get_platform_tools",
                 return_value={"web", "file"},
             ):
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            run_job(job)

        kwargs = mock_agent_cls.call_args.kwargs
        assert kwargs["enabled_toolsets"] == ["terminal"]

    def test_run_job_empty_response_returns_empty_not_placeholder(self, tmp_path):
        """Empty final_response should stay empty for delivery logic (issue #2234).

        The placeholder '(No response generated)' should only appear in the
        output log, not in the returned final_response that's used for delivery.
        """
        job = {
            "id": "silent-job",
            "name": "silent test",
            "prompt": "do work via tools only",
        }
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "***",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            # Agent did work via tools but returned no text
            mock_agent.run_conversation.return_value = {"final_response": ""}
            mock_agent_cls.return_value = mock_agent

            success, output, final_response, error = run_job(job)

        assert success is True
        assert error is None
        # final_response should be empty for delivery logic to skip
        assert final_response == ""
        # But the output log should show the placeholder
        assert "(No response generated)" in output

    @pytest.mark.parametrize(
        "agent_result,expected_err_substring",
        [
            (
                {
                    "final_response": "API call failed after 3 retries: Request timed out.",
                    "failed": True,
                    "completed": False,
                    "error": "API call failed after 3 retries: Request timed out.",
                },
                "API call failed",
            ),
            (
                {"final_response": None, "completed": False, "failed": True},
                "agent reported failure",
            ),
            (
                {"final_response": "", "completed": False},
                "agent reported failure",
            ),
            (
                {
                    "final_response": "partial reply before crash",
                    "failed": True,
                    "completed": False,
                    "error": "model abort: connection reset",
                },
                "model abort",
            ),
        ],
    )
    def test_run_job_treats_agent_failure_flag_as_failure(
        self, tmp_path, agent_result, expected_err_substring
    ):
        """Issue #17855: run_conversation returns ``failed=True``/``completed=False``
        when the agent's API call exhausts retries or aborts mid-run. run_job
        must surface this as success=False so cron's last_status reflects the
        failure and the user gets an error notification, instead of treating
        the (often non-empty) error string in final_response as a legitimate
        agent reply.
        """
        job = {
            "id": "failing-api-job",
            "name": "failing api",
            "prompt": "do something",
        }
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "***",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = agent_result
            mock_agent_cls.return_value = mock_agent

            success, output, final_response, error = run_job(job)

        assert success is False
        assert final_response == ""
        assert error is not None and expected_err_substring in error
        # Output should be the FAILED template, not the success template.
        assert "(FAILED)" in output
        # Ephemeral cron agent must still be closed even on agent-flagged failure.
        mock_agent.close.assert_called_once()

    def test_run_job_completed_true_without_failed_flag_succeeds(self, tmp_path):
        """Regression guard: a normal success result (``completed=True``,
        ``failed`` absent) must not trip the failure-flag check.
        """
        job = {
            "id": "ok-job",
            "name": "ok",
            "prompt": "hello",
        }
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "***",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {
                "final_response": "all good",
                "completed": True,
            }
            mock_agent_cls.return_value = mock_agent

            success, output, final_response, error = run_job(job)

        assert success is True
        assert error is None
        assert final_response == "all good"

    def test_run_job_delivers_max_iteration_fallback_summary(self, tmp_path):
        """Cron should deliver a usable max-iteration fallback summary.

        A cron run can exhaust the iteration budget, get a final text summary
        from the no-tools fallback call, and still have ``completed=False`` in
        the generic agent result. That should not make cron raise the report
        text as a RuntimeError.
        """
        job = {
            "id": "summary-job",
            "name": "summary",
            "prompt": "finish the report",
        }
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "***",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {
                "final_response": "final fallback report",
                "completed": False,
                "failed": False,
                "turn_exit_reason": "max_iterations_reached(60/60)",
            }
            mock_agent_cls.return_value = mock_agent

            success, output, final_response, error = run_job(job)

        assert success is True
        assert error is None
        assert final_response == "final fallback report"
        assert "final fallback report" in output
        assert "(FAILED)" not in output

    def test_tick_marks_empty_response_as_error(self, tmp_path):
        """When run_job returns success=True but final_response is empty,
        tick() should mark the job as error so last_status != 'ok'.
        (issue #8585)
        """
        from cron.scheduler import tick

        job = {
            "id": "empty-job",
            "name": "empty-test",
            "prompt": "do something",
            "schedule": "every 1h",
            "enabled": True,
            "next_run_at": "2020-01-01T00:00:00",
            "deliver": "local",
            "last_status": None,
        }

        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("cron.scheduler.get_due_jobs", return_value=[job]), \
             patch("cron.scheduler.advance_next_run"), \
             patch("cron.scheduler.mark_job_run") as mock_mark, \
             patch("cron.scheduler.save_job_output", return_value="/tmp/out.md"), \
             patch("cron.scheduler.run_job", return_value=(True, "output", "", None)):
            tick(verbose=False)

        # Should be called with success=False because final_response is empty
        mock_mark.assert_called_once()
        call_args = mock_mark.call_args
        assert call_args[0][0] == "empty-job"
        assert call_args[0][1] is False  # success should be False
        assert "empty" in call_args[0][2].lower()  # error should mention empty

class TestRunJobConfigLogging:
    """Verify that config.yaml parse failures are logged, not silently swallowed."""

    def test_bad_config_yaml_is_logged(self, caplog, tmp_path):
        """When config.yaml is malformed, a warning should be logged."""
        bad_yaml = tmp_path / "config.yaml"
        bad_yaml.write_text("invalid: yaml: [[[bad")

        job = {
            "id": "test-job",
            "name": "test",
            "prompt": "hello",
        }

        # Mock heavy post-yaml work so the test only exercises the warning
        # path. Without these mocks, run_job continues into provider
        # resolution and MCP discovery, both of which can spawn subprocesses
        # / hit the network and have caused this test to time out on CI
        # (>30s wall clock) under load. See PR #33661 follow-up.
        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value={"provider": "openrouter", "api_key": "x",
                                 "base_url": "https://example.invalid",
                                 "api_mode": "chat_completions"}), \
             patch("tools.mcp_tool.discover_mcp_tools", return_value=[]), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent

            with caplog.at_level(logging.WARNING, logger="cron.scheduler"):
                run_job(job)

        assert any("failed to load config.yaml" in r.message for r in caplog.records), \
            f"Expected 'failed to load config.yaml' warning in logs, got: {[r.message for r in caplog.records]}"

    def test_bad_prefill_messages_is_logged(self, caplog, tmp_path):
        """When the prefill messages file contains invalid JSON, a warning should be logged."""
        # Valid config.yaml that points to a bad prefill file
        config_yaml = tmp_path / "config.yaml"
        config_yaml.write_text("prefill_messages_file: prefill.json\n")

        bad_prefill = tmp_path / "prefill.json"
        bad_prefill.write_text("{not valid json!!!")

        job = {
            "id": "test-job",
            "name": "test",
            "prompt": "hello",
        }

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value={"provider": "openrouter", "api_key": "x",
                                 "base_url": "https://example.invalid",
                                 "api_mode": "chat_completions"}), \
             patch("tools.mcp_tool.discover_mcp_tools", return_value=[]), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent

            with caplog.at_level(logging.WARNING, logger="cron.scheduler"):
                run_job(job)

        assert any("failed to parse prefill messages" in r.message for r in caplog.records), \
            f"Expected 'failed to parse prefill messages' warning in logs, got: {[r.message for r in caplog.records]}"


class TestRunJobConfigEnvVarExpansion:
    """Verify that ${VAR} references in config.yaml are expanded when running cron jobs."""

    _RUNTIME = {
        "api_key": "test-key",
        "base_url": "https://example.invalid/v1",
        "provider": "openrouter",
        "api_mode": "chat_completions",
    }

    def test_model_env_ref_in_config_yaml_is_expanded(self, tmp_path, monkeypatch):
        """${VAR} in config.yaml model: is expanded using env after .env is loaded."""
        (tmp_path / "config.yaml").write_text("model: ${_HERMES_TEST_CRON_MODEL}\n")
        monkeypatch.setenv("_HERMES_TEST_CRON_MODEL", "gpt-4o-mini-cron-test")

        job = {"id": "env-job", "name": "env test", "prompt": "hi"}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            success, _, _, error = run_job(job)

        assert success is True
        assert error is None
        kwargs = mock_agent_cls.call_args.kwargs
        assert kwargs["model"] == "gpt-4o-mini-cron-test", (
            f"Expected model='gpt-4o-mini-cron-test', got {kwargs['model']!r}. "
            "config.yaml ${VAR} was not expanded in the cron execution path."
        )

    def test_legacy_agent_prefill_messages_file_is_loaded(self, tmp_path, monkeypatch):
        """Cron accepts the legacy agent.prefill_messages_file fallback."""
        prefill = [{"role": "system", "content": "legacy cron prefill"}]
        (tmp_path / "prefill.json").write_text(json.dumps(prefill), encoding="utf-8")
        (tmp_path / "config.yaml").write_text(
            "agent:\n"
            "  prefill_messages_file: prefill.json\n",
            encoding="utf-8",
        )

        job = {"id": "prefill-job", "name": "prefill test", "prompt": "hi"}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("tools.mcp_tool.discover_mcp_tools", return_value=[]), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            success, _, _, error = run_job(job)

        assert success is True
        assert error is None
        assert mock_agent_cls.call_args.kwargs["prefill_messages"] == prefill

    def test_fallback_model_env_ref_in_config_yaml_is_expanded(self, tmp_path, monkeypatch):
        """${VAR} in config.yaml fallback_providers model: is expanded."""
        (tmp_path / "config.yaml").write_text(
            "model: primary-model\n"
            "fallback_providers:\n"
            "  - provider: openrouter\n"
            "    model: ${_HERMES_TEST_CRON_FALLBACK}\n"
        )
        monkeypatch.setenv("_HERMES_TEST_CRON_FALLBACK", "gpt-4o-fallback-test")

        job = {"id": "fb-job", "name": "fallback test", "prompt": "hi"}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            run_job(job)

        kwargs = mock_agent_cls.call_args.kwargs
        fb = kwargs.get("fallback_model") or []
        fb_list = fb if isinstance(fb, list) else [fb]
        expanded = [e.get("model") for e in fb_list if isinstance(e, dict)]
        assert "gpt-4o-fallback-test" in expanded, (
            f"Expected expanded fallback model in {expanded!r}. "
            "config.yaml ${VAR} in fallback_providers was not expanded."
        )

    def test_unexpanded_ref_passthrough_when_var_unset(self, tmp_path, monkeypatch):
        """When the env var is not set, the literal ${VAR} is kept verbatim (not crashed)."""
        (tmp_path / "config.yaml").write_text("model: ${_HERMES_TEST_CRON_UNSET_VAR}\n")
        monkeypatch.delenv("_HERMES_TEST_CRON_UNSET_VAR", raising=False)

        job = {"id": "unset-job", "name": "unset var test", "prompt": "hi"}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            success, _, _, error = run_job(job)

        assert success is True
        kwargs = mock_agent_cls.call_args.kwargs
        # Unresolved refs are kept verbatim — _expand_env_vars contract
        assert kwargs["model"] == "${_HERMES_TEST_CRON_UNSET_VAR}"


class TestRunJobModelResolution:
    """Verify defensive model resolution for jobs stored with ``model: null``.

    Issue #23979: a cron job created without an explicit model is stored as
    ``model: null``. At fire time the scheduler must:
      1. fall back to ``HERMES_MODEL`` env if set,
      2. else fall back to config.yaml ``model.default`` if set,
      3. else fail fast with an actionable error — never let an empty string
         reach the provider where it surfaces as an opaque 400.
    """

    _RUNTIME = {
        "api_key": "test-key",
        "base_url": "https://example.invalid/v1",
        "provider": "openrouter",
        "api_mode": "chat_completions",
    }

    def test_null_job_model_falls_back_to_env(self, tmp_path, monkeypatch):
        """``model: null`` on the job uses HERMES_MODEL when set."""
        (tmp_path / "config.yaml").write_text("")
        monkeypatch.setenv("HERMES_MODEL", "env-model")

        job = {"id": "null-model-job", "name": "null model", "prompt": "hi", "model": None}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            success, _, _, error = run_job(job)

        assert success is True
        assert error is None
        assert mock_agent_cls.call_args.kwargs["model"] == "env-model"

    def test_null_job_model_falls_back_to_config_default(self, tmp_path, monkeypatch):
        """``model: null`` on the job uses config.yaml model.default when env is empty."""
        (tmp_path / "config.yaml").write_text("model:\n  default: config-default-model\n")
        monkeypatch.delenv("HERMES_MODEL", raising=False)

        job = {"id": "cfg-default-job", "name": "cfg default", "prompt": "hi", "model": None}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            success, _, _, error = run_job(job)

        assert success is True
        assert error is None
        assert mock_agent_cls.call_args.kwargs["model"] == "config-default-model"

    def test_explicit_null_model_block_in_config_does_not_overwrite_env(self, tmp_path, monkeypatch):
        """``model: null`` in config.yaml must not overwrite a resolved HERMES_MODEL.

        Regression: before #23979 the resolver coerced ``model: null`` to
        ``{}`` only via the ``.get("model", {})`` default — which does not
        fire when the key is present with a None value. The resolver then
        skipped both branches and kept the env value, but a similar
        ``model: {default: null}`` shape would call ``.get("default", model)``
        which returns ``None`` and clobbered ``model``.
        """
        (tmp_path / "config.yaml").write_text("model:\n  default: null\n")
        monkeypatch.setenv("HERMES_MODEL", "env-model")

        job = {"id": "null-default-job", "name": "null default", "prompt": "hi", "model": None}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            success, _, _, error = run_job(job)

        assert success is True
        assert mock_agent_cls.call_args.kwargs["model"] == "env-model"

    def test_no_model_anywhere_fails_with_actionable_error(self, tmp_path, monkeypatch):
        """All three sources empty → fail fast with a clear message, not an opaque 400."""
        (tmp_path / "config.yaml").write_text("")
        monkeypatch.delenv("HERMES_MODEL", raising=False)

        job = {"id": "no-model-job", "name": "no model anywhere", "prompt": "hi", "model": None}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            success, _, _, error = run_job(job)

        assert success is False
        assert error is not None
        assert "no model configured" in error
        # AIAgent must never be constructed with an empty model — that's
        # precisely the bug we're guarding against.
        mock_agent_cls.assert_not_called()

    def test_job_model_update_takes_effect_on_next_run(self, tmp_path, monkeypatch):
        """The per-job model is re-read every tick — no in-memory cache.

        This is the property the original bug report asked for. We verify
        it by calling run_job twice with the same job dict mutated between
        calls, simulating the storage update flow.
        """
        (tmp_path / "config.yaml").write_text("")
        monkeypatch.delenv("HERMES_MODEL", raising=False)

        job = {"id": "updated-model-job", "name": "updated", "prompt": "hi", "model": "first-model"}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent

            run_job(job)
            assert mock_agent_cls.call_args.kwargs["model"] == "first-model"

            job["model"] = "second-model"  # simulates jobs.json being rewritten
            run_job(job)
            assert mock_agent_cls.call_args.kwargs["model"] == "second-model"

    def test_config_model_as_plain_string(self, tmp_path, monkeypatch):
        """config.yaml ``model:`` given as a bare string is used directly."""
        (tmp_path / "config.yaml").write_text("model: string-form-model\n")
        monkeypatch.delenv("HERMES_MODEL", raising=False)

        job = {"id": "string-cfg-job", "name": "string cfg", "prompt": "hi", "model": None}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            success, _, _, error = run_job(job)

        assert success is True
        assert error is None
        assert mock_agent_cls.call_args.kwargs["model"] == "string-form-model"

    def test_config_model_alias_key_resolves(self, tmp_path, monkeypatch):
        """A ``model: {model: ...}`` alias key resolves like the CLI sibling.

        ``lliam_cli/oneshot.py``, ``fallback_cmd.py`` and ``prompt_size.py``
        all accept ``model.model`` as an alias for ``model.default``. The cron
        resolver mirrors that so a config that works in the CLI also works in
        cron.
        """
        (tmp_path / "config.yaml").write_text("model:\n  model: alias-key-model\n")
        monkeypatch.delenv("HERMES_MODEL", raising=False)

        job = {"id": "alias-job", "name": "alias", "prompt": "hi", "model": None}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            success, _, _, error = run_job(job)

        assert success is True
        assert error is None
        assert mock_agent_cls.call_args.kwargs["model"] == "alias-key-model"

    def test_corrupt_config_yaml_does_not_crash_with_job_model(self, tmp_path, monkeypatch):
        """A malformed config.yaml degrades gracefully when the job has a model."""
        (tmp_path / "config.yaml").write_text("{{{invalid yaml!!!")
        monkeypatch.delenv("HERMES_MODEL", raising=False)

        job = {"id": "corrupt-job", "name": "corrupt", "prompt": "hi", "model": "explicit-model"}
        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch("lliam_cli.runtime_provider.resolve_runtime_provider",
                   return_value=self._RUNTIME), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent
            success, _, _, error = run_job(job)

        # Explicit job model survives the corrupt-config fall-through.
        assert success is True
        assert error is None
        assert mock_agent_cls.call_args.kwargs["model"] == "explicit-model"


class TestRunJobSkillBacked:
    def test_run_job_preserves_skill_env_passthrough_into_worker_thread(self, tmp_path):
        job = {
            "id": "skill-env-job",
            "name": "skill env test",
            "prompt": "Use the skill.",
            "skill": "notion",
        }

        fake_db = MagicMock()

        def _skill_view(name):
            assert name == "notion"
            from tools.env_passthrough import register_env_passthrough

            register_env_passthrough(["NOTION_API_KEY"])
            return json.dumps({"success": True, "content": "# notion\nUse Notion."})

        def _run_conversation(prompt):
            from tools.env_passthrough import get_all_passthrough

            assert "NOTION_API_KEY" in get_all_passthrough()
            return {"final_response": "ok"}

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "***",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("tools.skills_tool.skill_view", side_effect=_skill_view), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.side_effect = _run_conversation
            mock_agent_cls.return_value = mock_agent

            try:
                success, output, final_response, error = run_job(job)
            finally:
                clear_env_passthrough()

        assert success is True
        assert error is None
        assert final_response == "ok"

    def test_run_job_preserves_credential_file_passthrough_into_worker_thread(self, tmp_path):
        """copy_context() also propagates credential_files ContextVar."""
        job = {
            "id": "cred-env-job",
            "name": "cred file test",
            "prompt": "Use the skill.",
            "skill": "google-workspace",
        }

        fake_db = MagicMock()

        # Create a credential file so register_credential_file succeeds
        cred_dir = tmp_path / "credentials"
        cred_dir.mkdir()
        (cred_dir / "google_token.json").write_text('{"token": "t"}')

        def _skill_view(name):
            assert name == "google-workspace"
            from tools.credential_files import register_credential_file

            register_credential_file("credentials/google_token.json")
            return json.dumps({"success": True, "content": "# google-workspace\nUse Google."})

        def _run_conversation(prompt):
            from tools.credential_files import _get_registered

            registered = _get_registered()
            assert registered, "credential files must be visible in worker thread"
            assert any("google_token.json" in v for v in registered.values())
            return {"final_response": "ok"}

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("tools.credential_files._resolve_lliam_home", return_value=tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "***",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("tools.skills_tool.skill_view", side_effect=_skill_view), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.side_effect = _run_conversation
            mock_agent_cls.return_value = mock_agent

            try:
                success, output, final_response, error = run_job(job)
            finally:
                clear_credential_files()

        assert success is True
        assert error is None
        assert final_response == "ok"

    def test_run_job_loads_skill_and_disables_recursive_cron_tools(self, tmp_path):
        job = {
            "id": "skill-job",
            "name": "skill test",
            "prompt": "Check the feeds and summarize anything new.",
            "skill": "blogwatcher",
        }

        fake_db = MagicMock()

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "***",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("tools.skills_tool.skill_view", return_value=json.dumps({"success": True, "content": "# Blogwatcher\nFollow this skill."})), \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent

            success, output, final_response, error = run_job(job)

        assert success is True
        assert error is None
        assert final_response == "ok"

        kwargs = mock_agent_cls.call_args.kwargs
        assert "cronjob" in (kwargs["disabled_toolsets"] or [])

        prompt_arg = mock_agent.run_conversation.call_args.args[0]
        assert "blogwatcher" in prompt_arg
        assert "Follow this skill" in prompt_arg
        assert "Check the feeds and summarize anything new." in prompt_arg

    def test_run_job_loads_multiple_skills_in_order(self, tmp_path):
        job = {
            "id": "multi-skill-job",
            "name": "multi skill test",
            "prompt": "Combine the results.",
            "skills": ["blogwatcher", "maps"],
        }

        fake_db = MagicMock()

        def _skill_view(name):
            return json.dumps({"success": True, "content": f"# {name}\nInstructions for {name}."})

        with patch("cron.scheduler._lliam_home", tmp_path), \
             patch("dotenv.load_dotenv"), \
             patch("lliam_state.SessionDB", return_value=fake_db), \
             patch(
                 "lliam_cli.runtime_provider.resolve_runtime_provider",
                 return_value={
                     "api_key": "***",
                     "base_url": "https://example.invalid/v1",
                     "provider": "openrouter",
                     "api_mode": "chat_completions",
                 },
             ), \
             patch("tools.skills_tool.skill_view", side_effect=_skill_view) as skill_view_mock, \
             patch("run_agent.AIAgent") as mock_agent_cls:
            mock_agent = MagicMock()
            mock_agent.run_conversation.return_value = {"final_response": "ok"}
            mock_agent_cls.return_value = mock_agent

            success, output, final_response, error = run_job(job)

        assert success is True
        assert error is None
        assert final_response == "ok"
        assert skill_view_mock.call_count == 2
        assert [call.args[0] for call in skill_view_mock.call_args_list] == ["blogwatcher", "maps"]

        prompt_arg = mock_agent.run_conversation.call_args.args[0]
        assert prompt_arg.index("blogwatcher") < prompt_arg.index("maps")
        assert "Instructions for blogwatcher." in prompt_arg
        assert "Instructions for maps." in prompt_arg
        assert "Combine the results." in prompt_arg


class TestParseWakeGate:
    """Unit tests for _parse_wake_gate — pure function, no side effects."""

    def test_empty_output_wakes(self):
        from cron.scheduler import _parse_wake_gate
        assert _parse_wake_gate("") is True
        assert _parse_wake_gate(None) is True

    def test_whitespace_only_wakes(self):
        from cron.scheduler import _parse_wake_gate
        assert _parse_wake_gate("   \n\n  \t\n") is True

    def test_non_json_last_line_wakes(self):
        from cron.scheduler import _parse_wake_gate
        assert _parse_wake_gate("hello world") is True
        assert _parse_wake_gate("line 1\nline 2\nplain text") is True

    def test_json_non_dict_wakes(self):
        """Bare arrays, numbers, strings must not be interpreted as a gate."""
        from cron.scheduler import _parse_wake_gate
        assert _parse_wake_gate("[1, 2, 3]") is True
        assert _parse_wake_gate("42") is True
        assert _parse_wake_gate('"wakeAgent"') is True

    def test_wake_gate_false_skips(self):
        from cron.scheduler import _parse_wake_gate
        assert _parse_wake_gate('{"wakeAgent": false}') is False

    def test_wake_gate_true_wakes(self):
        from cron.scheduler import _parse_wake_gate
        assert _parse_wake_gate('{"wakeAgent": true}') is True

    def test_wake_gate_missing_wakes(self):
        """A JSON dict without a wakeAgent key defaults to waking."""
        from cron.scheduler import _parse_wake_gate
        assert _parse_wake_gate('{"data": {"foo": "bar"}}') is True

    def test_non_boolean_false_still_wakes(self):
        """Only strict ``False`` skips — truthy/falsy shortcuts are too risky."""
        from cron.scheduler import _parse_wake_gate
        assert _parse_wake_gate('{"wakeAgent": 0}') is True
        assert _parse_wake_gate('{"wakeAgent": null}') is True
        assert _parse_wake_gate('{"wakeAgent": ""}') is True

    def test_only_last_non_empty_line_parsed(self):
        from cron.scheduler import _parse_wake_gate
        multi = 'some log output\nmore output\n{"wakeAgent": false}'
        assert _parse_wake_gate(multi) is False

    def test_trailing_blank_lines_ignored(self):
        from cron.scheduler import _parse_wake_gate
        multi = '{"wakeAgent": false}\n\n\n'
        assert _parse_wake_gate(multi) is False

    def test_non_last_json_line_does_not_gate(self):
        """A JSON gate on an earlier line with plain text after it does NOT trigger."""
        from cron.scheduler import _parse_wake_gate
        multi = '{"wakeAgent": false}\nactually this is the real output'
        assert _parse_wake_gate(multi) is True


class TestRunJobWakeGate:
    """Integration tests for run_job wake-gate short-circuit."""

    @pytest.fixture(autouse=True)
    def _stub_runtime_provider(self):
        """Stub ``resolve_runtime_provider`` for wake-gate tests.

        ``run_job`` resolves the runtime provider BEFORE constructing
        ``AIAgent``, so these tests must mock ``resolve_runtime_provider``
        in addition to ``AIAgent`` — otherwise in a hermetic CI env (no
        API keys), the resolver raises and the test fails before the
        patched AIAgent is ever reached.
        """
        fake_runtime = {
            "provider": "openrouter",
            "api_mode": "chat_completions",
            "base_url": "https://openrouter.ai/api/v1",
            "api_key": "test-key",
            "source": "stub",
            "requested_provider": None,
        }
        with patch(
            "lliam_cli.runtime_provider.resolve_runtime_provider",
            return_value=fake_runtime,
        ):
            yield

    def _make_job(self, name="wake-gate-test", script="check.py"):
        """Minimal valid cron job dict for run_job."""
        return {
            "id": f"job_{name}",
            "name": name,
            "prompt": "Do a thing",
            "schedule": "*/5 * * * *",
            "script": script,
        }

    def test_wake_false_skips_agent_and_returns_silent(self, caplog):
        """When _run_job_script output ends with {wakeAgent: false}, the agent
        is not invoked and run_job returns the SILENT marker so delivery is
        suppressed."""
        import cron.scheduler as scheduler

        with patch.object(scheduler, "_run_job_script",
                          return_value=(True, '{"wakeAgent": false}')), \
             patch("run_agent.AIAgent") as agent_cls:
            success, doc, final, err = scheduler.run_job(self._make_job())

        assert success is True
        assert err is None
        assert final == SILENT_MARKER
        assert "Script gate returned `wakeAgent=false`" in doc
        agent_cls.assert_not_called()

    def test_wake_true_runs_agent_with_injected_output(self):
        """When the script returns {wakeAgent: true, data: ...}, the agent is
        invoked and the data line still shows up in the prompt."""
        import cron.scheduler as scheduler

        script_output = '{"wakeAgent": true, "data": {"new": 3}}'
        agent = MagicMock()
        agent.run_conversation = MagicMock(return_value={
            "final_response": "ok", "messages": []
        })
        with patch.object(scheduler, "_run_job_script",
                          return_value=(True, script_output)), \
             patch("run_agent.AIAgent", return_value=agent) as agent_cls:
            success, doc, final, err = scheduler.run_job(self._make_job())

        agent_cls.assert_called_once()
        # The script output should be visible in the prompt passed to
        # run_conversation.
        call_kwargs = agent.run_conversation.call_args
        prompt_arg = call_kwargs.args[0] if call_kwargs.args else call_kwargs.kwargs.get("user_message", "")
        assert script_output in prompt_arg
        assert success is True
        assert err is None

    def test_script_runs_only_once_on_wake(self):
        """Wake-true path must not re-run the script inside _build_job_prompt
        (script would execute twice otherwise, wasting work and risking
        double-side-effects)."""
        import cron.scheduler as scheduler

        call_count = 0
        def _script_stub(path):
            nonlocal call_count
            call_count += 1
            return (True, "regular output")

        agent = MagicMock()
        agent.run_conversation = MagicMock(return_value={
            "final_response": "ok", "messages": []
        })
        with patch.object(scheduler, "_run_job_script", side_effect=_script_stub), \
             patch("run_agent.AIAgent", return_value=agent):
            scheduler.run_job(self._make_job())

        assert call_count == 1, f"script ran {call_count}x, expected exactly 1"

    def test_script_failure_does_not_trigger_gate(self):
        """If _run_job_script returns success=False, the gate is NOT evaluated
        and the agent still runs (the failure is reported as context)."""
        import cron.scheduler as scheduler

        # Malicious or broken script whose stderr happens to contain the
        # gate JSON — we must NOT honor it because ran_ok is False.
        agent = MagicMock()
        agent.run_conversation = MagicMock(return_value={
            "final_response": "ok", "messages": []
        })
        with patch.object(scheduler, "_run_job_script",
                          return_value=(False, '{"wakeAgent": false}')), \
             patch("run_agent.AIAgent", return_value=agent) as agent_cls:
            success, doc, final, err = scheduler.run_job(self._make_job())

        agent_cls.assert_called_once()  # Agent DID wake despite the gate-like text

    def test_no_script_path_runs_agent_normally(self):
        """Regression: jobs without a script still work."""
        import cron.scheduler as scheduler

        agent = MagicMock()
        agent.run_conversation = MagicMock(return_value={
            "final_response": "ok", "messages": []
        })
        job = self._make_job(script=None)
        job.pop("script", None)
        with patch.object(scheduler, "_run_job_script") as script_fn, \
             patch("run_agent.AIAgent", return_value=agent) as agent_cls:
            scheduler.run_job(job)

        script_fn.assert_not_called()
        agent_cls.assert_called_once()


class TestBuildJobPromptMissingSkill:
    """Verify that a missing skill logs a warning and does not crash the job."""

    def _missing_skill_view(self, name: str) -> str:
        return json.dumps({"success": False, "error": f"Skill '{name}' not found."})

    def test_missing_skill_does_not_raise(self):
        """Job should run even when a referenced skill is not installed."""
        with patch("tools.skills_tool.skill_view", side_effect=self._missing_skill_view):
            result = _build_job_prompt({"skills": ["ghost-skill"], "prompt": "do something"})
        # prompt is preserved even though skill was skipped
        assert "do something" in result

    def test_missing_skill_injects_user_notice_into_prompt(self):
        """A system notice about the missing skill is injected into the prompt."""
        with patch("tools.skills_tool.skill_view", side_effect=self._missing_skill_view):
            result = _build_job_prompt({"skills": ["ghost-skill"], "prompt": "do something"})
        assert "ghost-skill" in result
        assert "not found" in result.lower() or "skipped" in result.lower()

    def test_missing_skill_logs_warning(self, caplog):
        """A warning is logged when a skill cannot be found."""
        with caplog.at_level(logging.WARNING, logger="cron.scheduler"):
            with patch("tools.skills_tool.skill_view", side_effect=self._missing_skill_view):
                _build_job_prompt({"name": "My Job", "skills": ["ghost-skill"], "prompt": "do something"})
        assert any("ghost-skill" in record.message for record in caplog.records)

    def test_valid_skill_loaded_alongside_missing(self):
        """A valid skill is still loaded when another skill in the list is missing."""

        def _mixed_skill_view(name: str) -> str:
            if name == "real-skill":
                return json.dumps({"success": True, "content": "Real skill content."})
            return json.dumps({"success": False, "error": f"Skill '{name}' not found."})

        with patch("tools.skills_tool.skill_view", side_effect=_mixed_skill_view):
            result = _build_job_prompt({"skills": ["ghost-skill", "real-skill"], "prompt": "go"})
        assert "Real skill content." in result
        assert "go" in result


class TestBuildJobPromptBumpUse:
    """Verify that cron jobs bump skill usage counters so the curator sees them as active."""

    def test_bump_use_called_for_loaded_skill(self):
        """bump_use is called for each successfully loaded skill."""

        def _skill_view(name: str) -> str:
            return json.dumps({"success": True, "content": f"Content for {name}."})

        with patch("tools.skills_tool.skill_view", side_effect=_skill_view), \
             patch("tools.skill_usage.bump_use") as mock_bump:
            _build_job_prompt({"skills": ["alpha", "beta"], "prompt": "go"})

        assert mock_bump.call_count == 2
        calls = [c[0][0] for c in mock_bump.call_args_list]
        assert "alpha" in calls
        assert "beta" in calls

    def test_bump_use_not_called_for_missing_skill(self):
        """bump_use is NOT called when a skill fails to load."""

        def _missing_view(name: str) -> str:
            return json.dumps({"success": False, "error": "not found"})

        with patch("tools.skills_tool.skill_view", side_effect=_missing_view), \
             patch("tools.skill_usage.bump_use") as mock_bump:
            _build_job_prompt({"skills": ["ghost"], "prompt": "go"})

        assert mock_bump.call_count == 0

    def test_bump_failure_does_not_break_prompt(self, caplog):
        """If bump_use raises, the prompt still builds — error is logged at DEBUG."""

        def _skill_view(name: str) -> str:
            return json.dumps({"success": True, "content": "Works."})

        with patch("tools.skills_tool.skill_view", side_effect=_skill_view), \
             patch("tools.skill_usage.bump_use", side_effect=RuntimeError("boom")), \
             caplog.at_level(logging.DEBUG, logger="cron.scheduler"):
            result = _build_job_prompt({"skills": ["good-skill"], "prompt": "go"})

        # Prompt should still contain the skill content and original instruction
        assert "Works." in result
        assert "go" in result
        # The error should be logged at DEBUG level, not crash
        assert any("failed to bump" in r.message for r in caplog.records)


class TestParallelTick:
    """Verify that tick() runs due jobs concurrently and isolates ContextVars."""

    @pytest.fixture(autouse=True)
    def _isolate_tick_lock(self, tmp_path):
        """Point the tick file lock at a per-test temp dir to avoid xdist contention."""
        lock_dir = tmp_path / "cron"
        lock_dir.mkdir()
        lock_file = lock_dir / ".tick.lock"
        with patch("cron.scheduler._get_lock_paths", return_value=(lock_dir, lock_file)):
            yield

    def test_parallel_jobs_run_concurrently(self):
        """Two jobs launched in the same tick should overlap in time."""
        import threading

        barrier = threading.Barrier(2, timeout=5)
        call_order = []

        def mock_run_job(job):
            """Each job hits a barrier — both must be active simultaneously."""
            call_order.append(("start", job["id"]))
            barrier.wait()  # blocks until both threads reach here
            call_order.append(("end", job["id"]))
            return (True, "output", "response", None)

        jobs = [
            {"id": "job-a", "name": "a", "deliver": "local"},
            {"id": "job-b", "name": "b", "deliver": "local"},
        ]

        with patch("cron.scheduler.get_due_jobs", return_value=jobs), \
             patch("cron.scheduler.advance_next_run"), \
             patch("cron.scheduler.run_job", side_effect=mock_run_job), \
             patch("cron.scheduler.save_job_output", return_value="/tmp/out.md"), \
             patch("cron.scheduler.mark_job_run"):
            from cron.scheduler import tick
            result = tick(verbose=False)

        assert result == 2
        # Both starts happened before both ends — proof of concurrency
        starts = [i for i, (action, _) in enumerate(call_order) if action == "start"]
        ends = [i for i, (action, _) in enumerate(call_order) if action == "end"]
        assert len(starts) == 2
        assert len(ends) == 2
        assert max(starts) < min(ends), f"Jobs not concurrent: {call_order}"

    def test_parallel_jobs_isolated_contextvars(self):
        """Each job's ContextVars must be isolated — no cross-contamination."""
        from agent.session_context import get_session_env
        seen = {}

        def mock_run_job(job):
            origin = job.get("origin", {})
            # run_job sets ContextVars — verify each job sees its own
            from agent.session_context import set_session_vars, clear_session_vars
            tokens = set_session_vars(
                platform=origin.get("platform", ""),
                chat_id=str(origin.get("chat_id", "")),
            )
            import time
            time.sleep(0.05)  # give other thread time to set its vars
            platform = get_session_env("HERMES_SESSION_PLATFORM")
            chat_id = get_session_env("HERMES_SESSION_CHAT_ID")
            seen[job["id"]] = {"platform": platform, "chat_id": chat_id}
            clear_session_vars(tokens)
            return (True, "output", "response", None)

        jobs = [
            {"id": "tg-job", "name": "tg", "deliver": "local",
             "origin": {"platform": "telegram", "chat_id": "111"}},
            {"id": "dc-job", "name": "dc", "deliver": "local",
             "origin": {"platform": "discord", "chat_id": "222"}},
        ]

        with patch("cron.scheduler.get_due_jobs", return_value=jobs), \
             patch("cron.scheduler.advance_next_run"), \
             patch("cron.scheduler.run_job", side_effect=mock_run_job), \
             patch("cron.scheduler.save_job_output", return_value="/tmp/out.md"), \
             patch("cron.scheduler.mark_job_run"):
            from cron.scheduler import tick
            tick(verbose=False)

        assert seen["tg-job"] == {"platform": "telegram", "chat_id": "111"}
        assert seen["dc-job"] == {"platform": "discord", "chat_id": "222"}

    def test_max_parallel_env_var(self, monkeypatch):
        """HERMES_CRON_MAX_PARALLEL=1 should restore serial behaviour."""
        monkeypatch.setenv("HERMES_CRON_MAX_PARALLEL", "1")
        call_times = []

        def mock_run_job(job):
            import time
            call_times.append(("start", job["id"], time.monotonic()))
            time.sleep(0.05)
            call_times.append(("end", job["id"], time.monotonic()))
            return (True, "output", "response", None)

        jobs = [
            {"id": "s1", "name": "s1", "deliver": "local"},
            {"id": "s2", "name": "s2", "deliver": "local"},
        ]

        with patch("cron.scheduler.get_due_jobs", return_value=jobs), \
             patch("cron.scheduler.advance_next_run"), \
             patch("cron.scheduler.run_job", side_effect=mock_run_job), \
             patch("cron.scheduler.save_job_output", return_value="/tmp/out.md"), \
             patch("cron.scheduler.mark_job_run"):
            from cron.scheduler import tick
            result = tick(verbose=False)

        assert result == 2
        # With max_workers=1, second job starts after first ends
        end_s1 = [t for action, jid, t in call_times if action == "end" and jid == "s1"][0]
        start_s2 = [t for action, jid, t in call_times if action == "start" and jid == "s2"][0]
        assert start_s2 >= end_s1, "Jobs ran concurrently despite max_parallel=1"


