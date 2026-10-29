"""AI-1172: run_job marks cron context-locally, not in the process env.

The gateway runs the cron scheduler in-process. A process-wide cron env flag
would make every later live gateway turn look like cron to tools.approval.
"""

import os
from unittest.mock import MagicMock, patch

import tools.approval as approval_module
from cron.scheduler import run_job


def test_run_job_marks_cron_only_for_the_job(tmp_path, monkeypatch):
    monkeypatch.delenv("LLIAM_CRON_SESSION", raising=False)
    seen = {}

    def _run_conversation(prompt):
        seen["marker"] = approval_module._is_cron_session()
        seen["env"] = os.environ.get("LLIAM_CRON_SESSION")
        return {"final_response": "ok"}

    with patch("cron.scheduler._lliam_home", tmp_path), \
         patch("cron.scheduler._resolve_origin", return_value=None), \
         patch("dotenv.load_dotenv"), \
         patch("lliam_state.SessionDB", return_value=MagicMock()), \
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
        mock_agent.run_conversation.side_effect = _run_conversation
        mock_agent_cls.return_value = mock_agent

        success, _output, _final, error = run_job(
            {"id": "marker-job", "name": "marker", "prompt": "hello"}
        )

    assert success is True, error
    assert seen["marker"] is True
    assert seen["env"] is None
    assert "LLIAM_CRON_SESSION" not in os.environ
    assert approval_module._is_cron_session() is False
