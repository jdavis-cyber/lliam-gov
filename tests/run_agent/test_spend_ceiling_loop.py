"""security.spend_ceiling on the real model-call path (agent/conversation_loop.py).

Usage is accounted after each API response; the ceiling is checked before the
next call. Without approval the turn stops before the call is made.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from lliam_cli import model_cost_guard as mcg
from run_agent import AIAgent


def _tool_defs(*names):
    return [
        {"type": "function", "function": {"name": n, "description": n,
                                          "parameters": {"type": "object", "properties": {}}}}
        for n in names
    ]


def _response(content="", finish_reason="stop", tool_calls=None, tokens=0):
    msg = SimpleNamespace(content=content, tool_calls=tool_calls)
    resp = SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason=finish_reason)],
                           model="test/model")
    resp.usage = SimpleNamespace(prompt_tokens=tokens, completion_tokens=0, total_tokens=tokens)
    return resp


def _tool_call():
    return SimpleNamespace(id=f"call_{uuid.uuid4().hex[:8]}", type="function",
                           function=SimpleNamespace(name="web_search", arguments="{}"))


@pytest.fixture()
def agent(monkeypatch):
    mcg.reset_spend_state()
    cfg = mcg.load_spend_ceiling(
        {"security": {"spend_ceiling": {"enabled": True, "per_session_tokens": 100}}}
    )
    monkeypatch.setattr(mcg, "load_spend_ceiling", lambda config=None: cfg)
    with (
        patch("run_agent.get_tool_definitions", return_value=_tool_defs("web_search")),
        patch("run_agent.check_toolset_requirements", return_value={}),
        patch("run_agent.OpenAI"),
    ):
        a = AIAgent(api_key="test-key-1234567890", base_url="https://openrouter.ai/api/v1",
                    quiet_mode=True, skip_context_files=True, skip_memory=True)
    a.client = MagicMock()
    a._cached_system_prompt = "You are helpful."
    a._use_prompt_caching = False
    a.tool_delay = 0
    a.compression_enabled = False
    a.save_trajectories = False
    a._session_db = None
    yield a
    mcg.reset_spend_state()


def _run(agent):
    with (
        patch("run_agent.handle_function_call", return_value="result"),
        patch.object(agent, "_persist_session"),
        patch.object(agent, "_save_trajectory"),
        patch.object(agent, "_cleanup_task_resources"),
    ):
        return agent.run_conversation("search something")


def test_breach_without_approval_stops_before_next_call(agent, monkeypatch):
    monkeypatch.setattr(mcg, "request_spend_approval", lambda *a: (False, "no_approver"))
    agent.client.chat.completions.create.side_effect = [
        _response(finish_reason="tool_calls", tool_calls=[_tool_call()], tokens=150),
        _response(content="should not be reached", tokens=10),
    ]
    result = _run(agent)
    assert agent.client.chat.completions.create.call_count == 1
    assert result["failed"] is True
    assert result["completed"] is False
    assert "inference spend ceiling reached" in result["final_response"]
    assert result["api_calls"] == 1


def test_breach_with_approval_continues(agent, monkeypatch):
    asked = []
    monkeypatch.setattr(mcg, "request_spend_approval",
                        lambda a, summary, desc: asked.append(summary) or (True, "gateway"))
    agent.client.chat.completions.create.side_effect = [
        _response(finish_reason="tool_calls", tool_calls=[_tool_call()], tokens=150),
        _response(content="Done", tokens=10),
    ]
    result = _run(agent)
    assert agent.client.chat.completions.create.call_count == 2
    assert result["final_response"] == "Done"
    assert len(asked) == 1
