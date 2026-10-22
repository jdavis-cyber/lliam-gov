"""A raising governance gate fails closed under strict posture.

predispatch_gate is contracted never to raise. When it does anyway, the
dispatch seams (sequential + concurrent executor, and the public
handle_function_call funnel) must not read the exception as "allow": under
strict posture the call is denied through the existing guardrail-block path
and recorded as a blocked outcome. Low-side profiles keep the non-blocking
convention. The inference seam likewise refuses to start a provider under
strict posture when the kill-switch cannot be imported or evaluated.
"""

from __future__ import annotations

import json
import sys
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import agent.governance_audit_hooks as gah
import agent.governance_gate_errors as gge
import model_tools
from agent.governance_audit import GovernanceLedger, iter_records
from lliam_cli.auth import AuthError
import lliam_cli.runtime_provider as rp
from run_agent import AIAgent


def _make_agent(*tool_names: str) -> AIAgent:
    tool_defs = [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": f"{name} tool",
                "parameters": {"type": "object", "properties": {}},
            },
        }
        for name in tool_names
    ]
    with (
        patch("run_agent.get_tool_definitions", return_value=tool_defs),
        patch("run_agent.check_toolset_requirements", return_value={}),
        patch("lliam_cli.config.load_config", return_value={}),
        patch("run_agent.OpenAI"),
    ):
        agent = AIAgent(
            api_key="test-key-1234567890",
            base_url="https://openrouter.ai/api/v1",
            max_iterations=10,
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
        )
    agent.client = MagicMock()
    agent._cached_system_prompt = "You are helpful."
    agent._use_prompt_caching = False
    agent.tool_delay = 0
    agent.compression_enabled = False
    agent.save_trajectories = False
    return agent


def _tool_call(name: str, args: dict, call_id: str | None = None):
    return SimpleNamespace(
        id=call_id or f"call_{uuid.uuid4().hex[:8]}",
        type="function",
        function=SimpleNamespace(name=name, arguments=json.dumps(args)),
    )


@pytest.fixture
def raising_gate(tmp_path, monkeypatch):
    """predispatch_gate raises; the PDP stays out of the way; outcomes land in a ledger."""
    led = GovernanceLedger(tmp_path / "agent-audit.log")
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: led)
    gah.set_operator_subject(None)
    monkeypatch.setattr("tools.tool_policy.pdp_gate", lambda *a, **k: None)
    monkeypatch.setattr(model_tools, "_READ_SEARCH_TOOLS", frozenset())

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated gate failure")

    monkeypatch.setattr(gah, "predispatch_gate", _boom)
    return led


def _blocked_outcomes(led):
    return [
        r for r in iter_records(led.path)
        if r["event"] == "policy.violation" and r["outcome"]["status"] == "blocked"
    ]


# ---- strict: deny ----------------------------------------------------------

def test_strict_sequential_gate_exception_denies_and_records(raising_gate, monkeypatch):
    monkeypatch.setattr(gge, "_is_strict", lambda: True)
    agent = _make_agent("write_file")
    tc = _tool_call("write_file", {"path": "x", "content": "y"}, "c-seq")
    messages = []

    with patch("run_agent.handle_function_call", return_value="SHOULD_NOT_RUN") as mock_hfc:
        agent._execute_tool_calls_sequential(
            SimpleNamespace(content="", tool_calls=[tc]), messages, "task-1",
        )

    mock_hfc.assert_not_called()
    assert [m["tool_call_id"] for m in messages] == ["c-seq"]
    assert "governance_gate_error" in messages[0]["content"]
    assert "SHOULD_NOT_RUN" not in messages[0]["content"]
    assert agent._tool_guardrail_halt_decision.code == "governance_gate_error"
    assert [r["action"] for r in _blocked_outcomes(raising_gate)] == ["tool.write_file"]


def test_strict_concurrent_gate_exception_denies_and_records(raising_gate, monkeypatch):
    monkeypatch.setattr(gge, "_is_strict", lambda: True)
    agent = _make_agent("web_search")
    calls = [
        _tool_call("web_search", {"query": "a"}, "c-a"),
        _tool_call("web_search", {"query": "b"}, "c-b"),
    ]
    messages = []
    executed = []

    def fake_handle(name, args, task_id, **kwargs):
        executed.append(kwargs.get("tool_call_id"))
        return json.dumps({"ok": True})

    with patch("run_agent.handle_function_call", side_effect=fake_handle):
        agent._execute_tool_calls_concurrent(
            SimpleNamespace(content="", tool_calls=calls), messages, "task-1",
        )

    assert executed == []
    assert [m["tool_call_id"] for m in messages] == ["c-a", "c-b"]
    assert all("governance_gate_error" in m["content"] for m in messages)
    assert len(_blocked_outcomes(raising_gate)) == 2


def test_strict_direct_funnel_gate_exception_denies_and_records(raising_gate, monkeypatch):
    monkeypatch.setattr(gge, "_is_strict", lambda: True)
    dispatched = {"ran": False}
    from tools.registry import registry

    def _dispatch(name, args, **kw):
        dispatched["ran"] = True
        return '{"output": "should not run"}'

    monkeypatch.setattr(registry, "dispatch", _dispatch)
    out = model_tools.handle_function_call(
        "write_file", {"path": "x", "content": "y"}, task_id="t1",
    )

    assert dispatched["ran"] is False
    assert "fail-closed" in json.loads(out)["error"]
    assert [r["action"] for r in _blocked_outcomes(raising_gate)] == ["tool.write_file"]


# ---- low-side: non-blocking convention unchanged ---------------------------

def test_low_side_sequential_gate_exception_still_executes(raising_gate, monkeypatch):
    monkeypatch.setattr(gge, "_is_strict", lambda: False)
    agent = _make_agent("write_file")
    tc = _tool_call("write_file", {"path": "x", "content": "y"}, "c-low")
    messages = []

    with patch("run_agent.handle_function_call", return_value='{"ok": true}') as mock_hfc:
        agent._execute_tool_calls_sequential(
            SimpleNamespace(content="", tool_calls=[tc]), messages, "task-1",
        )

    mock_hfc.assert_called_once()
    assert "governance_gate_error" not in messages[0]["content"]
    assert _blocked_outcomes(raising_gate) == []


def test_low_side_concurrent_gate_exception_still_executes(raising_gate, monkeypatch):
    monkeypatch.setattr(gge, "_is_strict", lambda: False)
    agent = _make_agent("web_search")
    calls = [
        _tool_call("web_search", {"query": "a"}, "c-a"),
        _tool_call("web_search", {"query": "b"}, "c-b"),
    ]
    messages = []
    executed = []

    def fake_handle(name, args, task_id, **kwargs):
        executed.append(kwargs.get("tool_call_id"))
        return json.dumps({"ok": True})

    with patch("run_agent.handle_function_call", side_effect=fake_handle):
        agent._execute_tool_calls_concurrent(
            SimpleNamespace(content="", tool_calls=calls), messages, "task-1",
        )

    assert sorted(executed) == ["c-a", "c-b"]
    assert _blocked_outcomes(raising_gate) == []


def test_low_side_direct_funnel_gate_exception_still_executes(raising_gate, monkeypatch):
    monkeypatch.setattr(gge, "_is_strict", lambda: False)
    from tools.registry import registry
    monkeypatch.setattr(registry, "dispatch", lambda name, args, **kw: '{"output": "ok"}')

    out = model_tools.handle_function_call(
        "write_file", {"path": "x", "content": "y"}, task_id="t1",
    )

    assert json.loads(out) == {"output": "ok"}
    assert _blocked_outcomes(raising_gate) == []


def test_posture_resolution_failure_enforces(monkeypatch):
    def _cfg_boom(*a, **k):
        raise RuntimeError("config unreadable")

    monkeypatch.setattr("lliam_cli.config.load_config", _cfg_boom)
    decision = gge.gate_error_decision("write_file", "predispatch_gate", RuntimeError("x"))
    assert decision is not None
    assert decision.allows_execution is False


# ---- inference seam: kill-switch unavailable -------------------------------

def _no_killswitch_module(monkeypatch):
    import agent
    monkeypatch.delattr(agent, "killswitch", raising=False)
    monkeypatch.setitem(sys.modules, "agent.killswitch", None)  # import -> ImportError


def _killswitch_unreadable(monkeypatch):
    import agent.killswitch as ks

    def _boom():
        raise OSError("killswitch.state unreadable")

    monkeypatch.setattr(ks, "assert_inference_live", _boom)


@pytest.mark.parametrize("break_killswitch", [_no_killswitch_module, _killswitch_unreadable])
def test_strict_killswitch_unavailable_refuses_provider(monkeypatch, break_killswitch):
    monkeypatch.setattr(rp, "_is_strict", lambda: True)
    resolved = {"called": False}

    def _unchecked(**kw):
        resolved["called"] = True
        return {"provider": "custom", "base_url": "http://127.0.0.1:1234/v1"}

    monkeypatch.setattr(rp, "_resolve_runtime_provider_unchecked", _unchecked)
    break_killswitch(monkeypatch)

    with pytest.raises(AuthError) as exc_info:
        rp.resolve_runtime_provider(requested="lmstudio")

    assert exc_info.value.code == "killswitch_unavailable"
    assert resolved["called"] is False


@pytest.mark.parametrize("break_killswitch", [_no_killswitch_module, _killswitch_unreadable])
def test_low_side_killswitch_unavailable_still_resolves(monkeypatch, break_killswitch):
    monkeypatch.setattr(rp, "_is_strict", lambda: False)
    expected = {"provider": "moa", "base_url": ""}
    monkeypatch.setattr(rp, "_resolve_runtime_provider_unchecked", lambda **kw: expected)
    break_killswitch(monkeypatch)

    assert rp.resolve_runtime_provider(requested="moa") is expected
