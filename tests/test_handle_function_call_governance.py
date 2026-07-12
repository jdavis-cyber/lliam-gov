"""Governance dispatch/outcome accountability at the model_tools funnel (P1.2).

handle_function_call is a PUBLIC dispatcher reached directly by nested code
execution and the OpenAI-compatible API server — paths that do NOT go through
the agent-aware executor gate. These tests assert the universal contract:
every executed call gets exactly one governance predispatch record and exactly
one terminal outcome, including registry-exception and early-return paths, and
the already-gated executor path is not double-recorded.
"""

from __future__ import annotations

import json

import pytest

import agent.governance_audit as ga
import agent.governance_audit_hooks as gah
import model_tools
from agent.governance_audit import GovernanceLedger, iter_records


@pytest.fixture
def gov_ledger(tmp_path, monkeypatch):
    path = tmp_path / "agent-audit.log"
    led = GovernanceLedger(path)
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: led)
    gah.set_operator_subject(None)
    # Avoid unrelated read-loop side effects.
    monkeypatch.setattr(model_tools, "_READ_SEARCH_TOOLS", frozenset())
    return led


def _stub_dispatch(monkeypatch, result='{"output": "ok"}'):
    from tools.registry import registry
    monkeypatch.setattr(registry, "dispatch", lambda name, args, **kw: result)


def _events(led):
    return [r["event"] for r in iter_records(led.path)]


def _actions(led):
    return [r.get("action") for r in iter_records(led.path)]


# ---- fix #1: predispatch gate for direct callers -------------------------

def test_direct_call_emits_predispatch_and_outcome(gov_ledger, monkeypatch):
    _stub_dispatch(monkeypatch)
    model_tools.handle_function_call(
        "write_file", {"path": "x", "content": "y"}, task_id="t1",
    )
    evs = _events(gov_ledger)
    assert "tool.dispatch" in evs   # direct caller now gated
    assert "tool.result" in evs     # terminal outcome recorded
    assert evs.count("tool.dispatch") == 1


def test_executor_gated_path_skips_predispatch_but_records_outcome(gov_ledger, monkeypatch):
    _stub_dispatch(monkeypatch)
    model_tools.handle_function_call(
        "write_file", {"path": "x", "content": "y"}, task_id="t1",
        skip_governance_predispatch=True, skip_pre_tool_call_hook=True,
    )
    evs = _events(gov_ledger)
    assert "tool.dispatch" not in evs   # executor already emitted it
    assert "tool.result" in evs         # outcome still recorded


# ---- fix #2: registry exceptions record a terminal outcome ---------------

def test_registry_exception_records_error_outcome(gov_ledger, monkeypatch):
    from tools.registry import registry

    def _boom(name, args, **kw):
        raise RuntimeError("dispatch exploded")

    monkeypatch.setattr(registry, "dispatch", _boom)
    out = model_tools.handle_function_call(
        "write_file", {"path": "x", "content": "y"}, task_id="t1",
        skip_governance_predispatch=True, skip_pre_tool_call_hook=True,
    )
    assert "error" in json.loads(out)
    recs = [r for r in iter_records(gov_ledger.path)
            if r["event"] in ("tool.result", "policy.violation")]
    assert recs, "registry exception must still record a terminal outcome"
    assert recs[-1]["outcome"]["status"] == "failure"


# ---- fix #3: bridge / ACP early returns record outcomes ------------------

def test_tool_search_early_return_records_outcome(gov_ledger, monkeypatch):
    import tools.tool_search as ts
    monkeypatch.setattr(ts, "is_bridge_tool", lambda name: name == ts.TOOL_SEARCH_NAME)
    monkeypatch.setattr(ts, "dispatch_tool_search",
                        lambda args, current_tool_defs=None: '{"results": []}')
    monkeypatch.setattr(model_tools, "get_tool_definitions", lambda **k: [])
    model_tools.handle_function_call(ts.TOOL_SEARCH_NAME, {"query": "x"}, task_id="t1")
    assert f"tool.{ts.TOOL_SEARCH_NAME}" in _actions(gov_ledger)


def test_acp_edit_approval_block_records_outcome(gov_ledger, monkeypatch):
    _stub_dispatch(monkeypatch)
    monkeypatch.setattr(
        "acp_adapter.edit_approval.maybe_require_edit_approval",
        lambda name, args: json.dumps({"error": "edit approval denied"}),
    )
    out = model_tools.handle_function_call(
        "write_file", {"path": "x", "content": "y"}, task_id="t1",
        skip_governance_predispatch=True, skip_pre_tool_call_hook=True,
    )
    assert "edit approval denied" in out
    recs = [r for r in iter_records(gov_ledger.path)
            if r["event"] in ("tool.result", "policy.violation")]
    assert recs, "an ACP edit-approval block must record a terminal outcome"
    assert recs[-1]["outcome"]["status"] == "blocked"


# ---- fix #1 fail-closed: high-risk audit-write failure blocks -------------

def test_predispatch_fail_closed_blocks_direct_call(monkeypatch):
    class _Boom:
        def emit(self, *a, **k):
            raise ga.AuditWriteError("simulated audit outage")

    monkeypatch.setattr(gah, "_enabled_ledger", lambda: _Boom())
    monkeypatch.setattr(model_tools, "_READ_SEARCH_TOOLS", frozenset())
    dispatched = {"ran": False}
    from tools.registry import registry

    def _dispatch(name, args, **kw):
        dispatched["ran"] = True
        return '{"output": "should not run"}'

    monkeypatch.setattr(registry, "dispatch", _dispatch)
    out = model_tools.handle_function_call(
        "terminal", {"command": "rm -rf x"}, task_id="t1",
    )
    assert "error" in json.loads(out)
    assert dispatched["ran"] is False  # high-risk call must NOT execute
