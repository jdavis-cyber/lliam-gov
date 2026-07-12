"""Tests for the P1.2 dispatch-chokepoint wiring (agent/governance_audit_hooks).

These exercise the hook surface directly against a REAL enabled ledger
(pinned to a tmp path), rather than driving the full AIAgent dispatch
loop: the wiring's contracts are (1) every dispatch/outcome emits exactly
one record, (2) a high-risk audit-write failure returns a blocking
decision, (3) read-only tools are never fail-closed, (4) the auth bridge
and outcome funnel never raise. An end-to-end dispatch-path test lives in
the P1.2 verification demo.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import agent.governance_audit as ga
import agent.governance_audit_hooks as gah
from agent.governance_audit import GovernanceLedger, iter_records


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    """A real, enabled ledger pinned to tmp — shared by the module surface."""
    path = tmp_path / "agent-audit.log"
    led = GovernanceLedger(path)
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: led)
    # Reset the operator-subject contextvar between tests.
    gah.set_operator_subject(None)
    return led


def _agent():
    return SimpleNamespace(
        provider="bedrock-govcloud",
        model="claude-x",
        session_id="sess-1",
        _current_turn_id="turn-1",
        _current_api_request_id="req-1",
    )


# ---- risk classification -------------------------------------------------

def test_read_only_tools_are_low_risk():
    for name in ("read_file", "search_files", "session_search", "skills_list"):
        assert gah.classify_risk(name) == frozenset()


def test_mutating_and_unknown_tools_are_gated():
    assert "mutating" in gah.classify_risk("write_file")
    assert "privileged" in gah.classify_risk("terminal")
    assert gah.classify_risk("browser_click") == gah._BROWSER_ACTION_RISK
    # Unknown / MCP tools default conservative (gated).
    assert gah.classify_risk("some_mcp_tool") == gah._DEFAULT_RISK


def test_vision_and_video_tools_are_external_egress():
    """LG-AU-09: vision/video analysis ships local media to an external
    provider — external egress, not a read-only local op. Must be gated
    (non-empty risk including 'egress') so an audit-write outage fails closed
    rather than letting data leave off-the-books."""
    for name in ("vision_analyze", "video_analyze"):
        risk = gah.classify_risk(name)
        assert "egress" in risk, name
        assert name not in gah._READ_ONLY_TOOLS, name


# ---- provenance: middleware trace on dispatch + outcome (LG-MC-03) --------

def test_predispatch_records_middleware_trace(ledger):
    gah.predispatch_gate(
        _agent(), function_name="write_file", function_args={"path": "x"},
        tool_call_id="tc", effective_task_id="op1",
        middleware_trace=[{"name": "redactor"}, {"name": "policy_mw"}],
    )
    rec = next(iter_records(ledger.path))
    assert rec["trace"]["middleware"] == ["redactor", "policy_mw"]


def test_record_outcome_records_middleware_trace(ledger):
    gah.record_outcome(
        function_name="write_file", function_args={"path": "x"},
        status="ok", task_id="op1",
        middleware_trace=[{"name": "redactor"}],
    )
    rec = next(iter_records(ledger.path))
    assert rec["trace"]["middleware"] == ["redactor"]


# ---- predispatch gate (LG-AU-02 / LG-AU-09) ------------------------------

def test_predispatch_records_and_allows(ledger):
    decision = gah.predispatch_gate(
        _agent(),
        function_name="write_file",
        function_args={"path": "x.txt", "content": "hi"},
        tool_call_id="tc1",
        effective_task_id="task9",
    )
    assert decision is None  # allowed to proceed
    recs = list(iter_records(ledger.path))
    assert len(recs) == 1
    assert recs[0]["event"] == "tool.dispatch"
    assert recs[0]["action"] == "tool.write_file"
    assert recs[0]["correlation_id"] == "task-task9"
    assert recs[0]["actor"]["model"]["provider"] == "bedrock-govcloud"


def test_predispatch_blocks_high_risk_on_write_failure(tmp_path, monkeypatch):
    class _Boom:
        fail_closed = True
        fail_closed_scope = ga.DEFAULT_FAIL_CLOSED_SCOPE

        def emit(self, *a, **k):
            raise ga.AuditWriteError("simulated")

    monkeypatch.setattr(gah, "_enabled_ledger", lambda: _Boom())
    decision = gah.predispatch_gate(
        _agent(), function_name="terminal",
        function_args={"command": "rm x"}, tool_call_id="t", effective_task_id="",
    )
    assert decision is not None
    assert decision.action == "halt"
    assert not decision.allows_execution
    assert "fail-closed" in decision.message


def test_predispatch_readonly_not_blocked_on_write_failure(tmp_path, monkeypatch):
    class _Boom:
        fail_closed = True
        fail_closed_scope = ga.DEFAULT_FAIL_CLOSED_SCOPE

        def emit(self, *a, **k):
            # low-risk path: real ledger warns + returns None, never raises
            return None

    monkeypatch.setattr(gah, "_enabled_ledger", lambda: _Boom())
    decision = gah.predispatch_gate(
        _agent(), function_name="read_file",
        function_args={"path": "x"}, tool_call_id="t", effective_task_id="",
    )
    assert decision is None


def test_predispatch_noop_when_ledger_disabled(monkeypatch):
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: None)
    assert gah.predispatch_gate(
        _agent(), function_name="write_file", function_args={},
    ) is None


# ---- terminal outcome (LG-AU-02) -----------------------------------------

def test_record_outcome_success_is_tool_result(ledger):
    gah.record_outcome(
        function_name="read_file", function_args={"path": "x"},
        status="ok", task_id="t1",
    )
    rec = next(iter_records(ledger.path))
    assert rec["event"] == "tool.result"
    assert rec["outcome"]["status"] == "success"


def test_record_outcome_blocked_is_policy_violation(ledger):
    gah.record_outcome(
        function_name="terminal", function_args={"command": "x"},
        status="blocked", error_type="guardrail_block",
        error_message="HARDLINE pattern",
    )
    rec = next(iter_records(ledger.path))
    assert rec["event"] == "policy.violation"
    assert rec["decision"] == "deny"
    assert rec["severity"] == "warning"


def test_record_outcome_never_raises(monkeypatch):
    class _Boom:
        def emit(self, *a, **k):
            raise RuntimeError("kaboom")

    monkeypatch.setattr(gah, "_enabled_ledger", lambda: _Boom())
    # Must swallow — a post-facto record failure cannot break the caller.
    gah.record_outcome(function_name="x", function_args={}, status="ok")


# ---- operator subject (LG-AU-10) -----------------------------------------

def test_operator_subject_binds_into_records(ledger):
    gah.set_operator_subject("jdavis@agency.mil", auth="oauth/idp-mfa")
    gah.predispatch_gate(
        _agent(), function_name="write_file", function_args={"path": "x"},
    )
    rec = next(iter_records(ledger.path))
    assert rec["subject"]["principal"] == "jdavis@agency.mil"
    assert rec["subject"]["auth"] == "oauth/idp-mfa"


# ---- dashboard-auth bridge (LG-AU-10) ------------------------------------

def test_forward_auth_event_records_lifecycle(ledger):
    gah.forward_auth_event(
        "login_success", {"principal": "op@agency.mil", "session_id": "s7"}
    )
    rec = next(iter_records(ledger.path))
    assert rec["event"] == "agent.lifecycle"
    assert rec["action"] == "dashboard_auth.login_success"
    assert rec["subject"]["principal"] == "op@agency.mil"
    assert rec["outcome"]["status"] == "success"


def test_forward_auth_failure_marked_failure(ledger):
    gah.forward_auth_event("login_failure", {"principal": "op@agency.mil"})
    rec = next(iter_records(ledger.path))
    assert rec["outcome"]["status"] == "failure"


def test_forward_auth_event_never_raises(monkeypatch):
    class _Boom:
        def emit(self, *a, **k):
            raise RuntimeError("kaboom")

    monkeypatch.setattr(gah, "_enabled_ledger", lambda: _Boom())
    gah.forward_auth_event("login_success", {"principal": "x"})  # must not raise


def test_full_operation_shares_correlation_id(ledger):
    """A dispatch and its outcome under one task id share a correlation id
    so an operation is reconstructable end-to-end (LG-AU-10)."""
    gah.predispatch_gate(
        _agent(), function_name="write_file",
        function_args={"path": "x"}, tool_call_id="tc", effective_task_id="op1",
    )
    gah.record_outcome(
        function_name="write_file", function_args={"path": "x"},
        status="ok", task_id="op1", tool_call_id="tc",
    )
    recs = list(iter_records(ledger.path))
    assert len(recs) == 2
    assert recs[0]["correlation_id"] == recs[1]["correlation_id"] == "task-op1"
