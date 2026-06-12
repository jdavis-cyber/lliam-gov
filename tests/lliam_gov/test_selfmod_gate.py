"""Self-modification gate — LG-4.5 / AI-222.

WHY: ISO 42001 A.6.2.4 requires human oversight of system changes. These
tests pin the gate's core promise: gated behavior NEVER executes before
approval (the handler is not invoked, so rejection has nothing to clean
up), decisions require a principal and a note, and the whole lifecycle is
audited into the hash chain.
"""

import json

import pytest

from lliam_gov.security.selfmod_gate import (
    SELFMOD_GATE_ENV,
    NoteRequired,
    ProposalAlreadyDecided,
    ProposalNotFound,
    approve_proposal,
    list_proposals,
    propose,
    reject_proposal,
    selfmod_gate_enabled,
)


@pytest.fixture
def gated(monkeypatch, tmp_path):
    home = tmp_path / "lliam-home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv(SELFMOD_GATE_ENV, "1")
    monkeypatch.delenv("LLIAM_GOV_PRIVILEGED_USERS", raising=False)
    return home


def _audit_records(home):
    return [
        json.loads(line)
        for f in (home / "audit").glob("*.jsonl")
        for line in f.read_text().splitlines()
    ]


# ── lifecycle ───────────────────────────────────────────────────────────────


def test_gate_env_parsing(monkeypatch):
    monkeypatch.delenv(SELFMOD_GATE_ENV, raising=False)
    assert not selfmod_gate_enabled()
    monkeypatch.setenv(SELFMOD_GATE_ENV, "1")
    assert selfmod_gate_enabled()


def test_propose_stages_pending_and_audits(gated):
    pid = propose("tool:create_skill", "stage a skill", {"name": "x"})
    pending = list_proposals()
    assert [p.proposal_id for p in pending] == [pid]
    assert pending[0].status == "pending"
    assert pending[0].proposed_by
    events = [r["event_type"] for r in _audit_records(gated)]
    assert "selfmod_proposed" in events


def test_approve_requires_note(gated):
    pid = propose("tool:create_skill", "s", {})
    with pytest.raises(NoteRequired):
        approve_proposal(pid, "")
    with pytest.raises(NoteRequired):
        approve_proposal(pid, "   ")


def test_approve_records_principal_note_and_audits(gated):
    pid = propose("tool:create_skill", "s", {"k": "v"})
    p = approve_proposal(pid, "reviewed: safe, scoped to demo skill")
    assert p.status == "approved"
    assert p.decided_by and p.note.startswith("reviewed")
    assert "selfmod_approved" in [r["event_type"] for r in _audit_records(gated)]


def test_reject_keeps_payload_out_of_live_state(gated):
    pid = propose("tool:create_skill", "s", {"k": "v"})
    p = reject_proposal(pid, "not appropriate for governed profile")
    assert p.status == "rejected"
    assert list_proposals("pending") == []
    assert "selfmod_rejected" in [r["event_type"] for r in _audit_records(gated)]


def test_double_decision_refused(gated):
    pid = propose("t", "s", {})
    reject_proposal(pid, "no")
    with pytest.raises(ProposalAlreadyDecided):
        approve_proposal(pid, "changed my mind")


def test_unknown_and_traversal_ids_refused(gated):
    with pytest.raises(ProposalNotFound):
        approve_proposal("deadbeef0000", "x")
    with pytest.raises(ProposalNotFound):
        approve_proposal("../escape", "x")


# ── dispatch integration: gated tools never execute ─────────────────────────


def test_gated_dispatch_stages_instead_of_executing(gated):
    from model_tools import handle_function_call
    from tools.registry import registry

    executed = []

    registry.register(
        name="selfmod_probe_tool",
        toolset="skills",
        schema={"name": "selfmod_probe_tool", "parameters": {"type": "object", "properties": {}}},
        handler=lambda *a, **kw: executed.append(1) or "ran",
        check_fn=None,
        requires_env=None,
        is_async=False,
        description="probe",
        emoji="",
    )
    try:
        result = json.loads(
            handle_function_call("selfmod_probe_tool", {}, session_id="sm-test")
        )
        assert result.get("staged") is True
        assert executed == [], "handler must NOT run before approval"
        pid = result["proposal_id"]

        # Reject it; still nothing executed, nothing pending.
        reject_proposal(pid, "rejected in test")
        assert executed == []
        assert list_proposals("pending") == []
    finally:
        registry.deregister("selfmod_probe_tool")


def test_dispatch_unaffected_when_gate_off(gated, monkeypatch):
    monkeypatch.delenv(SELFMOD_GATE_ENV, raising=False)
    from model_tools import handle_function_call
    from tools.registry import registry

    registry.register(
        name="selfmod_probe_tool2",
        toolset="skills",
        schema={"name": "selfmod_probe_tool2", "parameters": {"type": "object", "properties": {}}},
        handler=lambda *a, **kw: "ran-directly",
        check_fn=None,
        requires_env=None,
        is_async=False,
        description="probe",
        emoji="",
    )
    try:
        result = handle_function_call("selfmod_probe_tool2", {}, session_id="sm-test")
        assert "ran-directly" in result
    finally:
        registry.deregister("selfmod_probe_tool2")
