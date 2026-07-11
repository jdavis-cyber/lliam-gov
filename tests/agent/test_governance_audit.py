"""Tests for the Lliam-GOV governance audit ledger (P1.1, LG-AU-01..07/09).

The chain checks here deliberately recompute every hash with a test-local
sha256 (independent of the module's own hashing helpers) so they stand as
an INDEPENDENT verifier of the persisted bytes — the P1.1 evidence that
the chain is valid is not the module grading its own homework.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import agent.governance_audit as ga
from agent.governance_audit import (
    AUDITABLE_EVENTS,
    AuditWriteError,
    GENESIS_PREV_HASH,
    GovernanceLedger,
    iter_records,
)


def _ledger(tmp_path: Path, **kw) -> GovernanceLedger:
    return GovernanceLedger(tmp_path / "agent-audit.log", **kw)


def _independent_hash(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "record_hash"}
    canon = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def test_chain_is_valid_and_monotonic(tmp_path):
    led = _ledger(tmp_path)
    led.emit("session.start", action="agent.run", source_module="tests")
    led.emit(
        "tool.dispatch",
        action="terminal.exec",
        parameters={"command": "ls -la"},
        source_module="tests",
    )
    led.emit(
        "policy.violation",
        action="file.write",
        decision="deny",
        outcome={"status": "blocked", "class": "write_denied"},
        source_module="tests",
    )

    records = list(iter_records(led.path))
    assert len(records) == 3
    assert records[0]["prev_hash"] == GENESIS_PREV_HASH
    for i, rec in enumerate(records):
        assert rec["seq"] == i + 1
        assert rec["record_hash"] == _independent_hash(rec)
        if i > 0:
            assert rec["prev_hash"] == records[i - 1]["record_hash"]


def test_tamper_breaks_chain(tmp_path):
    led = _ledger(tmp_path)
    for n in range(3):
        led.emit("tool.result", action=f"op-{n}", source_module="tests")
    lines = led.path.read_text(encoding="utf-8").splitlines()
    doctored = json.loads(lines[1])
    doctored["action"] = "op-FORGED"
    lines[1] = json.dumps(doctored, sort_keys=True, separators=(",", ":"))
    led.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    records = list(iter_records(led.path))
    # The edited record no longer matches its own sealed hash.
    assert records[1]["record_hash"] != _independent_hash(records[1])
    # Downstream linkage still points at the pre-tamper hash, so the edit
    # is detectable from record 2 onward — nothing re-seals silently.
    assert records[2]["prev_hash"] == records[1]["record_hash"]


def test_chain_continues_across_restart(tmp_path):
    path = tmp_path / "agent-audit.log"
    GovernanceLedger(path).emit(
        "session.start", action="agent.run", source_module="tests"
    )
    # New instance over the same file — must recover the tail, not fork.
    GovernanceLedger(path).emit(
        "session.stop", action="agent.run", source_module="tests"
    )
    records = list(iter_records(path))
    assert records[1]["seq"] == 2
    assert records[1]["prev_hash"] == records[0]["record_hash"]


def test_redaction_on_write_masks_secret_and_keeps_content_hash(tmp_path):
    led = _ledger(tmp_path)
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    led.emit(
        "tool.dispatch",
        action="terminal.exec",
        parameters={"command": f"curl -H 'Authorization: token {secret}'"},
        source_module="tests",
        risk_scope={"egress"},
    )
    raw = led.path.read_text(encoding="utf-8")
    assert secret not in raw, "raw secret must never touch disk (LG-AU-05)"
    rec = next(iter_records(led.path))
    assert rec["parameters"]["content_hash"].startswith("sha256:")
    # The sealed hash covers the REDACTED record — chain remains valid.
    assert rec["record_hash"] == _independent_hash(rec)


def test_benign_parameters_pass_through_without_content_hash(tmp_path):
    led = _ledger(tmp_path)
    led.emit(
        "tool.dispatch",
        action="file.read",
        parameters={"path": "notes/todo.md"},
        source_module="tests",
    )
    rec = next(iter_records(led.path))
    assert rec["parameters"] == {"path": "notes/todo.md"}


def test_fail_closed_blocks_high_risk_on_write_failure(tmp_path, monkeypatch):
    led = _ledger(tmp_path)

    def _boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr("builtins.open", _boom)
    with pytest.raises(AuditWriteError):
        led.emit(
            "tool.dispatch",
            action="file.write",
            risk_scope={"mutating"},
            source_module="tests",
        )


def test_write_failure_on_low_risk_warns_but_does_not_block(
    tmp_path, monkeypatch, caplog
):
    led = _ledger(tmp_path)
    monkeypatch.setattr(
        "builtins.open", lambda *a, **k: (_ for _ in ()).throw(OSError("nope"))
    )
    with caplog.at_level("WARNING"):
        result = led.emit(
            "tool.result", action="file.read", source_module="tests"
        )
    assert result is None
    assert any("audit append failed" in m for m in caplog.messages)


def test_corrupt_tail_refuses_gated_append(tmp_path):
    path = tmp_path / "agent-audit.log"
    path.write_text("{not json at all\n", encoding="utf-8")
    led = GovernanceLedger(path)
    with pytest.raises(AuditWriteError):
        led.emit(
            "tool.dispatch",
            action="terminal.exec",
            risk_scope={"privileged"},
            source_module="tests",
        )


def test_record_schema_required_fields(tmp_path):
    led = _ledger(tmp_path)
    rec = led.emit(
        "approval.decision",
        action="terminal.exec",
        decision="deny",
        approver={"principal": "operator@example.mil"},
        subject={"principal": "operator@example.mil"},
        resource={"type": "command", "value": "systemctl restart foo"},
        source_module="tools/approval.py:check_all_command_guards",
    )
    for field in (
        "schema", "seq", "event_id", "correlation_id", "ts", "event",
        "severity", "actor", "subject", "action", "decision", "outcome",
        "source_module", "prev_hash", "record_hash",
    ):
        assert field in rec, f"missing required field {field}"
    assert rec["schema"] == "lg-au/1"
    assert rec["severity"] == "notice"  # taxonomy default for approvals
    assert rec["ts"].endswith("+00:00") or rec["ts"].endswith("Z")
    assert "." in rec["ts"], "UTC timestamp must carry sub-second precision"


def test_unknown_event_and_decision_rejected(tmp_path):
    led = _ledger(tmp_path)
    with pytest.raises(ValueError):
        led.emit("made.up", action="x", source_module="tests")
    with pytest.raises(ValueError):
        led.emit(
            "tool.dispatch", action="x", decision="maybe",
            source_module="tests",
        )


def test_taxonomy_matches_gov_overlay(tmp_path):
    """The module constant and cli-config.gov.yaml must list the same events."""
    import yaml

    overlay = Path(__file__).resolve().parents[2] / "cli-config.gov.yaml"
    data = yaml.safe_load(overlay.read_text(encoding="utf-8"))
    assert set(data["audit"]["events"]) == set(AUDITABLE_EVENTS)


def test_module_emit_is_noop_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(ga, "_audit_config", lambda: {})
    monkeypatch.setattr(ga, "_ledger_singleton", None)
    assert ga.emit("tool.dispatch", action="x", source_module="tests") is None


def test_ledger_path_is_write_denied(tmp_path, monkeypatch):
    """LG-AU-07: the agent's own file tools cannot reach the ledger."""
    import agent.file_safety as fs

    monkeypatch.setattr(fs, "_lliam_home_path", lambda: tmp_path)
    monkeypatch.setattr(fs, "_lliam_root_path", lambda: tmp_path)
    assert fs.is_write_denied(str(tmp_path / "logs" / "agent-audit.log"))
    assert fs.is_write_denied(str(tmp_path / "logs"))
    assert not fs.is_write_denied(str(tmp_path / "workspace" / "notes.md"))
