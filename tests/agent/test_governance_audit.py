"""Tests for the Lliam-GOV governance audit ledger (P1.1, LG-AU-01..07/09).

The chain checks here deliberately recompute every hash with a test-local
sha256 (independent of the module's own hashing helpers) so they stand as
an INDEPENDENT verifier of the persisted bytes — the P1.1 evidence that
the chain is valid is not the module grading its own homework.

Post-review hardening coverage (PR #94 adversarial review): cross-process
interleaved writers, oversized tail records, torn-write repair,
non-JSON-native field values, sticky-on disablement, case-variant
write-deny bypass, ledger-path containment.
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


def _assert_chain_valid(records: list[dict]) -> None:
    prev = GENESIS_PREV_HASH
    for i, rec in enumerate(records):
        assert rec["seq"] == i + 1, f"seq gap at index {i}"
        assert rec["prev_hash"] == prev, f"chain break at seq {rec['seq']}"
        assert rec["record_hash"] == _independent_hash(rec)
        prev = rec["record_hash"]


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
    _assert_chain_valid(records)


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


def test_tampered_tail_refuses_gated_append(tmp_path):
    """A forged-but-parseable LAST record must not become the chain head."""
    led = _ledger(tmp_path)
    led.emit("tool.result", action="op", source_module="tests")
    lines = led.path.read_text(encoding="utf-8").splitlines()
    doctored = json.loads(lines[-1])
    doctored["action"] = "op-FORGED"  # seal now stale
    lines[-1] = json.dumps(doctored, sort_keys=True, separators=(",", ":"))
    led.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditWriteError, match="seal mismatch"):
        _ledger(tmp_path).emit(
            "tool.dispatch", action="x", risk_scope={"mutating"},
            source_module="tests",
        )


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


def test_two_live_instances_interleave_one_chain(tmp_path):
    """Two writer instances (stand-in for two processes) must extend ONE
    linear chain — the tail is re-read under the file lock per append,
    never trusted from instance memory."""
    path = tmp_path / "agent-audit.log"
    a, b = GovernanceLedger(path), GovernanceLedger(path)
    for n in range(4):
        (a if n % 2 == 0 else b).emit(
            "tool.result", action=f"op-{n}", source_module="tests"
        )
    records = list(iter_records(path))
    assert len(records) == 4
    _assert_chain_valid(records)


def test_concurrent_processes_extend_one_chain(tmp_path):
    """The review's P1 scenario: multiple OS processes appending to one
    ledger concurrently must produce a single valid chain — no duplicate
    seq, no stale prev_hash (exclusive file lock + tail re-read)."""
    import subprocess
    import sys as _sys

    path = tmp_path / "agent-audit.log"
    repo = str(Path(__file__).resolve().parents[2])
    script = (
        "import sys; sys.path.insert(0, {repo!r})\n"
        "from pathlib import Path\n"
        "from agent.governance_audit import GovernanceLedger\n"
        "led = GovernanceLedger(Path({path!r}))\n"
        "for n in range(10):\n"
        "    led.emit('tool.result', action=f'w{{n}}', source_module='mp')\n"
    ).format(repo=repo, path=str(path))
    procs = [
        subprocess.Popen([_sys.executable, "-c", script], cwd=repo)
        for _ in range(4)
    ]
    for p in procs:
        assert p.wait(timeout=120) == 0
    records = list(iter_records(path))
    assert len(records) == 40
    _assert_chain_valid(records)


def test_tail_recovery_on_record_larger_than_initial_window(tmp_path):
    """A last record larger than the 64 KB initial window is valid, not
    'corrupt' — the recovery window grows until the line is captured."""
    led = _ledger(tmp_path)
    led.emit(
        "tool.dispatch",
        action="big",
        parameters={"blob": "x" * 200_000},
        source_module="tests",
    )
    # Fresh instance must recover the oversized tail and continue.
    _ledger(tmp_path).emit("tool.result", action="after", source_module="tests")
    records = list(iter_records(led.path))
    assert len(records) == 2
    _assert_chain_valid(records)


def test_torn_trailing_fragment_is_repaired_and_recorded(tmp_path):
    """A crashed writer's unterminated fragment is truncated (it was never
    a sealed record) and the repair is itself a security.error record."""
    led = _ledger(tmp_path)
    led.emit("tool.result", action="op-0", source_module="tests")
    with open(led.path, "ab") as f:
        f.write(b'{"partial": "torn wri')  # no newline — torn write
    led.emit("tool.result", action="op-1", source_module="tests")
    records = list(iter_records(led.path))
    assert [r["event"] for r in records] == [
        "tool.result", "security.error", "tool.result",
    ]
    assert records[1]["action"] == "ledger.torn_write_repair"
    assert records[1]["outcome"]["error"] == (
        "invalid unterminated trailing fragment truncated (crashed writer); "
        "no sealed record removed"
    )
    _assert_chain_valid(records)


def test_valid_unterminated_tail_survives_append_and_is_recorded(tmp_path):
    """A complete sealed record missing only its trailing LF is evidence,
    not a partial fragment: repair the terminator and preserve the record."""
    led = _ledger(tmp_path)
    led.emit("tool.result", action="op-0", source_module="tests")
    led.path.write_bytes(led.path.read_bytes().removesuffix(b"\n"))

    led.emit("tool.result", action="op-1", source_module="tests")

    records = list(iter_records(led.path))
    assert [r["action"] for r in records] == [
        "op-0", "ledger.torn_write_repair", "op-1",
    ]
    assert records[1]["outcome"]["error"] == (
        "valid sealed trailing record was missing its LF terminator; "
        "terminator appended"
    )
    _assert_chain_valid(records)


@pytest.mark.parametrize("invalid_field", ["missing_seq", "schema", "prev_hash"])
def test_self_sealed_non_record_tail_is_truncated(tmp_path, invalid_field):
    """A self-hashed JSON object is not evidence unless its sequence,
    schema, and prior-hash linkage have usable ledger-record shape."""
    led = _ledger(tmp_path)
    first = led.emit("tool.result", action="op-0", source_module="tests")
    fragment = {
        "schema": ga.SCHEMA_VERSION,
        "seq": 2,
        "prev_hash": first["record_hash"],
        "event": "tool.result",
    }
    if invalid_field == "missing_seq":
        del fragment["seq"]
    elif invalid_field == "schema":
        fragment["schema"] = "not-lg-au"
    else:
        fragment["prev_hash"] = "not-a-sha256"
    fragment["record_hash"] = _independent_hash(fragment)
    with open(led.path, "ab") as f:
        f.write(json.dumps(
            fragment, sort_keys=True, separators=(",", ":")
        ).encode("utf-8"))

    rec = led.emit(
        "tool.dispatch",
        action="file.write",
        risk_scope={"mutating"},
        source_module="tests",
    )

    assert rec is not None
    records = list(iter_records(led.path))
    assert [r["action"] for r in records] == [
        "op-0", "ledger.torn_write_repair", "file.write",
    ]
    assert records[1]["outcome"]["error"].startswith(
        "invalid unterminated trailing fragment truncated"
    )
    _assert_chain_valid(records)


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


def test_redaction_covers_all_freeform_fields(tmp_path):
    """LG-AU-05 applies to resource/subject/actor/approver/action/trace,
    not only parameters and outcome (review finding)."""
    led = _ledger(tmp_path)
    secret = "ghp_" + "Q9w8E7r6T5y4U3i2O1p0A9s8D7f6G5h4J3k2"
    led.emit(
        "tool.dispatch",
        action=f"terminal.exec token={secret}",
        resource={"type": "url", "value": f"https://x.test/?key={secret}"},
        subject={"principal": f"svc {secret}"},
        approver={"principal": f"approver {secret}"},
        trace={"note": secret},
        actor={"type": "npe", "hint": secret},
        source_module="tests",
    )
    raw = led.path.read_text(encoding="utf-8")
    assert secret not in raw


def test_secret_in_dict_key_position_is_redacted(tmp_path):
    led = _ledger(tmp_path)
    secret = "ghp_" + "Z1x2C3v4B5n6M7a8S9d0F1g2H3j4K5l6P7o8"
    led.emit(
        "tool.dispatch",
        action="x",
        parameters={secret: "value"},
        source_module="tests",
    )
    assert secret not in led.path.read_text(encoding="utf-8")


def test_non_json_native_values_do_not_break_the_contract(tmp_path):
    """bytes/datetime/Path/set/tuple in fields are data, not programming
    errors — they must seal fine, and never escape as raw TypeError."""
    import datetime as dt

    led = _ledger(tmp_path)
    rec = led.emit(
        "tool.dispatch",
        action="x",
        parameters={
            "raw": b"bytes-value",
            "when": dt.datetime(2026, 7, 11, tzinfo=dt.timezone.utc),
            "path": Path("/tmp/x"),
            "opts": {"a", "b"},
            "pair": (1, 2),
        },
        risk_scope={"mutating"},
        source_module="tests",
    )
    assert rec is not None
    records = list(iter_records(led.path))
    _assert_chain_valid(records)


def test_plain_tuple_params_get_no_spurious_content_hash(tmp_path):
    """jsonify runs BEFORE the redaction-equality check, so a tuple that
    redacts to nothing must not claim 'a value was masked here'."""
    led = _ledger(tmp_path)
    led.emit(
        "tool.dispatch", action="x",
        parameters={"pair": (1, 2)}, source_module="tests",
    )
    rec = next(iter_records(led.path))
    assert "content_hash" not in rec["parameters"]


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
    monkeypatch.setattr(ga, "_audit_config_or_none", lambda: {})
    monkeypatch.setattr(ga, "_ledger_singleton", None)
    monkeypatch.setattr(ga, "_was_enabled", False)
    assert ga.emit("tool.dispatch", action="x", source_module="tests") is None


def test_first_use_config_failure_is_fail_closed(monkeypatch):
    monkeypatch.setattr(ga, "_audit_config_or_none", lambda: None)
    monkeypatch.setattr(ga, "_ledger_singleton", None)
    monkeypatch.setattr(ga, "_was_enabled", False)

    ledger = ga.get_ledger()
    assert ledger is not None
    with pytest.raises(AuditWriteError, match="config load failure"):
        ga.emit(
            "tool.dispatch",
            action="file.write",
            risk_scope={"mutating"},
            source_module="tests",
        )


def test_mid_session_disable_is_sticky_on(tmp_path, monkeypatch):
    """Once enabled in a process, a config flip to disabled must not
    silently kill auditing — the flip is recorded and emits continue."""
    path = tmp_path / "agent-audit.log"
    cfg: dict = {"ledger_enabled": True, "ledger_path": str(path)}
    monkeypatch.setattr(ga, "_audit_config_or_none", lambda: dict(cfg))
    monkeypatch.setattr(ga, "_ledger_singleton", None)
    monkeypatch.setattr(ga, "_was_enabled", False)
    monkeypatch.setattr(ga, "_disable_flip_logged", False)
    # Containment refusal will redirect a tmp path outside <home>/logs, so
    # pin the resolver for this test.
    monkeypatch.setattr(ga, "resolve_ledger_path", lambda c=None: path)

    assert ga.emit("session.start", action="run", source_module="tests")
    cfg["ledger_enabled"] = False  # adversarial mid-session flip
    rec = ga.emit("tool.dispatch", action="x", risk_scope={"mutating"},
                  source_module="tests")
    assert rec is not None, "sticky-on: auditing must continue"
    events = [r["event"] for r in iter_records(path)]
    assert "security.error" in events, "disable attempt must be recorded"


def test_configured_ledger_path_outside_home_logs_is_refused(tmp_path, monkeypatch):
    """audit.ledger_path outside <home>/logs would leave the LG-AU-07
    denylist — the resolver must refuse it and use the default."""
    import lliam_constants

    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    escape = tmp_path / "elsewhere" / "ledger.log"
    resolved = ga.resolve_ledger_path({"ledger_path": str(escape)})
    assert resolved == lliam_constants.get_lliam_home() / "logs" / "agent-audit.log"
    inside = ga.resolve_ledger_path({"ledger_path": "$HERMES_HOME/logs/x.log"})
    assert inside.name == "x.log"


def test_verify_chain_passes_on_good_ledger(tmp_path):
    led = _ledger(tmp_path)
    for n in range(5):
        led.emit("tool.result", action=f"op-{n}", source_module="tests")
    result = ga.verify_chain(led.path)
    assert result.ok
    assert result.checked == 5
    assert result.total == 5
    assert result.break_seq is None


def test_verify_chain_empty_and_missing_are_pass(tmp_path):
    missing = ga.verify_chain(tmp_path / "nope.log")
    assert missing.ok and missing.total == 0
    (tmp_path / "empty.log").write_text("", encoding="utf-8")
    empty = ga.verify_chain(tmp_path / "empty.log")
    assert empty.ok and empty.total == 0


def test_verify_chain_detects_inplace_edit(tmp_path):
    led = _ledger(tmp_path)
    for n in range(3):
        led.emit("tool.result", action=f"op-{n}", source_module="tests")
    lines = led.path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["action"] = "op-FORGED"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    led.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = ga.verify_chain(led.path)
    assert not result.ok
    assert result.break_seq == 2
    assert "record_hash mismatch" in result.reason


def test_verify_chain_detects_deletion(tmp_path):
    led = _ledger(tmp_path)
    for n in range(4):
        led.emit("tool.result", action=f"op-{n}", source_module="tests")
    lines = led.path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # drop record seq=2 → seq 3's prev_hash now dangles
    led.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = ga.verify_chain(led.path)
    assert not result.ok
    # First anomaly is the seq gap (…1, 3…).
    assert result.break_seq == 3
    assert "seq" in result.reason


def test_verify_chain_detects_reorder(tmp_path):
    led = _ledger(tmp_path)
    for n in range(3):
        led.emit("tool.result", action=f"op-{n}", source_module="tests")
    lines = led.path.read_text(encoding="utf-8").splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    led.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = ga.verify_chain(led.path)
    assert not result.ok


def test_verify_chain_segment_after_anchor(tmp_path):
    led = _ledger(tmp_path)
    recs = [led.emit("tool.result", action=f"op-{n}", source_module="tests")
            for n in range(5)]
    # Verify only the segment after seq 3 — cheaper, same guarantee forward.
    result = ga.verify_chain(led.path, start_after_seq=3,
                             start_prev_hash=recs[2]["record_hash"])
    assert result.ok
    assert result.checked == 2  # seqs 4 and 5


def test_verify_chain_segment_rejects_forged_anchor(tmp_path):
    """Segment mode must not take the on-disk anchor on faith: a
    start_prev_hash that doesn't match the anchor's sealed hash is a break
    (P1.3 review — start_prev_hash was previously ignored)."""
    led = _ledger(tmp_path)
    recs = [led.emit("tool.result", action=f"op-{n}", source_module="tests")
            for n in range(5)]
    result = ga.verify_chain(led.path, start_after_seq=3,
                             start_prev_hash="deadbeef" * 8)
    assert not result.ok
    assert "anchor" in result.reason


def test_verify_chain_treats_garbage_line_as_break(tmp_path):
    """An unparseable line is a tamper signal, not a benign error — the
    verifier must return FAIL, never raise (P1.3 review, fail-open gap)."""
    led = _ledger(tmp_path)
    led.emit("tool.result", action="op", source_module="tests")
    with open(led.path, "a", encoding="utf-8") as f:
        f.write("{ this is not valid json at all\n")
    result = ga.verify_chain(led.path)  # must NOT raise
    assert not result.ok
    assert "unparseable" in result.reason


def test_ledger_path_is_write_denied(tmp_path, monkeypatch):
    """LG-AU-07: the agent's own file tools cannot reach the ledger."""
    import agent.file_safety as fs

    monkeypatch.setattr(fs, "_lliam_home_path", lambda: tmp_path)
    monkeypatch.setattr(fs, "_lliam_root_path", lambda: tmp_path)
    assert fs.is_write_denied(str(tmp_path / "logs" / "agent-audit.log"))
    assert fs.is_write_denied(str(tmp_path / "logs"))
    # Case-variant bypass (macOS APFS is case-insensitive): denied too.
    assert fs.is_write_denied(str(tmp_path / "Logs" / "agent-audit.log"))
    assert fs.is_write_denied(str(tmp_path / "LOGS" / "agent-audit.log"))
    assert not fs.is_write_denied(str(tmp_path / "workspace" / "notes.md"))
