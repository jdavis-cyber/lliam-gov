"""Tests for ``lliam_gov.security.audit_logger``.

Covers the AI-210 / Rev. 3 §5.2 core: JSONL audit records, append-only
monthly files, hash-chain verification, deterministic params hashing,
and fail-closed open behavior.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lliam_gov.security.audit_logger import (
    AuditChainError,
    AuditLogger,
    AuditLoggerOpenError,
    canonical_json,
    params_hash,
    verify_audit_chain,
)


JANUARY = datetime(2026, 1, 5, 12, 0, 0, tzinfo=timezone.utc)
FEBRUARY = datetime(2026, 2, 1, 0, 0, 1, tzinfo=timezone.utc)


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_log_event_builds_hash_chain_and_verifies(tmp_path: Path) -> None:
    logger = AuditLogger(audit_dir=tmp_path, session_id="s1", principal="jerome")

    first = logger.log_event(
        event_type="tool_call_start",
        tool_name="terminal",
        tool_call_id="call-1",
        params={"cmd": "date", "nested": {"b": 2, "a": 1}},
        model_id="gpt-5",
        at=JANUARY,
    )
    second = logger.log_event(
        event_type="tool_call_end",
        tool_name="terminal",
        tool_call_id="call-1",
        duration_ms=7,
        at=JANUARY,
    )

    path = tmp_path / "tool-calls-2026-01.jsonl"
    records = read_jsonl(path)
    assert len(records) == 2
    assert records[0]["prev_hash"] == AuditLogger.GENESIS_HASH
    assert records[1]["prev_hash"] == first.record_hash
    assert second.record_hash == verify_audit_chain(path).last_hash
    assert records[0]["params_hash"] == params_hash({
        "nested": {"a": 1, "b": 2},
        "cmd": "date",
    })
    assert "params" not in records[0]


def test_verify_audit_chain_detects_retroactive_tampering(tmp_path: Path) -> None:
    logger = AuditLogger(audit_dir=tmp_path, session_id="s1", principal="jerome")
    logger.log_event(event_type="tool_call_start", tool_name="terminal", at=JANUARY)
    logger.log_event(event_type="tool_call_end", tool_name="terminal", at=JANUARY)

    path = tmp_path / "tool-calls-2026-01.jsonl"
    records = read_jsonl(path)
    records[0]["event_type"] = "tool_call_start_tampered"
    path.write_text("\n".join(canonical_json(record) for record in records) + "\n")

    with pytest.raises(AuditChainError, match="prev_hash mismatch"):
        verify_audit_chain(path)


def test_verify_audit_chain_detects_tail_tamper_with_expected_hash(
    tmp_path: Path,
) -> None:
    logger = AuditLogger(audit_dir=tmp_path, session_id="s1", principal="jerome")
    logger.log_event(event_type="tool_call_start", tool_name="terminal", at=JANUARY)
    original = logger.log_event(
        event_type="tool_call_end",
        tool_name="terminal",
        error=None,
        at=JANUARY,
    )

    path = tmp_path / "tool-calls-2026-01.jsonl"
    records = read_jsonl(path)
    records[-1]["error"] = "tail record tampered"
    path.write_text("\n".join(canonical_json(record) for record in records) + "\n")

    with pytest.raises(AuditChainError, match="last_hash mismatch"):
        verify_audit_chain(path, expected_last_hash=original.record_hash)


def test_verify_audit_chain_detects_bad_genesis(tmp_path: Path) -> None:
    logger = AuditLogger(audit_dir=tmp_path, session_id="s1", principal="jerome")
    logger.log_event(event_type="session_open", at=JANUARY)

    path = tmp_path / "tool-calls-2026-01.jsonl"
    records = read_jsonl(path)
    records[0]["prev_hash"] = "sha256:not-the-genesis"
    path.write_text(canonical_json(records[0]) + "\n")

    with pytest.raises(AuditChainError, match="genesis"):
        verify_audit_chain(path)


def test_fail_closed_when_audit_file_cannot_open(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    blocked_file = audit_dir / "tool-calls-2026-01.jsonl"
    audit_dir.mkdir()
    blocked_file.mkdir()
    logger = AuditLogger(audit_dir=audit_dir, session_id="s1", principal="jerome")

    with pytest.raises(AuditLoggerOpenError):
        logger.log_event(event_type="tool_call_start", at=JANUARY)


def test_file_modes_and_append_only_open_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, int] = {}
    real_open = os.open

    def spy_open(path: Path | str, flags: int, mode: int = 0o777) -> int:
        observed["flags"] = flags
        observed["mode"] = mode
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", spy_open)
    logger = AuditLogger(audit_dir=tmp_path, session_id="s1", principal="jerome")

    logger.log_event(event_type="session_open", at=JANUARY)

    path = tmp_path / "tool-calls-2026-01.jsonl"
    assert observed["flags"] & os.O_APPEND
    assert observed["flags"] & os.O_WRONLY
    assert observed["flags"] & os.O_CREAT
    assert observed["mode"] == 0o600
    assert stat_mode(path) == 0o600
    assert stat_mode(tmp_path) == 0o700
    assert stat_mode(tmp_path / "archive") == 0o700


def test_record_shape_contains_required_audit_fields(tmp_path: Path) -> None:
    logger = AuditLogger(
        audit_dir=tmp_path,
        session_id="s1",
        principal="jerome",
        host="host1",
        pid=123,
        agent_version="0.test",
    )

    logger.log_event(
        event_type="tool_call_error",
        model_id="gpt-5",
        tool_name="terminal",
        tool_call_id="call-1",
        params={"cmd": "false"},
        duration_ms=12,
        blocked=True,
        block_reason="audit_test",
        error="boom",
        at=JANUARY,
    )

    record = read_jsonl(tmp_path / "tool-calls-2026-01.jsonl")[0]
    assert set(record) == {
        "agent_version",
        "block_reason",
        "blocked",
        "duration_ms",
        "error",
        "event_type",
        "host",
        "model_id",
        "params_hash",
        "pid",
        "prev_hash",
        "principal",
        "session_id",
        "timestamp_ms_utc",
        "tool_call_id",
        "tool_name",
    }
    assert record["timestamp_ms_utc"] == 1767614400000
    assert record["blocked"] is True
    assert record["params_hash"] == params_hash({"cmd": "false"})


def test_monthly_rotation_archives_previous_month(tmp_path: Path) -> None:
    logger = AuditLogger(audit_dir=tmp_path, session_id="s1", principal="jerome")

    january_event = logger.log_event(event_type="session_open", at=JANUARY)
    february_event = logger.log_event(event_type="session_open", at=FEBRUARY)

    january_archive = tmp_path / "archive" / "tool-calls-2026-01.jsonl"
    february_current = tmp_path / "tool-calls-2026-02.jsonl"
    assert not (tmp_path / "tool-calls-2026-01.jsonl").exists()
    assert january_archive.exists()
    assert february_current.exists()
    assert stat_mode(january_archive) == 0o400
    assert read_jsonl(january_archive)[0]["prev_hash"] == AuditLogger.GENESIS_HASH
    assert read_jsonl(february_current)[0]["prev_hash"] == AuditLogger.GENESIS_HASH
    assert verify_audit_chain(january_archive).last_hash == january_event.record_hash
    assert verify_audit_chain(february_current).last_hash == february_event.record_hash


def test_params_hash_is_deterministic_canonical_json() -> None:
    left = {"z": [3, 2, 1], "a": {"b": True, "a": None}}
    right = {"a": {"a": None, "b": True}, "z": [3, 2, 1]}

    assert params_hash(left) == params_hash(right)
    assert params_hash(left).startswith("sha256:")
    assert canonical_json(left) == '{"a":{"a":null,"b":true},"z":[3,2,1]}'


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777
