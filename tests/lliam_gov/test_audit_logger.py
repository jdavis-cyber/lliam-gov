"""Tests for ``lliam_gov.security.audit_logger``.

Covers the AI-210 / Rev. 3 §5.2 core: JSONL audit records, append-only
monthly files, hash-chain verification, deterministic params hashing,
and fail-closed open behavior.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lliam_gov.security.audit_logger import (
    AuditChainError,
    AuditLogger,
    AuditLoggerOpenError,
    canonical_json,
    get_shared_audit_logger,
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


def test_log_event_serializes_concurrent_writes(tmp_path: Path, monkeypatch) -> None:
    logger = AuditLogger(audit_dir=tmp_path, session_id="s1", principal="jerome")
    real_append = logger._append_chained
    active_appends = 0
    max_active_appends = 0
    active_lock = threading.Lock()

    def slow_append(path, record):
        nonlocal active_appends, max_active_appends
        with active_lock:
            active_appends += 1
            max_active_appends = max(max_active_appends, active_appends)
        try:
            time.sleep(0.02)
            return real_append(path, record)
        finally:
            with active_lock:
                active_appends -= 1

    monkeypatch.setattr(logger, "_append_chained", slow_append)

    threads = [
        threading.Thread(
            target=logger.log_event,
            kwargs={
                "event_type": "tool_call_start",
                "tool_name": "terminal",
                "tool_call_id": f"call-{index}",
                "at": JANUARY,
            },
        )
        for index in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert max_active_appends == 1
    assert verify_audit_chain(tmp_path / "tool-calls-2026-01.jsonl").record_count == 8


def test_concurrent_independent_writers_do_not_fork_chain(tmp_path: Path) -> None:
    """Issue #69 regression: two *independent* writers (the desktop app and a
    CLI turn) share the monthly file but not the in-memory chain tail.

    Each ``AuditLogger`` has its own ``_previous_hash`` cache and its own
    thread lock, exactly like two OS processes. Before the fix their
    interleaved appends forked the chain and ``verify_audit_chain`` raised a
    false ``prev_hash mismatch`` (the fail-closed tamper lockout). With the
    inter-process ``flock`` + re-read-tail-under-lock fix, the on-disk chain
    must stay single and verify clean.
    """

    app_writer = AuditLogger(
        audit_dir=tmp_path, session_id="app", principal="jerome", pid=1001
    )
    cli_writer = AuditLogger(
        audit_dir=tmp_path, session_id="cli", principal="jerome", pid=2002
    )
    per_writer = 25

    def hammer(logger: AuditLogger, tag: str) -> None:
        for index in range(per_writer):
            logger.log_event(
                event_type="tool_call_start",
                tool_name="terminal",
                tool_call_id=f"{tag}-{index}",
                at=JANUARY,
            )

    threads = [
        threading.Thread(target=hammer, args=(app_writer, "app")),
        threading.Thread(target=hammer, args=(cli_writer, "cli")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    path = tmp_path / "tool-calls-2026-01.jsonl"
    # Must NOT raise AuditChainError: the chain is intact across both writers.
    verification = verify_audit_chain(path)
    assert verification.record_count == per_writer * 2


def test_shared_audit_logger_reuses_single_chain_writer(tmp_path: Path, monkeypatch) -> None:
    import lliam_gov.security.audit_logger as audit_logger

    monkeypatch.setattr(audit_logger, "get_hermes_home", lambda: tmp_path)

    first = get_shared_audit_logger(session_id="s1", principal="jerome")
    second = get_shared_audit_logger(session_id="s2", principal="other")

    assert second is first


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
    # O_RDWR (not O_WRONLY) because the append path re-reads the chain tail
    # under the lock before writing (issue #69). Append-only is preserved by
    # O_APPEND + the absence of O_TRUNC.
    assert (observed["flags"] & os.O_RDWR) == os.O_RDWR
    assert not (observed["flags"] & os.O_TRUNC)
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
        "destination",
        "duration_ms",
        "error",
        "event_type",
        "host",
        "marker",
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



def test_persisted_record_masks_raw_params(tmp_path: Path) -> None:
    """ISO 27001 A.8.11 data masking: persisted audit records carry only the
    canonical ``params_hash`` and never the raw ``params`` payload."""
    logger = AuditLogger(audit_dir=tmp_path, session_id="s1", principal="jerome")
    secret = {"cmd": "deploy", "token": "super-secret-value"}
    logger.log_event(
        event_type="tool_call_start",
        tool_name="terminal",
        tool_call_id="call-1",
        params=secret,
        model_id="gpt-5",
        at=JANUARY,
    )
    record = read_jsonl(tmp_path / "tool-calls-2026-01.jsonl")[0]
    assert record["params_hash"] == params_hash(secret)
    assert "params" not in record
    assert "super-secret-value" not in (tmp_path / "tool-calls-2026-01.jsonl").read_text()
