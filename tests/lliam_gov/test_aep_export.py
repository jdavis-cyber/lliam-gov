"""Tests for audit Evidence Package (AEP) export/re-import."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from lliam_gov.security.audit_logger import AuditChainError, AuditLogger
from lliam_gov.security.aep_export import (
    AEP_SCHEMA,
    build_aep_export,
    verify_aep_export,
    write_aep_export,
)


def _build_audit_log(tmp_path: Path) -> Path:
    logger = AuditLogger(
        audit_dir=tmp_path / "audit",
        session_id="session-1",
        principal="operator@example.com",
        host="workstation",
        pid=4242,
        agent_version="test-version",
    )
    first = datetime(2026, 5, 28, 12, 0, tzinfo=timezone.utc)
    second = datetime(2026, 5, 28, 12, 1, tzinfo=timezone.utc)
    logger.log_event(
        event_type="tool_call_start",
        model_id="gpt-test",
        tool_name="read_file",
        tool_call_id="call-1",
        params={"path": "/tmp/cui-free.txt", "limit": 5},
        at=first,
    )
    logger.log_event(
        event_type="tool_call_end",
        model_id="gpt-test",
        tool_name="read_file",
        tool_call_id="call-1",
        params={"limit": 5, "path": "/tmp/cui-free.txt"},
        duration_ms=17,
        at=second,
    )
    return tmp_path / "audit" / "tool-calls-2026-05.jsonl"


def test_build_aep_export_verifies_chain_and_excludes_raw_params(
    tmp_path: Path,
) -> None:
    audit_log = _build_audit_log(tmp_path)

    package = build_aep_export(
        [audit_log],
        generated_at=datetime(2026, 5, 28, 13, 0, tzinfo=timezone.utc),
    )

    assert package["schema"] == AEP_SCHEMA
    assert package["record_count"] == 2
    assert package["sources"][0]["record_count"] == 2
    assert package["sources"][0]["first_record_index"] == 0
    assert package["sources"][0]["last_record_index"] == 1
    assert package["sources"][0]["last_hash"].startswith("sha256:")
    assert package["records"][0]["params_hash"].startswith("sha256:")
    assert '"params":' not in json.dumps(package)

    verification = verify_aep_export(package)
    assert verification.record_count == 2
    assert verification.sources[0].last_hash == package["sources"][0]["last_hash"]


def test_write_and_reimport_aep_export_round_trips(tmp_path: Path) -> None:
    audit_log = _build_audit_log(tmp_path)
    output_path = tmp_path / "evidence" / "audit-aep.json"

    package = write_aep_export(
        [audit_log],
        output_path,
        generated_at=datetime(2026, 5, 28, 13, 0, tzinfo=timezone.utc),
    )

    assert output_path.exists()
    assert json.loads(output_path.read_text(encoding="utf-8")) == package
    assert verify_aep_export(output_path).record_count == 2


def test_verify_aep_export_detects_reimport_tampering(tmp_path: Path) -> None:
    audit_log = _build_audit_log(tmp_path)
    package = build_aep_export([audit_log])

    package["records"][1]["duration_ms"] = 999

    with pytest.raises(AuditChainError, match="last_hash mismatch"):
        verify_aep_export(package)
