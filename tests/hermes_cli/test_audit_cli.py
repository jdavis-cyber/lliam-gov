"""Tests for governance audit CLI commands."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from hermes_cli.audit_cli import cmd_audit
from lliam_gov.security.audit_logger import AuditLogger


def _build_audit_log(tmp_path: Path) -> Path:
    logger = AuditLogger(audit_dir=tmp_path / "audit", session_id="session-cli")
    logger.log_event(
        event_type="tool_call_start",
        tool_name="terminal",
        tool_call_id="call-cli",
        params={"command": "pwd"},
        at=datetime(2026, 5, 28, 12, 0, tzinfo=timezone.utc),
    )
    return tmp_path / "audit" / "tool-calls-2026-05.jsonl"


def test_export_aep_command_writes_package(tmp_path: Path, capsys) -> None:
    audit_log = _build_audit_log(tmp_path)
    output_path = tmp_path / "audit-aep.json"
    args = argparse.Namespace(
        audit_command="export-aep",
        input=[str(audit_log)],
        output=str(output_path),
    )

    code = cmd_audit(args)

    assert code == 0
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["record_count"] == 1
    assert "Exported 1 audit record" in capsys.readouterr().out


def test_verify_aep_command_accepts_round_trip_export(tmp_path: Path, capsys) -> None:
    audit_log = _build_audit_log(tmp_path)
    output_path = tmp_path / "audit-aep.json"
    assert (
        cmd_audit(
            argparse.Namespace(
                audit_command="export-aep",
                input=[str(audit_log)],
                output=str(output_path),
            )
        )
        == 0
    )

    code = cmd_audit(
        argparse.Namespace(audit_command="verify-aep", input=str(output_path))
    )

    assert code == 0
    assert "Verified 1 audit record" in capsys.readouterr().out
