"""Tests for the inbound gateway-auth decision audit hook (gateway_audit.py).

Covers LG-3.6 / AI-214: every authorization decision (allow or deny) is recorded
to the hash-chained chain keyed to the principal, the chain stays intact, no
display-name/PII leaks into cleartext, and the hook fails closed (propagates) so
its caller can deny when the decision cannot be recorded.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from lliam_gov.security.audit_logger import (
    AuditLogger,
    AuditLoggerError,
    verify_audit_chain,
)
from lliam_gov.security.gateway_audit import GATEWAY_AUTH_EVENT, audit_gateway_auth


def _logger(tmp_path: Path) -> AuditLogger:
    return AuditLogger(audit_dir=tmp_path)


def _records(tmp_path: Path) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(tmp_path.glob("tool-calls-*.jsonl")):
        rows.extend(
            json.loads(line) for line in path.read_text().splitlines() if line.strip()
        )
    return rows


def _source(
    *,
    user_id="U123",
    platform="telegram",
    chat_id="C1",
    chat_type="dm",
    user_name="Jane Doe",
    is_bot=False,
):
    return SimpleNamespace(
        user_id=user_id,
        user_name=user_name,
        chat_id=chat_id,
        chat_type=chat_type,
        platform=platform,
        is_bot=is_bot,
    )


def test_authorized_decision_recorded(tmp_path):
    log = _logger(tmp_path)
    audit_gateway_auth(_source(), authorized=True, logger=log)
    rows = _records(tmp_path)
    assert len(rows) == 1
    assert rows[0]["event_type"] == GATEWAY_AUTH_EVENT
    assert rows[0]["principal"] == "U123"
    assert rows[0]["tool_name"] == "telegram"
    assert rows[0]["blocked"] is False
    assert rows[0]["block_reason"] is None


def test_denied_decision_recorded(tmp_path):
    log = _logger(tmp_path)
    audit_gateway_auth(_source(user_id="evil"), authorized=False, logger=log)
    rows = _records(tmp_path)
    assert rows[0]["blocked"] is True
    assert rows[0]["block_reason"] == "unauthorized_user"
    assert rows[0]["principal"] == "evil"


def test_custom_denial_reason(tmp_path):
    log = _logger(tmp_path)
    audit_gateway_auth(_source(), authorized=False, reason="rate_limited", logger=log)
    assert _records(tmp_path)[0]["block_reason"] == "rate_limited"


def test_platform_enum_value_extracted(tmp_path):
    log = _logger(tmp_path)
    audit_gateway_auth(
        _source(platform=SimpleNamespace(value="slack")), authorized=True, logger=log
    )
    assert _records(tmp_path)[0]["tool_name"] == "slack"


def test_principal_falls_back_to_chat_then_anonymous(tmp_path):
    log = _logger(tmp_path)
    audit_gateway_auth(
        _source(user_id=None, chat_id="9988"), authorized=True, logger=log
    )
    audit_gateway_auth(
        _source(user_id=None, chat_id=None), authorized=False, logger=log
    )
    rows = _records(tmp_path)
    assert rows[0]["principal"] == "chat:9988"
    assert rows[1]["principal"] == "anonymous"


def test_display_name_not_in_cleartext(tmp_path):
    log = _logger(tmp_path)
    audit_gateway_auth(
        _source(user_name="Top Secret Person"), authorized=True, logger=log
    )
    raw = next(tmp_path.glob("tool-calls-*.jsonl")).read_text()
    # The display name is carried only inside params -> persisted as params_hash.
    assert "Top Secret Person" not in raw
    assert _records(tmp_path)[0]["params_hash"].startswith("sha256:")


def test_chain_intact_across_mixed_decisions(tmp_path):
    log = _logger(tmp_path)
    audit_gateway_auth(_source(user_id="a"), authorized=True, logger=log)
    audit_gateway_auth(_source(user_id="b"), authorized=False, logger=log)
    audit_gateway_auth(_source(user_id="c"), authorized=True, logger=log)
    path = next(tmp_path.glob("tool-calls-*.jsonl"))
    verification = verify_audit_chain(path)
    assert verification.record_count == 3


def test_fails_closed_when_chain_unwritable(tmp_path):
    # Point the audit dir at a path blocked by an existing regular file so the
    # logger cannot create its directory: the hook must propagate, not swallow.
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    broken = AuditLogger(audit_dir=blocker / "audit")
    with pytest.raises(AuditLoggerError):
        audit_gateway_auth(_source(), authorized=True, logger=broken)
