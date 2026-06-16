"""Adapter-level inbound auth-deny audit wiring (LG-3.6 / AI-214 follow-up).

The chokepoint audit hook in ``GatewayRunner._is_user_authorized`` only sees
decisions that reach it. Some retained adapters reject inbound traffic before
that chokepoint — email allowlist drops in ``_dispatch_message`` and Slack
button-click handlers (slash-confirm, approval) — and used to leave no §5.2
audit record. These tests prove each of those deny paths now invokes the
``audit_adapter_auth_deny`` helper so the LG-3.6 trail is complete.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest


# -- Email: unallowlisted sender drop -----------------------------------------


def test_email_unallowlisted_sender_records_auth_deny(monkeypatch):
    """gateway/platforms/email.py:_dispatch_message must audit allowlist drops."""
    from gateway.platforms.email import EmailAdapter

    calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(
        "lliam_gov.security.gateway_audit.audit_adapter_auth_deny",
        lambda **kw: calls.append(kw),
    )
    monkeypatch.setenv("EMAIL_ALLOWED_USERS", "ok@example.com")

    # Lightweight stand-in: _dispatch_message only touches _address before the
    # deny return.
    stub = SimpleNamespace(_address="me@example.com")
    msg = {
        "sender_addr": "intruder@example.com",
        "subject": "hi",
        "body": "",
        "attachments": [],
        "message_id": "m1",
    }

    asyncio.run(EmailAdapter._dispatch_message(stub, msg))

    assert len(calls) == 1, "deny path must emit exactly one audit-deny call"
    assert calls[0]["platform"] == "email"
    assert calls[0]["user_id"] == "intruder@example.com"
    assert calls[0]["chat_id"] == "intruder@example.com"


def test_email_allowlisted_sender_does_not_audit_deny(monkeypatch):
    """Allowed senders must not emit an adapter-level deny audit."""
    from gateway.platforms.email import EmailAdapter

    calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(
        "lliam_gov.security.gateway_audit.audit_adapter_auth_deny",
        lambda **kw: calls.append(kw),
    )
    monkeypatch.setenv("EMAIL_ALLOWED_USERS", "ok@example.com")

    # Stop the dispatch as soon as it gets past the auth gate — otherwise it
    # would try to call self._handle_message and exercise unrelated code.
    sentinel = RuntimeError("stop after auth gate")

    def _stop(self, *a, **kw):  # noqa: ANN001
        raise sentinel

    monkeypatch.setattr(EmailAdapter, "_handle_message", _stop, raising=False)

    stub = SimpleNamespace(
        _address="me@example.com",
        _thread_context={},
        _handle_message=lambda *a, **kw: (_ for _ in ()).throw(sentinel),
    )
    msg = {
        "sender_addr": "ok@example.com",
        "subject": "hi",
        "body": "",
        "attachments": [],
        "message_id": "m2",
    }

    with pytest.raises(Exception):
        asyncio.run(EmailAdapter._dispatch_message(stub, msg))

    assert calls == [], "allowed senders must not audit a deny"


def test_email_audit_failure_does_not_raise(monkeypatch, caplog):
    """An audit-chain failure must not raise out of _dispatch_message — the
    deny is already happening and the adapter cannot do better."""
    from gateway.platforms.email import EmailAdapter
    from lliam_gov.security.audit_logger import AuditLoggerOpenError

    def _boom(**kw):
        raise AuditLoggerOpenError("audit chain unavailable")

    monkeypatch.setattr(
        "lliam_gov.security.gateway_audit.audit_adapter_auth_deny", _boom,
    )
    monkeypatch.setenv("EMAIL_ALLOWED_USERS", "ok@example.com")

    stub = SimpleNamespace(_address="me@example.com")
    msg = {
        "sender_addr": "intruder@example.com",
        "subject": "",
        "body": "",
        "attachments": [],
        "message_id": "m3",
    }

    # Must not raise.
    asyncio.run(EmailAdapter._dispatch_message(stub, msg))


# -- Slack: button auth-deny helper -------------------------------------------


def test_slack_button_deny_helper_calls_audit(monkeypatch):
    """_audit_slack_button_deny constructs the right adapter-deny call."""
    from gateway.platforms import slack as slack_mod

    calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(
        "lliam_gov.security.gateway_audit.audit_adapter_auth_deny",
        lambda **kw: calls.append(kw),
    )

    slack_mod._audit_slack_button_deny(
        user_id="U999",
        user_name="Mallory",
        channel_id="C42",
        reason="unauthorized_approval_click",
    )

    assert len(calls) == 1
    assert calls[0]["platform"] == "slack"
    assert calls[0]["user_id"] == "U999"
    assert calls[0]["user_name"] == "Mallory"
    assert calls[0]["chat_id"] == "C42"
    assert calls[0]["reason"] == "unauthorized_approval_click"


def test_slack_button_deny_helper_swallows_audit_failure(monkeypatch):
    """An audit-chain failure must not raise out of the helper — the button
    click is already being denied and we cannot change that outcome."""
    from gateway.platforms import slack as slack_mod
    from lliam_gov.security.audit_logger import AuditLoggerOpenError

    def _boom(**kw):
        raise AuditLoggerOpenError("audit chain unavailable")

    monkeypatch.setattr(
        "lliam_gov.security.gateway_audit.audit_adapter_auth_deny", _boom,
    )

    # Must not raise.
    slack_mod._audit_slack_button_deny(
        user_id="U999",
        user_name="Mallory",
        channel_id="C42",
        reason="unauthorized_slash_confirm",
    )
