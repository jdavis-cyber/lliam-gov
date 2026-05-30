"""GatewayRunner inbound-auth audit wiring (LG-3.6 / AI-214).

Proves the audit-wrapped ``_is_user_authorized`` records every decision and, per
plan §5.2, fails closed — denying authorization when the decision cannot be
recorded — without standing up a full GatewayRunner.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from gateway.run import GatewayRunner
from lliam_gov.security.audit_logger import AuditLoggerOpenError


class _StubRunner:
    """Minimal carrier for the unbound wrapper + a controllable decision impl."""

    # Bind the real audit wrapper onto a lightweight object so we exercise the
    # production code path without GatewayRunner's heavy __init__.
    _is_user_authorized = GatewayRunner._is_user_authorized

    def __init__(self, impl_result: bool) -> None:
        self._impl_result = impl_result

    def _is_user_authorized_impl(self, source) -> bool:  # noqa: ANN001
        return self._impl_result


def _source():
    return SimpleNamespace(
        user_id="U1",
        user_name="Jane",
        chat_id="C1",
        chat_type="dm",
        platform=SimpleNamespace(value="telegram"),
        is_bot=False,
    )


def test_decision_is_audited_and_returned(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "lliam_gov.security.gateway_audit.audit_gateway_auth",
        lambda source, *, authorized, **kw: calls.append(authorized),
    )
    assert _StubRunner(True)._is_user_authorized(_source()) is True
    assert _StubRunner(False)._is_user_authorized(_source()) is False
    assert calls == [True, False]


def test_authorize_fails_closed_when_audit_unavailable(monkeypatch):
    def _boom(source, *, authorized, **kw):
        raise AuditLoggerOpenError("audit chain unavailable")

    monkeypatch.setattr("lliam_gov.security.gateway_audit.audit_gateway_auth", _boom)
    # Impl would authorize, but an unrecordable decision must be denied.
    assert _StubRunner(True)._is_user_authorized(_source()) is False


def test_denied_stays_denied_on_audit_failure(monkeypatch):
    def _boom(source, *, authorized, **kw):
        raise AuditLoggerOpenError("audit chain unavailable")

    monkeypatch.setattr("lliam_gov.security.gateway_audit.audit_gateway_auth", _boom)
    assert _StubRunner(False)._is_user_authorized(_source()) is False
