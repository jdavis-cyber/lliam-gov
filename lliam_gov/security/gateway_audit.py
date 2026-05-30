"""Inbound gateway authentication-decision audit hook for Lliam-GOV.

Plan §5.2 ("auth events in the retained gateway adapters"), LG-3.6 / AI-214.

The cross-platform inbound-authorization decision is made in one place —
``gateway.run.GatewayRunner._is_user_authorized(source)`` — which every retained
adapter (Slack, email, Telegram) funnels its DM/user authorization through. This
module records that decision (allow or deny) to the §5.2 hash-chained audit
chain, keyed to the principal, so every inbound auth event is uniquely traceable.

Only non-sensitive decision metadata reaches the chain:

* ``principal`` (top-level, visible): the authenticated/claimed user id — this is
  the SP 800-171 3.3.2 traceability anchor.
* ``tool_name`` (top-level, visible): the platform name (the component that
  handled the inbound auth), e.g. ``telegram``.
* ``blocked`` / ``block_reason`` (top-level, visible): allow vs deny.
* ``params`` (persisted only as a salted-free SHA-256 ``params_hash`` — never raw):
  ancillary context (chat type/id, display name, bot flag). Hashing keeps
  display names and chat ids out of the cleartext log while preserving
  tamper-evidence.

Request bodies, headers, signatures, and tokens are never passed here.

Fail-closed: a caller that cannot durably record the decision must refuse to
authorize (mirrors the §5.2 tool-dispatch rule "refuse if the audit logger
cannot open its file"). :func:`audit_gateway_auth` therefore lets
:class:`~lliam_gov.security.audit_logger.AuditLoggerError` propagate; the caller
denies on that error.

Maps to: SP 800-171 3.3.1, 3.3.2 (and supports 3.1.1/3.1.2 access control
evidence); ISO/IEC 27001 A.8.15; ISO/IEC 42001 A.6.2.8.
"""

from __future__ import annotations

from typing import Any, Protocol

from lliam_gov.security.audit_logger import AuditLogger, get_shared_audit_logger

# Stable event-type string; audit consumers (AEP export) match on this.
GATEWAY_AUTH_EVENT = "gateway_auth"


class _SourceLike(Protocol):
    """Structural view of ``gateway.session.SessionSource``.

    Declared structurally so this security module never imports the gateway
    package (keeps the dependency arrow gateway -> lliam_gov.security one-way).
    """

    user_id: str | None
    user_name: str | None
    chat_id: str | None
    chat_type: str | None
    # ``platform`` is an enum with a ``.value`` string in production; tests may
    # pass a plain string. Handled defensively in :func:`_platform_name`.


def _platform_name(source: Any) -> str:
    platform = getattr(source, "platform", None)
    value = getattr(platform, "value", platform)
    return str(value or "unknown")


def _principal(source: Any) -> str:
    user_id = getattr(source, "user_id", None)
    if user_id:
        return str(user_id)
    chat_id = getattr(source, "chat_id", None)
    if chat_id:
        return f"chat:{chat_id}"
    return "anonymous"


def audit_gateway_auth(
    source: _SourceLike,
    *,
    authorized: bool,
    reason: str | None = None,
    logger: AuditLogger | None = None,
) -> None:
    """Record one inbound gateway authorization decision.

    Args:
        source: The inbound message source (duck-typed ``SessionSource``).
        authorized: The authorization outcome (``True`` = allowed).
        reason: Optional coarse reason for a denial (e.g. ``"unauthorized_user"``);
            never a free-form body. Ignored when ``authorized`` is ``True``.
        logger: Audit logger to use; defaults to the process-wide shared logger
            (the same chain used by session/tool audit events).

    Raises:
        AuditLoggerError: if the decision cannot be recorded durably. Callers
            must treat this as fail-closed and refuse to authorize.
    """
    log = logger or get_shared_audit_logger()
    log.log_event(
        event_type=GATEWAY_AUTH_EVENT,
        principal=_principal(source),
        tool_name=_platform_name(source),
        blocked=not authorized,
        block_reason=None if authorized else (reason or "unauthorized_user"),
        params={
            "platform": _platform_name(source),
            "chat_type": getattr(source, "chat_type", None),
            "chat_id": getattr(source, "chat_id", None),
            "user_name": getattr(source, "user_name", None),
            "is_bot": bool(getattr(source, "is_bot", False)),
        },
    )


__all__ = ["GATEWAY_AUTH_EVENT", "audit_gateway_auth"]
