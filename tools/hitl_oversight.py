"""tools/hitl_oversight.py — Lliam-GOV human-oversight decision layer (P2.2).

ADDITIVE OVERLAY MODULE (PATH-FREEZE) — binds the PDP's hitl_approve tier to
real, recorded human decisions. Realizes:

  * LG-HO-02 — ``strict_fail_closed()``: under strict posture the legacy
    non-interactive auto-approve branch in tools/approval.py fails CLOSED.
  * LG-HO-07 — approval-prompt fatigue tracking (``note_approval_prompt``):
    a session that crosses the threshold is flagged and logged so over-gating
    is surfaced as a tuning signal — prompts are NEVER auto-approved.
  * LG-HO-08 — decision messages carry the concrete risk rationale (the
    matched pattern description) and how to obtain approval.
  * LG-HO-09 — ``operator_override()``: the explicit appeal/override channel.
    An override is an approval-backed JIT grant with a recorded justification;
    it can NEVER re-enable a deny-tier class (deny is terminal).
  * LG-HO-10 — ``record_decision()``: every approval / denial / override lands
    in the hash-chained ledger as ``approval.decision`` with the approver
    identity and rationale. Observer-safe: recording never breaks the
    decision path (the ledger's own LG-AU-09 fail-closed contract is enforced
    at the dispatch gate, not here).
  * LG-GV-05 — ``authorize_approval()``: when
    ``security.require_authenticated_approver`` is true, an approval (any
    non-deny choice) is refused unless the resolving context carries an
    authenticated approver: the operator-subject contextvar stamped by the
    gateway WS layer, either for a dashboard_auth user or for the local
    operator's desktop app (the connection that presented the desktop
    shell's per-launch gateway secret). Denials are always accepted —
    refusing a deny would only leave the action pending until it times out
    to a deny.

Low-side postures: ``strict_fail_closed()`` and
``require_authenticated_approver()`` are False and nothing here changes
shipped behavior (capability preserving).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, NamedTuple, Optional, Tuple

logger = logging.getLogger("hermes.governance.hitl_oversight")

#: Identities that authenticate a *connection* but are not a human approver
#: (the dashboard's process-lifetime internal WS credential). An approval made
#: under one of these is not an authenticated approval.
_NON_HUMAN_PRINCIPALS = frozenset({"server-internal"})

#: Subject ``auth`` methods that authenticate a human approver (LG-GV-05):
#: a dashboard_auth login (``dashboard_auth:<provider>``, stamped from a
#: consumed WS ticket or a principal-bound child credential), or the desktop
#: app's per-launch gateway secret, held only by the desktop shell that
#: spawned the backend. Must match ``tui_gateway.transport.LOCAL_OPERATOR_AUTH``.
_DASHBOARD_AUTH_PREFIX = "dashboard_auth:"
LOCAL_OPERATOR_AUTH = "desktop-launch-secret"

#: Choices that do not approve anything. Every other choice ("once",
#: "session", "always", "approve", "allow-once", ...) is an approval.
_DENY_CHOICES = frozenset({"deny", "denied", "reject", "halt", "timeout", ""})

#: LG-HO-07 — prompts per session before the fatigue flag trips. Generous:
#: routine work should see far fewer; crossing it signals over-gating to tune
#: via the tool-risk policy deviation register, never a reason to auto-approve.
FATIGUE_PROMPT_THRESHOLD = 10

_PROMPT_COUNTS: Dict[str, int] = {}


def reset_fatigue_state() -> None:
    _PROMPT_COUNTS.clear()


def note_approval_prompt(session_key: str) -> bool:
    """Count one approval prompt for the session (LG-HO-07).

    Returns True when the session has now EXCEEDED the fatigue threshold —
    callers log/surface it (and the tuning register is the fix); the prompt
    itself still happens. Never auto-approves.
    """
    key = str(session_key or "default")
    _PROMPT_COUNTS[key] = _PROMPT_COUNTS.get(key, 0) + 1
    exceeded = _PROMPT_COUNTS[key] > FATIGUE_PROMPT_THRESHOLD
    if exceeded:
        logger.warning(
            "LG-HO-07 approval-fatigue flag: session %s has seen %d approval "
            "prompts — review tool-risk tiering (deviation register) if this "
            "is routine work.", key, _PROMPT_COUNTS[key],
        )
    return exceeded


def strict_fail_closed() -> bool:
    """True when the no-approver branch must fail closed (LG-HO-02/06).

    Strict posture always qualifies; ``security.deny_on_no_approver: true``
    (which the posture resolver also forces under strict) qualifies on its own.
    """
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr
        cfg = _cfg.load_config()
        if _pr.is_strict(cfg):
            return True
        sec = (cfg or {}).get("security") if isinstance(cfg, dict) else None
        return isinstance(sec, dict) and sec.get("deny_on_no_approver") is True
    except Exception:
        return False


def require_authenticated_approver(config: Optional[Dict[str, Any]] = None) -> bool:
    """True when ``security.require_authenticated_approver`` is set (LG-GV-05).

    *config* lets a caller (the CI control-effectiveness probe) evaluate a
    specific overlay instead of the live config. Low-side configs do not set
    the key, so this is False there.
    """
    try:
        if config is None:
            from lliam_cli import config as _cfg
            config = _cfg.load_config()
        sec = (config or {}).get("security") if isinstance(config, dict) else None
        return isinstance(sec, dict) and sec.get("require_authenticated_approver") is True
    except Exception:
        return False


def _is_approver_auth(method: Any) -> bool:
    method = str(method or "").strip()
    return method == LOCAL_OPERATOR_AUTH or (
        method.startswith(_DASHBOARD_AUTH_PREFIX) and len(method) > len(_DASHBOARD_AUTH_PREFIX)
    )


def bound_approver() -> Optional[Tuple[str, str]]:
    """Return ``(principal, method)`` of the authenticated approver bound here.

    The subject comes from the LG-AU-10 operator-subject contextvar, which
    only the gateway WS layer stamps: for a dashboard_auth user (from a
    consumed WS ticket or a principal-bound child credential) or for the
    local operator's desktop app (``local-operator:<os-user>@<host>``, from
    the desktop shell's per-launch gateway secret). A subject without one of
    those auth methods, or a connection-only identity such as
    ``server-internal``, does not count.
    """
    try:
        from agent.governance_audit_hooks import _current_subject
        subject = _current_subject() or {}
    except Exception:
        return None
    principal = str(subject.get("principal") or "").strip()
    if not principal or principal in _NON_HUMAN_PRINCIPALS:
        return None
    method = str(subject.get("auth") or "").strip()
    if not _is_approver_auth(method):
        return None
    return principal, method


def authenticated_principal() -> Optional[str]:
    """Return the authenticated approver principal bound to this context, if any."""
    bound = bound_approver()
    return bound[0] if bound else None


def is_approval_choice(choice: Any) -> bool:
    """True when *choice* approves the action (anything but a deny/timeout)."""
    return str(choice or "").strip().lower() not in _DENY_CHOICES


class ApprovalAuthorization(NamedTuple):
    allowed: bool
    principal: Optional[str]
    reason: str
    #: How *principal* authenticated (``dashboard_auth:<provider>`` or
    #: ``desktop-launch-secret``), when one is bound.
    method: Optional[str] = None


UNAUTHENTICATED_APPROVER_REASON = (
    "approval refused: security.require_authenticated_approver is set and no "
    "authenticated approver is bound to this approval (LG-GV-05). Approve "
    "from the desktop app or an authenticated dashboard session, or deny."
)


def authorize_approval(
    choice: Any,
    *,
    gate: str,
    target: str = "",
    description: str = "",
    origin: str = "",
    config: Optional[Dict[str, Any]] = None,
    record: bool = True,
) -> ApprovalAuthorization:
    """Decide whether *choice* may resolve a HITL gate in this context (LG-GV-05).

    Denials always pass. Approvals pass when the requirement is off (low-side)
    or an authenticated principal is bound; otherwise the refusal is logged and
    recorded to the ledger (unless *record* is False — read-only probes) and
    ``allowed`` is False. Never raises.
    """
    bound = bound_approver()
    principal, method = bound if bound else (None, None)
    if not is_approval_choice(choice):
        return ApprovalAuthorization(True, principal, "", method)
    if principal or not require_authenticated_approver(config):
        return ApprovalAuthorization(True, principal, "", method)
    if not record:
        return ApprovalAuthorization(False, None, UNAUTHENTICATED_APPROVER_REASON)
    logger.warning(
        "LG-GV-05: refused unauthenticated approval (gate=%s origin=%s choice=%s)",
        gate, origin, choice,
    )
    record_decision(
        decision="deny", gate=gate, target=target, description=description,
        origin=f"{origin or 'approval'}:unauthenticated_approver_refused",
        justification=UNAUTHENTICATED_APPROVER_REASON,
    )
    return ApprovalAuthorization(False, None, UNAUTHENTICATED_APPROVER_REASON)


def record_decision(
    *,
    decision: str,                    # approve | deny | halt | timeout | n/a
    gate: str,                        # which gate decided (e.g. shell.dangerous)
    target: str = "",                 # command / path / capability
    description: str = "",            # risk rationale (LG-HO-08)
    approver: Optional[str] = None,   # authenticated principal, if any
    origin: str = "",                 # non_interactive_fail_closed | interactive_prompt | gateway | jit_grant | operator_override
    justification: str = "",
    approver_authenticated: Optional[bool] = None,
    approver_method: Optional[str] = None,
    session_id: Optional[str] = None,
) -> None:
    """Emit one ``approval.decision`` record (LG-HO-10). Never raises.

    The approver defaults to the authenticated approver bound to this
    context (LG-GV-05); ``approver.authenticated`` says whether the recorded
    identity is that bound principal rather than a caller-supplied label, and
    ``approver.method`` how it authenticated. A caller that captured the
    principal in another context (the gateway resolver thread) passes
    ``approver_authenticated=True`` and ``approver_method``.

    A completed request supplies ``session_id`` to also record its resolution
    in agent.log, independently of the ledger. Authorization probes omit it
    because they may leave the request pending. The supplied approver is the
    resolver's identity; None means no identified operator answered.
    """
    if session_id is not None:
        try:
            from agent.redact import redact_sensitive_text

            logger.info("approval.decision %s", json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "command": redact_sensitive_text(target, force=True),
                "decision": decision,
                "approver": approver,
            }))
        except Exception:
            logger.warning("Approval resolution log failed (non-blocking)", exc_info=True)

    try:
        from agent.governance_audit_hooks import _current_subject, _enabled_ledger
        ledger = _enabled_ledger()
        if ledger is None:
            return
        bound = bound_approver()
        bound_id, bound_method = bound if bound else (None, None)
        approver_id = approver or bound_id
        approver_rec: Dict[str, Any] = {}
        if approver_id:
            is_bound = bool(bound_id) and str(approver_id) == bound_id
            if approver_authenticated is None:
                approver_authenticated = is_bound
            if approver_method is None and is_bound:
                approver_method = bound_method
            approver_rec = {
                "id": approver_id,
                "authenticated": bool(approver_authenticated),
            }
            if approver_authenticated and approver_method:
                approver_rec["method"] = approver_method
        ledger.emit(
            "approval.decision",
            action=f"approval.{gate}",
            decision=decision,
            subject=_current_subject(),
            approver=approver_rec,
            parameters={"target": target},
            resource={"type": "approval_gate", "name": gate},
            source_module="tools/hitl_oversight.py",
            outcome={
                "origin": origin,
                "rationale": description,
                "justification": justification,
                "control": "LG-HO-02" if origin == "non_interactive_fail_closed" else "LG-HO-10",
            },
        )
    except Exception:
        logger.warning("approval.decision ledger emit failed (non-blocking)", exc_info=True)


def _require_bound_approver(approver: str, *, gate: str, origin: str) -> None:
    """Under LG-GV-05, a named approver must be the authenticated principal.

    Raises PermissionError when the requirement is on and either no principal
    is bound or the caller-supplied *approver* names someone else. No-op when
    the requirement is off (low-side).
    """
    auth = authorize_approval("approve", gate=gate, target=gate, origin=origin)
    if not auth.allowed:
        raise PermissionError(auth.reason)
    if auth.principal and require_authenticated_approver() and str(approver).strip() != auth.principal:
        record_decision(
            decision="deny", gate=gate, target=gate,
            origin=f"{origin}:approver_mismatch",
            justification=f"claimed approver {approver!r} is not the authenticated principal",
        )
        raise PermissionError(
            f"approver {approver!r} is not the authenticated principal "
            f"{auth.principal!r} (LG-GV-05)"
        )


def operator_override(
    action_class: str,
    *,
    approver: str,
    justification: str,
    ttl_seconds: Optional[int] = None,
    session_id: Optional[str] = None,
) -> None:
    """LG-HO-09 appeal/override: approval-backed JIT grant with justification.

    Raises ValueError for deny-tier classes — deny is terminal and no override
    re-enables it (LG-HO-03). The override is recorded to the ledger and takes
    effect as a normal TTL-bounded, session-scoped grant (LG-AZ-07).
    """
    if not (approver or "").strip():
        raise ValueError("operator_override requires an authenticated approver")
    if not (justification or "").strip():
        raise ValueError("operator_override requires a justification")
    _require_bound_approver(approver, gate=str(action_class).strip(), origin="operator_override")
    from tools import tool_policy as tp
    policy = tp._load_risk_policy()
    tier = tp._class_tiers(policy).get(str(action_class).strip()) if isinstance(policy, dict) else None
    if tier == "deny":
        raise ValueError(
            f"deny-tier class '{action_class}' cannot be overridden — deny is "
            "terminal (LG-HO-03); no toggle, grant, or override re-enables it"
        )
    tp.grant_capability(
        str(action_class).strip(), approver=approver,
        ttl_seconds=ttl_seconds, session_id=session_id,
    )
    record_decision(
        decision="approve",
        gate=str(action_class).strip(),
        target=str(action_class).strip(),
        description="operator override / appeal channel",
        approver=approver,
        origin="operator_override",
        justification=justification,
    )
