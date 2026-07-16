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

Low-side postures: ``strict_fail_closed()`` is False and nothing here changes
shipped behavior (capability preserving).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("hermes.governance.hitl_oversight")

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
    """True when strict posture requires fail-closed HITL (LG-HO-02/06)."""
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr
        return _pr.is_strict(_cfg.load_config())
    except Exception:
        return False


def record_decision(
    *,
    decision: str,                    # approve | deny | halt | timeout | n/a
    gate: str,                        # which gate decided (e.g. shell.dangerous)
    target: str = "",                 # command / path / capability
    description: str = "",            # risk rationale (LG-HO-08)
    approver: Optional[str] = None,   # authenticated principal, if any
    origin: str = "",                 # non_interactive_fail_closed | interactive_prompt | gateway | jit_grant | operator_override
    justification: str = "",
) -> None:
    """Emit one ``approval.decision`` record (LG-HO-10). Never raises."""
    try:
        from agent.governance_audit_hooks import _current_subject, _enabled_ledger
        ledger = _enabled_ledger()
        if ledger is None:
            return
        ledger.emit(
            "approval.decision",
            action=f"approval.{gate}",
            decision=decision,
            subject=_current_subject(),
            approver={"id": approver} if approver else {},
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


def operator_override(
    action_class: str,
    *,
    approver: str,
    justification: str,
    ttl_seconds: Optional[int] = None,
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
    from tools import tool_policy as tp
    policy = tp._load_risk_policy()
    tier = tp._class_tiers(policy).get(str(action_class).strip()) if isinstance(policy, dict) else None
    if tier == "deny":
        raise ValueError(
            f"deny-tier class '{action_class}' cannot be overridden — deny is "
            "terminal (LG-HO-03); no toggle, grant, or override re-enables it"
        )
    tp.grant_capability(str(action_class).strip(), approver=approver, ttl_seconds=ttl_seconds)
    record_decision(
        decision="approve",
        gate=str(action_class).strip(),
        target=str(action_class).strip(),
        description="operator override / appeal channel",
        approver=approver,
        origin="operator_override",
        justification=justification,
    )
