"""Fail-closed handling for a governance gate that raises at a dispatch seam.

The governance gates (``predispatch_gate`` and friends) are contracted never to
raise. When one does anyway, the call sites in ``agent.tool_executor`` and
``model_tools`` must not read the exception as "allow": under strict posture
the call is denied and surfaced through the existing guardrail-block path, so
it is recorded like any other blocked call. Low-side profiles keep the gates'
non-blocking convention (the exception is logged and the call proceeds).

Deliberately self-contained (no import of the gate modules) so it still works
when the failure was the gate module's own import.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _is_strict() -> bool:
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr
        return _pr.is_strict(_cfg.load_config())
    except Exception:
        logger.warning(
            "governance gate-error posture resolution failed; enforcing strict controls",
            exc_info=True,
        )
        return True


def gate_error_decision(function_name: str, gate: str, error: BaseException) -> Optional[Any]:
    """Decision for a dispatch-seam governance gate that raised ``error``.

    Returns a blocking ``ToolGuardrailDecision`` (action="halt") under strict
    posture; None on low-side profiles.
    """
    if not _is_strict():
        logger.warning(
            "governance %s error (non-blocking, low-side) for %s: %s",
            gate, function_name, error,
        )
        return None
    logger.error(
        "governance %s raised for %s — failing closed (strict posture): %s",
        gate, function_name, error,
    )
    from agent.tool_guardrails import ToolGuardrailDecision
    return ToolGuardrailDecision(
        action="halt",
        code="governance_gate_error",
        message=(
            f"Blocked (fail-closed): the governance {gate} raised before "
            "dispatch and strict posture does not allow an unevaluated "
            f"call to execute. Underlying error: {error}"
        ),
        tool_name=(function_name or "").strip(),
    )
