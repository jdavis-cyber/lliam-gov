"""tools/injection_defense.py — Lliam-GOV runtime injection + output handling (P2.3).

ADDITIVE OVERLAY MODULE (PATH-FREEZE). Realizes the content-gating controls:

  * LG-PI-04 — detect prompt-injection / content-threats in tool & MCP RESULTS
    (indirect injection: a fetched page or tool output that carries adversarial
    instructions), reusing the existing tools/threat_patterns engine.
  * LG-PI-06 — classify results; a high-risk result TAINTS the session so a
    SUBSEQUENT egress/exec action does not auto-proceed — it is escalated to
    the P2.2 HITL gate (via the P2.1 PDP). The agent keeps reading/analyzing;
    only the dangerous downstream side effect pauses for a human.
  * LG-PI-09 — validate tool output before it reaches a downstream
    sink/egress/exec (``validate_output_sink``).

Capability preservation: complete no-op on low-side postures; taint escalates
ONLY egress/exec side-effect classes to HITL (never reads/analysis), and it is
an escalation to approval, never a blanket block. The taint is per-session and
cleared by ``reset_injection_state()`` (session-reset policy).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger("hermes.governance.injection_defense")

# Action classes that carry a dangerous side effect off the back of tool
# output. A session that has observed indirect injection escalates THESE to
# hitl_approve; reads/analysis/in-safe-root writes are unaffected.
_SIDE_EFFECT_CLASSES = frozenset({
    "network.egress",
    "external_send",
    "shell.non_destructive", "shell.destructive",
    "file_write.outside_safe_root",
    "browser.unlisted_or_action",
})

# Runtime-session keyed taint. A gateway process can host many users, and an
# indirect-injection finding in one session must neither gate nor clear another.
_STATES: Dict[str, Dict[str, object]] = {}


def _state(session_id: Optional[str] = None) -> Dict[str, object]:
    return _STATES.setdefault(
        str(session_id or "default"), {"tainted": False, "matched": None}
    )


def _is_strict() -> bool:
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr
        return _pr.is_strict(_cfg.load_config())
    except Exception:
        return False


@dataclass(frozen=True)
class ResultClassification:
    """LG-PI-06 classification of one tool/MCP result."""

    risk: str                 # low | high
    matched: Optional[str]    # the first threat message, if any


@dataclass(frozen=True)
class SinkValidation:
    """LG-PI-09 verdict for content about to reach a downstream sink."""

    blocked: bool
    matched: Optional[str]


def reset_injection_state(session_id: Optional[str] = None) -> None:
    """Clear session injection taint (session-reset policy / tests)."""
    if session_id is None:
        _STATES.clear()
    else:
        _STATES.pop(str(session_id or "default"), None)


def _first_threat(content: str) -> Optional[str]:
    """First injection/threat message in content, or None. Never raises."""
    if not content:
        return None
    try:
        from tools.threat_patterns import first_threat_message
        # "context" scope covers classic injection + C2/promptware in fetched
        # content (the indirect-injection surface), without the memory/skill-
        # only "strict" persistence patterns.
        return first_threat_message(content, scope="context")
    except Exception:
        logger.warning("injection_defense threat scan failed; treating as clean", exc_info=True)
        return None


def classify_tool_result(tool_name: str, result: str) -> ResultClassification:
    """LG-PI-04/06: classify a tool/MCP result. No-op (low) on low-side."""
    if not _is_strict():
        return ResultClassification(risk="low", matched=None)
    matched = _first_threat(result or "")
    if matched:
        logger.warning(
            "LG-PI-04: indirect-injection content in result of '%s' — %s",
            tool_name, matched,
        )
        return ResultClassification(risk="high", matched=matched)
    return ResultClassification(risk="low", matched=None)


def note_tool_result(
    tool_name: str, result: str, *, session_id: Optional[str] = None
) -> ResultClassification:
    """Classify a result and taint the session on a high-risk finding (LG-PI-06).

    Returns the classification. Called at the tool-result seam so the taint is
    set BEFORE the model's next action is dispatched.
    """
    c = classify_tool_result(tool_name, result)
    if c.risk == "high":
        state = _state(session_id)
        state["tainted"] = True
        state["matched"] = c.matched
    return c


def session_injection_tainted(*, session_id: Optional[str] = None) -> bool:
    """True when this session has observed indirect-injection content."""
    return bool(_state(session_id)["tainted"])


def injection_taint_reason(*, session_id: Optional[str] = None) -> Optional[str]:
    value = _state(session_id)["matched"]
    return str(value) if value is not None else None


def should_escalate_for_injection(
    action_class: str, *, session_id: Optional[str] = None
) -> bool:
    """LG-PI-06: True when a tainted session must route this class to HITL.

    Only the dangerous side-effect classes escalate; reads/analysis proceed so
    the agent can keep working with the (now-suspect) content.
    """
    if not _is_strict() or not session_injection_tainted(session_id=session_id):
        return False
    return str(action_class).strip() in _SIDE_EFFECT_CLASSES


def validate_output_sink(content: str, *, sink: str = "") -> SinkValidation:
    """LG-PI-09: validate content before it reaches a downstream sink.

    No-op (not blocked) on low-side. Under strict posture, content carrying
    injection/exfiltration markers is blocked from an egress/exec sink and the
    caller routes it to HITL instead.
    """
    if not _is_strict():
        return SinkValidation(blocked=False, matched=None)
    matched = _first_threat(content or "")
    if matched:
        logger.warning(
            "LG-PI-09: blocking injected content from sink '%s' — %s", sink, matched,
        )
        return SinkValidation(blocked=True, matched=matched)
    return SinkValidation(blocked=False, matched=None)
