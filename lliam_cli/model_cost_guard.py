"""Model cost guards: expensive-model confirmation and the inference spend ceiling."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

from agent.models_dev import ModelInfo


INPUT_COST_WARNING_THRESHOLD = Decimal("20")
OUTPUT_COST_WARNING_THRESHOLD = Decimal("100")
GPT55_PRO_OPENROUTER_ID = "openai/gpt-5.5-pro"
GPT55_SUGGESTION = "did you mean to select openai/gpt-5.5?"


@dataclass(frozen=True)
class ExpensiveModelWarning:
    """Confirmation payload for models above Lliam-GOV' cost guardrail."""

    model: str
    provider: str
    input_cost_per_million: Optional[Decimal]
    output_cost_per_million: Optional[Decimal]
    source: str
    message: str


def _to_decimal(value: object) -> Optional[Decimal]:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _format_money(value: Optional[Decimal]) -> str:
    if value is None:
        return "unknown"
    return f"${value:.2f}/M"


def _pricing_from_model_info(
    model_info: Optional[ModelInfo],
) -> tuple[Optional[Decimal], Optional[Decimal], str]:
    if model_info is None or not model_info.has_cost_data():
        return None, None, ""
    return (
        _to_decimal(model_info.cost_input),
        _to_decimal(model_info.cost_output),
        "models.dev",
    )


def expensive_model_warning(
    model_name: str,
    *,
    provider: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    model_info: Optional[ModelInfo] = None,
) -> Optional[ExpensiveModelWarning]:
    """Return a warning payload when known pricing exceeds safety thresholds.

    The guard only triggers when pricing is known. Callers should use this after
    model resolution so aliases and provider-specific model IDs have settled.
    """
    model = (model_name or "").strip()
    if not model:
        return None

    input_cost, output_cost, source = _pricing_from_model_info(model_info)
    if input_cost is None and output_cost is None and provider:
        try:
            from agent.models_dev import get_model_info

            input_cost, output_cost, source = _pricing_from_model_info(
                get_model_info(provider, model)
            )
        except Exception:
            pass
    if input_cost is None and output_cost is None:
        try:
            from agent.usage_pricing import get_pricing_entry

            entry = get_pricing_entry(
                model,
                provider=provider,
                base_url=base_url,
                api_key=api_key,
            )
        except Exception:
            entry = None
        if entry is not None:
            input_cost = entry.input_cost_per_million
            output_cost = entry.output_cost_per_million
            source = entry.source

    over_input = (
        input_cost is not None and input_cost > INPUT_COST_WARNING_THRESHOLD
    )
    over_output = (
        output_cost is not None and output_cost > OUTPUT_COST_WARNING_THRESHOLD
    )
    if not over_input and not over_output:
        return None

    lines = [
        "!!! EXPENSIVE MODEL WARNING !!!",
        "",
        f"{model} has known pricing above Lliam-GOV' safety threshold.",
        f"Input tokens: {_format_money(input_cost)}",
        f"Output tokens: {_format_money(output_cost)}",
        (
            "Threshold: more than $20/M input tokens or more than "
            "$100/M output tokens."
        ),
    ]
    if source:
        lines.append(f"Pricing source: {source}.")
    if model.lower() == GPT55_PRO_OPENROUTER_ID:
        lines.append(GPT55_SUGGESTION)
    lines.append("Confirm only if you intend to use this model.")

    return ExpensiveModelWarning(
        model=model,
        provider=(provider or "").strip(),
        input_cost_per_million=input_cost,
        output_cost_per_million=output_cost,
        source=source or "unknown",
        message="\n".join(lines),
    )


# ---------------------------------------------------------------------------
# Inference spend ceiling (security.spend_ceiling)
# ---------------------------------------------------------------------------
#
# ``tool_loop_guardrails`` / ``security.max_mutating_calls`` bound tool calls;
# nothing bounded model spend. When ``security.spend_ceiling.enabled`` is true,
# the agent loop checks the ceiling BEFORE every model API call
# (``check_spend_before_call``) and accounts usage AFTER every response
# (``record_spend``):
#
#   * per session — tokens (input + output + cache read/write) and, when the
#     price is known, estimated USD. The tracker is shared down the delegation
#     tree, so subagents spend from their parent's session allowance.
#   * per day (UTC) — summed from the session DB across every session started
#     today; falls back to an in-process tally when no session DB is attached.
#
# A breach routes to HITL (``on_breach: hitl_approve``): the operator is asked
# through the existing approval surfaces (gateway approval queue, or the CLI
# approval prompt). An approval buys one more increment of the breached
# ceiling, measured from current usage. A denial, a timeout, a subagent
# (no human surface on its thread) or a session with no approver at all stops
# the turn before the call is made: fail closed. YOLO / approvals.mode=off /
# smart approval do not apply — a spend approval must come from a person.

_spend_logger = logging.getLogger("hermes.governance.spend_ceiling")

_APPROVED_CHOICES = frozenset({"once", "session", "always"})
_ON_BREACH_VALUES = frozenset({"hitl_approve", "deny"})
_SPEND_GATE = "inference.spend_ceiling"


class SpendCeilingConfigError(ValueError):
    """security.spend_ceiling is enabled but malformed."""


@dataclass(frozen=True)
class SpendCeilingConfig:
    enabled: bool = False
    per_session_tokens: Optional[int] = None
    per_day_tokens: Optional[int] = None
    per_session_cost_usd: Optional[float] = None
    per_day_cost_usd: Optional[float] = None
    on_breach: str = "hitl_approve"


def _positive_number(block: dict, key: str, *, integer: bool) -> Optional[float]:
    value = block.get(key)
    if value is None:
        return None
    if isinstance(value, bool):
        raise SpendCeilingConfigError(f"security.spend_ceiling.{key}={value!r} is not a number")
    try:
        number = int(value) if integer else float(value)
    except (TypeError, ValueError):
        raise SpendCeilingConfigError(
            f"security.spend_ceiling.{key}={value!r} is not a number"
        ) from None
    if integer and float(value) != number:
        raise SpendCeilingConfigError(f"security.spend_ceiling.{key}={value!r} is not an integer")
    if number <= 0:
        raise SpendCeilingConfigError(f"security.spend_ceiling.{key}={value!r} must be > 0")
    return number


def load_spend_ceiling(config: Optional[dict] = None) -> SpendCeilingConfig:
    """Resolve ``security.spend_ceiling``. Raises SpendCeilingConfigError when
    it is enabled but malformed or sets no limit at all."""
    if config is None:
        from lliam_cli.config import load_config_readonly

        config = load_config_readonly()
    sec = config.get("security") if isinstance(config, dict) else None
    block = sec.get("spend_ceiling") if isinstance(sec, dict) else None
    if block is None:
        return SpendCeilingConfig(enabled=False)
    if not isinstance(block, dict):
        raise SpendCeilingConfigError("security.spend_ceiling must be a mapping")
    if not block.get("enabled"):
        return SpendCeilingConfig(enabled=False)
    on_breach = str(block.get("on_breach") or "hitl_approve").strip().lower()
    if on_breach not in _ON_BREACH_VALUES:
        raise SpendCeilingConfigError(
            f"security.spend_ceiling.on_breach={on_breach!r} must be one of "
            f"{sorted(_ON_BREACH_VALUES)}"
        )
    cfg = SpendCeilingConfig(
        enabled=True,
        per_session_tokens=_positive_number(block, "per_session_tokens", integer=True),
        per_day_tokens=_positive_number(block, "per_day_tokens", integer=True),
        per_session_cost_usd=_positive_number(block, "per_session_cost_usd", integer=False),
        per_day_cost_usd=_positive_number(block, "per_day_cost_usd", integer=False),
        on_breach=on_breach,
    )
    if not any(
        v is not None
        for v in (cfg.per_session_tokens, cfg.per_day_tokens,
                  cfg.per_session_cost_usd, cfg.per_day_cost_usd)
    ):
        raise SpendCeilingConfigError(
            "security.spend_ceiling.enabled is true but no ceiling is set "
            "(per_session_tokens / per_day_tokens / per_session_cost_usd / "
            "per_day_cost_usd)"
        )
    return cfg


def _utc_day_start(now: Optional[float] = None) -> Tuple[str, float]:
    dt = datetime.fromtimestamp(time.time() if now is None else now, tz=timezone.utc)
    start = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.date().isoformat(), start.timestamp()


# Process-wide daily state: in-process tally (used when no session DB is
# attached) and operator-approved extensions, keyed by UTC date.
_DAILY_LOCK = threading.Lock()
_DAILY_TALLY: Dict[str, List[float]] = {}        # date -> [tokens, cost_usd]
_DAILY_EXTENSION: Dict[str, List[float]] = {}    # date -> [tokens, cost_usd]


def reset_spend_state() -> None:
    """Clear process-wide daily spend state (tests)."""
    with _DAILY_LOCK:
        _DAILY_TALLY.clear()
        _DAILY_EXTENSION.clear()


class SpendTracker:
    """Per-session spend shared by an agent and its delegated children."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.tokens = 0
        self.cost_usd = 0.0
        # Operator-approved allowance on top of the configured ceiling.
        self.extra_tokens = 0
        self.extra_cost_usd = 0.0

    def record(self, tokens: int, cost_usd: Optional[float]) -> None:
        tokens = max(0, int(tokens or 0))
        cost = float(cost_usd) if cost_usd is not None else 0.0
        with self._lock:
            self.tokens += tokens
            self.cost_usd += max(0.0, cost)
        day, _ = _utc_day_start()
        with _DAILY_LOCK:
            tally = _DAILY_TALLY.setdefault(day, [0, 0.0])
            tally[0] += tokens
            tally[1] += max(0.0, cost)


def ensure_spend_tracker(agent: Any) -> SpendTracker:
    tracker = getattr(agent, "_spend_tracker", None)
    if isinstance(tracker, SpendTracker):
        return tracker
    tracker = SpendTracker()
    try:
        agent._spend_tracker = tracker
    except Exception:
        pass
    return tracker


def _daily_usage(agent: Any) -> Tuple[float, float]:
    """(tokens, cost_usd) spent today (UTC)."""
    day, start_ts = _utc_day_start()
    db = getattr(agent, "_session_db", None)
    if db is not None and hasattr(db, "usage_since"):
        try:
            usage = db.usage_since(start_ts)
            return float(usage.get("tokens", 0)), float(usage.get("cost_usd", 0.0))
        except Exception:
            _spend_logger.debug("session DB daily usage unavailable", exc_info=True)
    with _DAILY_LOCK:
        tally = _DAILY_TALLY.get(day, [0, 0.0])
        return float(tally[0]), float(tally[1])


def _breaches(cfg: SpendCeilingConfig, tracker: SpendTracker, daily: Tuple[float, float]) -> List[Tuple[str, float, float]]:
    """List of (kind, used, limit) for every ceiling reached."""
    day, _ = _utc_day_start()
    with _DAILY_LOCK:
        ext = list(_DAILY_EXTENSION.get(day, [0, 0.0]))
    out: List[Tuple[str, float, float]] = []
    with tracker._lock:
        if cfg.per_session_tokens is not None:
            limit = cfg.per_session_tokens + tracker.extra_tokens
            if tracker.tokens >= limit:
                out.append(("session_tokens", tracker.tokens, limit))
        if cfg.per_session_cost_usd is not None:
            limit = cfg.per_session_cost_usd + tracker.extra_cost_usd
            if tracker.cost_usd >= limit:
                out.append(("session_cost_usd", tracker.cost_usd, limit))
    if cfg.per_day_tokens is not None:
        limit = cfg.per_day_tokens + ext[0]
        if daily[0] >= limit:
            out.append(("day_tokens", daily[0], limit))
    if cfg.per_day_cost_usd is not None:
        limit = cfg.per_day_cost_usd + ext[1]
        if daily[1] >= limit:
            out.append(("day_cost_usd", daily[1], limit))
    return out


def _grant(cfg: SpendCeilingConfig, tracker: SpendTracker, breaches) -> None:
    """Extend each breached ceiling by one increment beyond current usage."""
    day, _ = _utc_day_start()
    for kind, used, limit in breaches:
        if kind == "session_tokens":
            with tracker._lock:
                tracker.extra_tokens += int(used - limit) + int(cfg.per_session_tokens)
        elif kind == "session_cost_usd":
            with tracker._lock:
                tracker.extra_cost_usd += (used - limit) + float(cfg.per_session_cost_usd)
        elif kind == "day_tokens":
            with _DAILY_LOCK:
                _DAILY_EXTENSION.setdefault(day, [0, 0.0])[0] += (used - limit) + cfg.per_day_tokens
        elif kind == "day_cost_usd":
            with _DAILY_LOCK:
                _DAILY_EXTENSION.setdefault(day, [0, 0.0])[1] += (used - limit) + cfg.per_day_cost_usd


def _fmt(kind: str, value: float) -> str:
    return f"${value:,.2f}" if kind.endswith("cost_usd") else f"{int(value):,} tokens"


def _describe(breaches) -> str:
    labels = {
        "session_tokens": "session token ceiling",
        "session_cost_usd": "session cost ceiling",
        "day_tokens": "daily token ceiling",
        "day_cost_usd": "daily cost ceiling",
    }
    return "; ".join(
        f"{labels.get(kind, kind)} reached ({_fmt(kind, used)} of {_fmt(kind, limit)})"
        for kind, used, limit in breaches
    )


def _record(decision: str, target: str, description: str, origin: str) -> None:
    try:
        from tools.hitl_oversight import record_decision

        record_decision(
            decision=decision, gate=_SPEND_GATE, target=target,
            description=description, origin=origin,
        )
    except Exception:
        _spend_logger.debug("spend decision not recorded", exc_info=True)


def request_spend_approval(agent: Any, summary: str, description: str) -> Tuple[bool, str]:
    """Ask a human to approve continued spend. Returns (approved, origin).

    Uses the gateway approval queue in gateway sessions and the CLI approval
    prompt in interactive CLI sessions. Anything else has no approver and is
    refused.
    """
    try:
        local_depth = int(getattr(agent, "_delegate_depth", 0) or 0)
    except Exception:
        local_depth = 1
    if local_depth > 0:
        # Subagent threads carry a non-interactive approval callback; a spend
        # approval must not be auto-resolved by it.
        return False, "subagent_no_approver"
    try:
        from tools import approval as _ap
        from utils import env_var_enabled
    except Exception:
        return False, "approval_unavailable"

    approval_data = {
        "command": summary,
        "pattern_key": "spend_ceiling",
        "pattern_keys": ["spend_ceiling"],
        "description": description,
    }
    session_key = _ap.get_current_session_key()
    try:
        if _ap._is_gateway_approval_context():
            with _ap._lock:
                notify_cb = _ap._gateway_notify_cbs.get(session_key)
            if notify_cb is None:
                return False, "gateway_no_notifier"
            decision = _ap._await_gateway_decision(
                session_key, notify_cb, approval_data, surface="gateway"
            )
            approved = bool(decision.get("resolved")) and decision.get("choice") in _APPROVED_CHOICES
            return approved, "gateway"
        if env_var_enabled("HERMES_INTERACTIVE"):
            try:
                from tools.terminal_tool import _get_approval_callback

                callback = _get_approval_callback()
            except Exception:
                callback = None
            choice = _ap.prompt_dangerous_approval(
                summary, description, allow_permanent=False, approval_callback=callback,
            )
            return choice in _APPROVED_CHOICES, "interactive_prompt"
    except Exception:
        _spend_logger.error("spend approval request failed; denying", exc_info=True)
        return False, "approval_error"
    return False, "no_approver"


def _ceiling_config_or_error() -> Tuple[Optional[SpendCeilingConfig], Optional[str]]:
    try:
        return load_spend_ceiling(), None
    except SpendCeilingConfigError as exc:
        strict = True
        try:
            from lliam_cli import posture_resolver as _pr
            from lliam_cli.config import load_config_readonly

            strict = bool(_pr.is_strict(load_config_readonly()))
        except Exception:
            pass
        if strict:
            return None, (
                f"Model call refused: {exc}. Failing closed under strict posture."
            )
        _spend_logger.warning("%s; spend ceiling disabled (advisory, not strict)", exc)
        return None, None
    except Exception:
        _spend_logger.debug("spend ceiling config unavailable", exc_info=True)
        return None, None


def check_spend_before_call(agent: Any) -> Optional[str]:
    """Gate one model API call. None = proceed; a string = refuse (stop the turn)."""
    cfg, error = _ceiling_config_or_error()
    if error:
        return error
    if cfg is None or not cfg.enabled:
        return None
    tracker = ensure_spend_tracker(agent)
    breaches = _breaches(cfg, tracker, _daily_usage(agent))
    if not breaches:
        return None
    description = _describe(breaches)
    summary = f"Continue model calls past the inference spend ceiling: {description}"
    if cfg.on_breach == "deny":
        _record("deny", summary, description, "policy_deny")
        return (
            f"Stopped: inference spend ceiling reached — {description}. "
            "security.spend_ceiling.on_breach is deny."
        )
    _spend_logger.warning("spend ceiling breach: %s — requesting approval", description)
    approved, origin = request_spend_approval(agent, summary, description)
    if approved:
        _grant(cfg, tracker, breaches)
        _record("approve", summary, description, origin)
        return None
    _record("deny", summary, description, origin)
    reason = {
        "subagent_no_approver": "subagents cannot obtain spend approval; the parent agent will ask the operator",
        "gateway_no_notifier": "no approval channel is registered for this gateway session",
        "no_approver": "no approver is present in this session",
        "approval_unavailable": "the approval system is unavailable",
        "approval_error": "the approval request failed",
    }.get(origin, "the operator did not approve")
    return (
        f"Stopped: inference spend ceiling reached — {description}. "
        f"Further model calls were denied ({reason}). "
        "Approval is required to continue (security.spend_ceiling)."
    )


def record_spend(agent: Any, total_tokens: int, cost_usd: Optional[float]) -> None:
    """Account one API response against the session/day ceilings. Never raises."""
    try:
        cfg, _error = _ceiling_config_or_error()
        if cfg is None or not cfg.enabled:
            return
        ensure_spend_tracker(agent).record(total_tokens, cost_usd)
    except Exception:
        _spend_logger.debug("spend accounting failed", exc_info=True)
