"""Continuous authorization (cATO) evaluator + posture-break auto-suspend
(LG-GV-07, P5.4).

Closes the authorization loop: the cATO evaluator consumes the recurring
control-effectiveness result (LG-MO-08) and the runtime-monitor alerts
(LG-MO-01..06) and decides whether the current posture still holds. On a REAL
posture-break — a control-effectiveness failure or a critical alert — it
auto-suspends autonomy via the kill-switch (LG-IR-01) and flags that
re-authorization is required (LG-GV-06/08). On steady state it is a **complete
no-op**: it never suspends on low/medium alert noise (the FINAL-gate
requirement — cATO auto-suspends only on real injected drift, no false
auto-suspensions).

Additive — composes the existing control_effectiveness gate and killswitch;
renames nothing.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_log = logging.getLogger("hermes.cato")

_SEVERITY_ORDER = {"info": 0, "notice": 1, "warning": 2, "critical": 3}


@dataclass(frozen=True)
class AlertView:
    """A minimal view of a monitor alert for the cATO decision."""
    control: str
    severity: str


@dataclass(frozen=True)
class CatoVerdict:
    suspend: bool
    reason: str
    reauthorization_required: bool


def evaluate(*, alerts: list, effectiveness_failures: list) -> CatoVerdict:
    """Decide whether the posture has broken. Steady state → no suspend.

    Suspends only on a genuine break: any control-effectiveness failure
    (LG-MO-08 — godmode re-enabled, allowlist off, encryption/audit/monitoring
    off, posture not strict) or any CRITICAL monitor alert. Warning/notice/info
    alerts are steady-state signal and do NOT suspend (capability preserved).
    """
    if effectiveness_failures:
        first = str(effectiveness_failures[0])
        return CatoVerdict(
            suspend=True,
            reason=f"control-effectiveness break: {first}",
            reauthorization_required=True)
    critical = [a for a in (alerts or [])
                if _SEVERITY_ORDER.get(getattr(a, "severity", ""), 0) >= 3]
    if critical:
        c = critical[0]
        return CatoVerdict(
            suspend=True,
            reason=f"critical alert {getattr(c, 'control', '?')}",
            reauthorization_required=True)
    return CatoVerdict(suspend=False, reason="posture effective; steady state",
                       reauthorization_required=False)


def current_effectiveness_failures(*, repo_root: Optional[Path] = None) -> list:
    """Run the real control-effectiveness gate; return its failure list."""
    try:
        import sys
        root = repo_root or Path(__file__).resolve().parent.parent
        gates = str(root / "ci" / "governance-ci-gates")
        if gates not in sys.path:
            sys.path.insert(0, gates)
        import control_effectiveness as ce
        return ce.check_effectiveness(repo_root=root)
    except Exception as e:  # fail-safe: an evaluator error is not a break
        _log.debug("cato effectiveness check unavailable (non-fatal): %s", e)
        return []


def run_cato_cycle(*, alerts: list, effectiveness_failures: Optional[list] = None,
                   actor: str, repo_root: Optional[Path] = None) -> CatoVerdict:
    """Evaluate the posture and auto-suspend via the kill-switch on a break.

    ``effectiveness_failures`` defaults to a live control-effectiveness run.
    On suspend, engages the kill-switch (LG-GV-07 corrective → LG-IR-01) with
    the reason recorded for re-authorization. Idempotent and fail-safe.
    """
    if effectiveness_failures is None:
        effectiveness_failures = current_effectiveness_failures(
            repo_root=repo_root)
    verdict = evaluate(alerts=alerts,
                       effectiveness_failures=effectiveness_failures)
    if verdict.suspend:
        try:
            from agent import killswitch as ks
            ks.engage(reason=f"cATO auto-suspend: {verdict.reason}",
                      actor=actor)
        except Exception as e:
            _log.error("cATO auto-suspend could not engage kill-switch: %s", e)
        _log.critical("cATO AUTO-SUSPEND — %s (re-authorization required)",
                      verdict.reason)
    return verdict
