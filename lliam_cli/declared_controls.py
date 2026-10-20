"""Fail-closed checks for security controls the governance overlay declares.

``cli-config.gov.yaml`` turns on several ``security.*`` / ``delegation.*``
switches. Each one is enforced on its own runtime path:

* ``delegation.max_spawn_depth`` — ``tools/delegate_tool.py`` (in-process and,
  via ``agent/delegation_depth.py``, across spawned processes).
* ``security.spend_ceiling`` — the model-call loop
  (``lliam_cli/model_cost_guard.py``).

This module holds :func:`enforce_declared_controls_at_startup`, a one-shot
configuration check that raises under strict posture when one of these
controls is configured in a way that cannot be enforced.

NOTE: ``enforce_declared_controls_at_startup`` is not yet called from a
startup sequence. It should be added to ``enforce_startup_posture`` in
``lliam_cli/startup_posture.py`` once that module (PR #116) merges. Until
then each control still fails closed on its own runtime path.
"""

from __future__ import annotations

import logging
from typing import List, Optional

logger = logging.getLogger("hermes.governance.declared_controls")


class DeclaredControlError(RuntimeError):
    """A declared security control cannot be enforced under strict posture."""


def _load(config: Optional[dict]) -> dict:
    if isinstance(config, dict) and config:
        return config
    try:
        from lliam_cli.config import load_config

        return load_config()
    except Exception:
        return config or {}


def _is_strict(config: Optional[dict]) -> bool:
    try:
        from lliam_cli import posture_resolver as _pr

        return bool(_pr.is_strict(config))
    except Exception:
        return True


# --------------------------------------------------------------------------- #
# One-shot startup configuration check
# --------------------------------------------------------------------------- #

def declared_control_findings(config: Optional[dict] = None) -> List[str]:
    """Configuration problems that make a declared control unenforceable."""
    cfg = _load(config)
    findings: List[str] = []

    deleg = cfg.get("delegation") if isinstance(cfg, dict) else None
    if isinstance(deleg, dict) and "max_spawn_depth" in deleg:
        val = deleg.get("max_spawn_depth")
        if isinstance(val, bool) or not isinstance(val, int) or val < 1:
            findings.append(
                f"delegation.max_spawn_depth={val!r} is not an integer >= 1"
            )

    try:
        from lliam_cli.model_cost_guard import SpendCeilingConfigError, load_spend_ceiling

        try:
            load_spend_ceiling(cfg)
        except SpendCeilingConfigError as exc:
            findings.append(str(exc))
    except Exception as exc:  # pragma: no cover - import failure
        findings.append(f"security.spend_ceiling could not be evaluated: {exc}")

    return findings


def enforce_declared_controls_at_startup(config: Optional[dict] = None) -> Optional[List[str]]:
    """Raise :class:`DeclaredControlError` under strict posture on any finding.

    Low-side posture: findings are logged and returned. Returns None when
    there is nothing to report. See the module NOTE about wiring this into
    ``enforce_startup_posture`` after PR #116.
    """
    cfg = _load(config)
    findings = declared_control_findings(cfg)
    if not findings:
        return None
    if _is_strict(cfg):
        for f in findings:
            logger.critical("[declared-controls] BLOCKING: %s", f)
        raise DeclaredControlError("; ".join(findings))
    for f in findings:
        logger.warning("[declared-controls] (advisory, not strict) %s", f)
    return findings


__all__ = [
    "DeclaredControlError",
    "declared_control_findings",
    "enforce_declared_controls_at_startup",
]
