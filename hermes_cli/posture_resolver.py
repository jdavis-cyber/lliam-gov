"""hermes_cli/posture_resolver.py — Lliam-GOV strict-posture coherence.

ADDITIVE OVERLAY MODULE — no existing Hermes/Lliam module, file, CLI command, or
identifier is renamed, moved, or refactored by anything in here. (PATH-FREEZE.)

Realizes:
  * LG-CH-02 — single strict-posture switch (``security.posture: strict``) that
    coherently coerces the fail-open guards to fail-closed, so the secure state
    cannot be reached by accidental half-configuration.
  * LG-CH-09 — stamp a signal that critical startup posture findings are
    *blocking* (not advisory) under strict posture; the startup gate
    (security_audit_startup, a later Phase-0 step) reads this signal.

How it is wired (capability-preserving, additive):
  ``resolve(config)`` is called at config-load post-processing inside
  ``hermes_cli/config._load_config_impl`` — AFTER the user + governance-overlay +
  managed merge and env expansion — so its coercions win over every config source.
  Permissive (non-gov) deployments never set ``security.posture``; the resolver is
  a strict no-op for them (returns the config unchanged, applies nothing). Only the
  governance overlay (cli-config.gov.yaml) sets ``posture: strict``.

Design notes:
  * Deterministic + idempotent: applying twice yields the same result.
  * Never raises into the config-load path. A resolver fault must not brick every
    ``hermes`` invocation; on unexpected error it logs and returns the config
    untouched. The *enforcement* of fail-closed blocking lives in the dedicated
    startup gate; this module only renders the coherent fail-closed config + the
    blocking signal it consumes.
  * The coercion table is data-driven so later Phase-0 steps can extend it (e.g.
    website-policy fail-closed in the egress phase) without restructuring.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hermes.governance.posture")

STRICT = "strict"

# Coercion table: (dotted path under the loaded config, value to force when
# posture == strict, short human reason). Every key here already exists in
# Hermes DEFAULT_CONFIG except ``security.deny_on_no_approver``, which is an
# additive governance key consumed by the approval path (a later Phase-0/2 step).
# Forcing it here makes the no-approver branch fail-closed under strict posture.
_STRICT_COERCIONS: Tuple[Tuple[str, Any, str], ...] = (
    ("security.tirith_fail_open", False,
     "content scanner fails CLOSED (a missing/timed-out tirith routes to approval/deny, never auto-allow)"),
    ("security.allow_private_urls", False,
     "SSRF/private-IP/metadata egress stays blocked"),
    ("security.allow_lazy_installs", False,
     "no runtime PyPI installs (air-gap / supply-chain integrity)"),
    ("security.deny_on_no_approver", True,
     "high-risk actions fail CLOSED when no human approver is reachable"),
)

# Where the LG-CH-09 'findings are blocking' signal is stamped, so the startup
# posture gate (built in a later step) can read it without re-deriving posture.
_FINDINGS_BLOCKING_PATH = "security.posture_findings_blocking"


@dataclass
class Coercion:
    key: str
    old: Any
    new: Any
    reason: str


@dataclass
class PostureResolution:
    posture: Optional[str]
    strict: bool
    coercions: List[Coercion] = field(default_factory=list)
    findings_blocking: bool = False

    def summary(self) -> str:
        if not self.strict:
            return f"posture={self.posture!r} (permissive; no coercion applied)"
        changed = ", ".join(
            f"{c.key}: {c.old!r}->{c.new!r}" for c in self.coercions
        ) or "(already coherent — nothing to change)"
        return (
            f"posture='strict' findings_blocking={self.findings_blocking} "
            f"coercions[{len(self.coercions)}]: {changed}"
        )


# Module-level record of the most recent resolution (per-process). Lets a CLI /
# verification read what the resolver did without re-loading. Also gates one-shot
# logging so a cached config-load hot path does not spam the log every call.
LAST_RESOLUTION: Optional[PostureResolution] = None
_LOGGED_ONCE = False


def _get(config: Dict[str, Any], dotted: str) -> Any:
    cur: Any = config
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _set(config: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = config
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def get_posture(config: Optional[Dict[str, Any]]) -> Optional[str]:
    """Return the configured ``security.posture`` (lower-cased) or None."""
    if not isinstance(config, dict):
        return None
    val = _get(config, "security.posture")
    if val is None:
        return None
    return str(val).strip().lower()


def is_strict(config: Optional[Dict[str, Any]]) -> bool:
    return get_posture(config) == STRICT


def resolve(config: Dict[str, Any]) -> PostureResolution:
    """Coerce fail-open guards to fail-closed when ``security.posture == strict``.

    Mutates ``config`` in place and returns a :class:`PostureResolution` record.
    No-op (no mutation) unless posture is strict. Never raises into the caller.
    """
    global LAST_RESOLUTION, _LOGGED_ONCE

    try:
        posture = get_posture(config)
    except Exception:  # pragma: no cover - defensive
        return PostureResolution(posture=None, strict=False)

    if posture != STRICT:
        res = PostureResolution(posture=posture, strict=False)
        LAST_RESOLUTION = res
        return res

    res = PostureResolution(posture=STRICT, strict=True, findings_blocking=True)
    try:
        for key, forced, reason in _STRICT_COERCIONS:
            old = _get(config, key)
            if old != forced:
                _set(config, key, forced)
                res.coercions.append(Coercion(key=key, old=old, new=forced, reason=reason))
        # LG-CH-09: stamp the blocking signal the startup posture gate reads.
        _set(config, _FINDINGS_BLOCKING_PATH, True)
    except Exception:  # pragma: no cover - never brick config load
        logger.warning("posture_resolver: strict coercion failed; config left as loaded", exc_info=True)
        # Fall through with whatever was applied; record stays truthful.

    LAST_RESOLUTION = res
    if not _LOGGED_ONCE:
        _LOGGED_ONCE = True
        logger.info("Lliam-GOV strict posture resolved — %s", res.summary())
    return res


# Backwards-compatible alias; some call sites prefer apply_*() naming.
def apply_posture(config: Dict[str, Any]) -> Dict[str, Any]:
    resolve(config)
    return config
