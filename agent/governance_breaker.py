"""Governance circuit-breaker (LG-IR-03): repeated denials trip the kill-switch.

A run of consecutive blocked/denied tool calls (PDP denials, guardrail and
plugin blocks, audit fail-closed blocks) inside one session, all within a
sliding time window, is the signature of an agent hammering on its policy
boundary — a prompt-injection-driven action chain or a runaway loop. When the
run reaches ``threshold`` within ``window_seconds`` the breaker engages the
kill-switch (:func:`agent.killswitch.engage`), which then halts tool
execution and inference until an operator releases it.

Any allowed outcome in the session resets its run, so ordinary, occasional
denials never accumulate. Fed from the universal tool-outcome funnel
(``agent.governance_audit_hooks.record_outcome``).

Configuration lives only in the governed overlay::

    incident_response:
      circuit_breaker:
        policy_denials:
          enabled: true
          threshold: 10
          window_seconds: 120

Absent that section the breaker is off (no behaviour change outside the
governed profile). The clock is injectable for tests.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict, deque
from typing import Callable, Optional

_log = logging.getLogger("hermes.governance_breaker")

ACTOR = "system:governance-circuit-breaker"
# Fallbacks for a policy_denials block that is enabled but omits a value.
FALLBACK_THRESHOLD = 10
FALLBACK_WINDOW_SECONDS = 120.0
_MAX_SESSIONS = 512


class GovernanceBreaker:
    """Per-session run counter over blocked outcomes with a sliding window."""

    def __init__(self, *, threshold: int, window_seconds: float,
                 clock: Callable[[], float] = time.monotonic,
                 engage: Optional[Callable[..., object]] = None) -> None:
        if int(threshold) < 1:
            raise ValueError("threshold must be >= 1")
        if float(window_seconds) <= 0:
            raise ValueError("window_seconds must be > 0")
        self.threshold = int(threshold)
        self.window_seconds = float(window_seconds)
        self._clock = clock
        self._engage = engage
        self._runs: "OrderedDict[str, deque]" = OrderedDict()
        self._lock = threading.Lock()

    def observe(self, *, blocked: bool, session_id: str = "", tool: str = "",
                detail: str = "") -> bool:
        """Feed one tool outcome. Returns True when this call tripped the breaker."""
        key = session_id or "_global"
        if not blocked:
            with self._lock:
                self._runs.pop(key, None)
            return False
        from agent import killswitch as ks
        if ks.is_engaged():
            # Already halted: the kill-switch's own denials must not stack
            # into a second engagement.
            with self._lock:
                self._runs.pop(key, None)
            return False
        now = self._clock()
        with self._lock:
            run = self._runs.get(key)
            if run is None:
                run = self._runs[key] = deque()
                while len(self._runs) > _MAX_SESSIONS:
                    self._runs.popitem(last=False)
            else:
                self._runs.move_to_end(key)
            run.append(now)
            while run and now - run[0] > self.window_seconds:
                run.popleft()
            if len(run) < self.threshold:
                return False
            count = len(run)
            self._runs.pop(key, None)
        reason = (f"governance circuit-breaker: {count} consecutive blocked "
                  f"tool calls within {self.window_seconds:g}s "
                  f"(session {session_id or 'n/a'}, last: {tool or '?'}"
                  + (f" — {str(detail)[:200]}" if detail else "") + ")")
        _log.critical("GOVERNANCE CIRCUIT-BREAKER TRIPPED — %s", reason)
        (self._engage or ks.engage)(reason=reason, actor=ACTOR)
        return True


_breaker: Optional[GovernanceBreaker] = None
_loaded = False
_singleton_lock = threading.Lock()


def _from_config() -> Optional[GovernanceBreaker]:
    try:
        from lliam_cli.config import load_config
        cfg = load_config() or {}
    except Exception as e:
        _log.debug("circuit-breaker config unavailable: %s", e)
        return None
    section = (((cfg.get("incident_response") or {}).get("circuit_breaker") or {})
               .get("policy_denials"))
    if not isinstance(section, dict) or not section.get("enabled", False):
        return None
    try:
        return GovernanceBreaker(
            threshold=int(section.get("threshold", FALLBACK_THRESHOLD)),
            window_seconds=float(section.get("window_seconds",
                                             FALLBACK_WINDOW_SECONDS)))
    except (TypeError, ValueError) as e:
        # An enabled-but-malformed safety control falls back to the defaults
        # rather than silently switching off.
        _log.error("invalid incident_response.circuit_breaker.policy_denials "
                   "(%s); using threshold=%d window=%gs", e,
                   FALLBACK_THRESHOLD, FALLBACK_WINDOW_SECONDS)
        return GovernanceBreaker(threshold=FALLBACK_THRESHOLD,
                                 window_seconds=FALLBACK_WINDOW_SECONDS)


def get_breaker() -> Optional[GovernanceBreaker]:
    """The process breaker (built once from config), or None when disabled."""
    global _breaker, _loaded
    if _loaded:
        return _breaker
    with _singleton_lock:
        if not _loaded:
            _breaker = _from_config()
            _loaded = True
    return _breaker


def set_breaker_for_tests(breaker: Optional[GovernanceBreaker]) -> None:
    global _breaker, _loaded
    with _singleton_lock:
        _breaker, _loaded = breaker, True


def reset_for_tests() -> None:
    global _breaker, _loaded
    with _singleton_lock:
        _breaker, _loaded = None, False


def observe_outcome(*, blocked: bool, session_id: str = "", tool: str = "",
                    detail: str = "") -> bool:
    """Funnel entry point. Never raises."""
    try:
        b = get_breaker()
        if b is None:
            return False
        return b.observe(blocked=blocked, session_id=session_id, tool=tool,
                         detail=detail or "")
    except Exception as e:
        _log.error("governance circuit-breaker error: %s", e)
        return False
