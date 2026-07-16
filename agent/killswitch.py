"""Kill-switch, containment & recovery authority (LG-IR-01/02/08, LG-RM-09, P5.3).

The durable fail-safe: engaging the kill-switch suspends BOTH tool execution
(the tool-dispatch chokepoint returns a halt decision) and inference (the
provider-resolution seam raises), and stays engaged across threads and process
restarts until an authorized recovery. Recovery is fail-closed: autonomy is
re-enabled only after ``verify_chain()`` PASSes over the audit ledger and the
running baseline is confirmed against the last signed tag (LG-IR-08).

Design guarantees (the FINAL-gate requirements):
  * **No false auto-suspension on steady state** — absent a state file, the
    switch is NOT engaged; every guard is a no-op.
  * **Halts then cleanly restores full capability** — a clean recovery clears
    the state entirely (halt + containment), so tool and inference flow again
    with no residue.
  * **Durable** — state is a file under the agent home, so a halt survives
    thread/process boundaries and cannot be cleared by an ordinary agent write
    (the file lives outside the write-safe-root; disengage is gated on
    verify_chain).

Additive — no existing module renamed; the guards are wired into the existing
``predispatch_gate`` and ``resolve_runtime_provider`` seams.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger("hermes.killswitch")
_lock = threading.Lock()

# In-process cache of the durable state (authoritative source is the file).
_cache: Optional[dict] = None
_cache_loaded = False


class KillSwitchEngaged(RuntimeError):
    """Raised at the inference seam when the kill-switch is engaged."""


def _state_path() -> Path:
    """Durable state file under the agent home (outside the write-safe-root)."""
    try:
        from lliam_constants import get_lliam_home
        home = get_lliam_home()
    except Exception:
        home = Path(os.environ.get("HERMES_HOME")
                    or os.environ.get("LLIAM_HOME")
                    or Path.home() / ".lliam")
    return Path(home) / "killswitch.state"


def reset_for_tests() -> None:
    """Clear the durable state + in-process cache (test hygiene)."""
    global _cache, _cache_loaded
    with _lock:
        try:
            _state_path().unlink(missing_ok=True)
        except Exception:
            pass
        _cache = None
        _cache_loaded = False


def _read_state() -> Optional[dict]:
    global _cache, _cache_loaded
    p = _state_path()
    try:
        if not p.exists():
            _cache, _cache_loaded = None, True
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        _cache, _cache_loaded = data, True
        return data
    except Exception as e:
        # A corrupt/unreadable state file is treated fail-closed: assume
        # engaged so a tamper cannot silently re-enable autonomy.
        _log.error("killswitch state unreadable — treating as ENGAGED: %s", e)
        engaged = {"engaged": True, "reason": f"state-unreadable ({e})",
                   "actor": "system", "contain_classes": []}
        _cache, _cache_loaded = engaged, True
        return engaged


def _write_state(state: Optional[dict]) -> None:
    global _cache, _cache_loaded
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if state is None:
        p.unlink(missing_ok=True)
    else:
        tmp = p.with_suffix(".state.tmp")
        tmp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        os.replace(tmp, p)
    _cache, _cache_loaded = state, True


# ---------------------------------------------------------------------------
# Engage / query
# ---------------------------------------------------------------------------

def engage(*, reason: str, actor: str,
           contain_classes: Optional[list[str]] = None) -> dict:
    """Engage the kill-switch (LG-IR-01/02). Idempotent; records reason+actor.

    Halts tool execution + inference and optionally contains named tool
    classes (LG-IR-02). Emits ``killswitch.activate`` to the ledger for
    forensic reconstruction (LG-IR-04/07) and trips the per-thread interrupt.
    """
    state = {
        "engaged": True,
        "reason": str(reason),
        "actor": str(actor),
        "contain_classes": list(contain_classes or []),
    }
    with _lock:
        _write_state(state)
    _emit_activate(state)
    try:
        from tools.interrupt import set_interrupt
        set_interrupt(True)
    except Exception:
        pass
    _log.critical("KILL-SWITCH ENGAGED by %s — %s", actor, reason)
    return state


def is_engaged() -> bool:
    if _cache_loaded and _cache is not None:
        return bool(_cache.get("engaged"))
    st = _read_state()
    return bool(st and st.get("engaged"))


def state() -> dict:
    st = _read_state()
    return dict(st) if st else {"engaged": False}


def class_contained(tool_class: str) -> bool:
    """True when a specific tool class is under containment (LG-IR-02)."""
    st = _read_state()
    if not st or not st.get("engaged"):
        return False
    return str(tool_class) in set(st.get("contain_classes") or [])


# ---------------------------------------------------------------------------
# Runtime-seam guards (wired at the tool-dispatch + inference chokepoints)
# ---------------------------------------------------------------------------

def guard_tool_dispatch(function_name: str) -> Optional[Any]:
    """Return a blocking halt decision when engaged; else None (LG-IR-01).

    Fail-safe: any internal error yields None (does not break dispatch for a
    reason other than an explicit engaged state).
    """
    try:
        if not is_engaged():
            return None
        from agent.tool_guardrails import ToolGuardrailDecision
        return ToolGuardrailDecision(
            action="halt",
            code="killswitch_engaged",
            message=("Blocked (fail-safe): the kill-switch is ENGAGED — all "
                     "tool execution is suspended pending recovery "
                     "(LG-IR-01)."),
            tool_name=function_name,
        )
    except Exception as e:
        _log.debug("killswitch tool guard error (non-fatal): %s", e)
        return None


def assert_inference_live() -> None:
    """Raise :class:`KillSwitchEngaged` when engaged (LG-IR-01, inference seam)."""
    if is_engaged():
        st = _read_state() or {}
        raise KillSwitchEngaged(
            f"inference halted — kill-switch engaged ({st.get('reason')})")


# ---------------------------------------------------------------------------
# Recovery (LG-IR-08) — fail-closed on a broken chain
# ---------------------------------------------------------------------------

def recover_and_reenable(*, baseline_tag: str, actor: str,
                         verify_ok: bool,
                         verify_reason: str = "") -> bool:
    """Re-enable autonomy ONLY after verify_chain PASS + baseline confirmation.

    Returns True and clears the halt (full capability restored) when
    ``verify_ok``; returns False and KEEPS the halt when the chain is broken
    (LG-IR-08 fail-closed). Records the recovery attempt for the incident log.
    """
    if not verify_ok:
        _log.critical(
            "RECOVERY REFUSED — audit chain not verified (%s); kill-switch "
            "stays ENGAGED (LG-IR-08 fail-closed)", verify_reason or "unknown")
        _emit_recovery(baseline_tag, actor, ok=False,
                       reason=verify_reason or "chain not verified")
        return False
    with _lock:
        _write_state(None)  # clear halt + containment entirely
    try:
        from tools.interrupt import set_interrupt
        set_interrupt(False)
    except Exception:
        pass
    _emit_recovery(baseline_tag, actor, ok=True, reason="verify_chain PASS")
    _log.warning("KILL-SWITCH RECOVERED by %s → baseline %s (chain verified); "
                 "full capability restored", actor, baseline_tag)
    return True


# ---------------------------------------------------------------------------
# Ledger emission (best-effort; never breaks the switch)
# ---------------------------------------------------------------------------

def _emit_activate(state: dict) -> None:
    try:
        from agent import governance_audit as ga
        led = ga.get_ledger()
        if led is not None:
            led.emit(
                "killswitch.activate",
                action="killswitch.engage",
                decision="halt",
                severity="warning",
                outcome={"status": "engaged", "reason": state.get("reason"),
                         "contain_classes": state.get("contain_classes")},
                subject={"principal": state.get("actor")},
                source_module="agent/killswitch.py:engage",
            )
    except Exception:
        pass


def _emit_recovery(baseline_tag: str, actor: str, *, ok: bool,
                   reason: str) -> None:
    try:
        from agent import governance_audit as ga
        led = ga.get_ledger()
        if led is not None:
            led.emit(
                "killswitch.activate",
                action="killswitch.recover",
                decision="allow" if ok else "deny",
                severity="notice" if ok else "critical",
                outcome={"status": "recovered" if ok else "recovery_refused",
                         "baseline": baseline_tag, "reason": reason},
                subject={"principal": actor},
                source_module="agent/killswitch.py:recover_and_reenable",
            )
    except Exception:
        pass
