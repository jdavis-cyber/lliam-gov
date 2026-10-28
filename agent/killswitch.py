"""Kill-switch, containment & recovery authority (LG-IR-01/02/08, LG-RM-09, P5.3).

The durable fail-safe: engaging the kill-switch suspends BOTH tool execution
(the tool-dispatch chokepoint returns a halt decision) and inference (the
provider-resolution seam raises), and stays engaged across threads and process
restarts until an authorized recovery. Recovery is fail-closed and does its
own verification: autonomy is re-enabled only after ``verify_chain()`` PASSes
over the audit ledger, the signed baseline is restored from git, and the
restored baseline re-verifies (file hashes + the critical-key drift check)
— see :func:`recover` and :mod:`agent.incident_recovery`.

Design guarantees (the FINAL-gate requirements):
  * **No false auto-suspension on steady state** — absent a state file, the
    switch is NOT engaged; every guard is a no-op.
  * **Halts then cleanly restores full capability** — a clean recovery
    replaces the halt with a release record (who/when/why), so tool and
    inference flow again with no deny residue.
  * **Durable** — state is a file under the agent root (shared by every
    profile, so a halt is global), written atomically, re-read by every
    process on change, and on the agent's write-denylist. A state file that
    vanishes after this process saw it engaged is treated as tampering and
    the halt stays in force until a recorded release.
  * **Fail-closed guards** — an internal error while checking the switch
    denies the tool call / inference request rather than allowing it.

Operators drive it with ``lliam-gov killswitch engage|status|release``
(:mod:`lliam_cli.killswitch_cli`); the governance circuit-breaker
(:mod:`agent.governance_breaker`) engages it automatically.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger("hermes.killswitch")
_lock = threading.RLock()
_recovery_lock = threading.Lock()

STATE_SCHEMA = "lg-ir/killswitch/2"

# In-process cache of the durable state (authoritative source is the file),
# keyed on the file's identity so another process's engage/release is seen.
_cache: Optional[dict] = None
_cache_key: Optional[tuple] = None
# True once this process has observed the switch engaged; cleared only by a
# release record (or reset_for_tests). Guards against a deleted state file
# silently re-enabling autonomy.
_sticky_engaged = False
_sticky_state: Optional[dict] = None


class KillSwitchEngaged(RuntimeError):
    """Raised at the inference seam when the kill-switch is engaged."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z")


def _state_path() -> Path:
    """Durable state file under the agent root (global across profiles)."""
    try:
        from lliam_constants import get_default_lliam_root
        home = get_default_lliam_root()
    except Exception:
        home = Path(os.environ.get("LLIAM_HOME")
                    or os.environ.get("HERMES_HOME")
                    or Path.home() / ".lliam")
    return Path(home) / "killswitch.state"


def reset_for_tests() -> None:
    """Clear the durable state + in-process cache (test hygiene)."""
    global _cache, _cache_key, _sticky_engaged, _sticky_state
    with _lock:
        try:
            _state_path().unlink(missing_ok=True)
        except Exception:
            pass
        _cache, _cache_key = None, None
        _sticky_engaged, _sticky_state = False, None


def _engaged_failsafe(reason: str) -> dict:
    return {"engaged": True, "reason": reason, "actor": "system",
            "contain_classes": []}


def _read_state() -> Optional[dict]:
    """Return the current state dict, or None when never engaged.

    Fail-closed: an unreadable/corrupt file, or a file that disappeared after
    this process saw the switch engaged, reads as ENGAGED.
    """
    global _cache, _cache_key, _sticky_engaged, _sticky_state
    with _lock:
        try:
            p = _state_path()
            try:
                st = p.stat()
            except FileNotFoundError:
                _cache, _cache_key = None, None
                if _sticky_engaged:
                    _log.critical(
                        "killswitch state file vanished while ENGAGED — "
                        "treating as tamper; halt stays in force until a "
                        "recorded release")
                    held = dict(_sticky_state or {})
                    held.update(_engaged_failsafe(
                        "state file removed while engaged (no release record)"))
                    held["prior_reason"] = (_sticky_state or {}).get("reason")
                    return held
                return None
            key = (str(p), st.st_ino, st.st_mtime_ns, st.st_size)
            if key == _cache_key and _cache is not None:
                return _cache
            data = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("state is not a JSON object")
            _cache, _cache_key = data, key
            if data.get("engaged"):
                _sticky_engaged, _sticky_state = True, dict(data)
            else:
                # A release record is the only way to clear the sticky halt.
                _sticky_engaged, _sticky_state = False, None
            return data
        except Exception as e:
            # A corrupt/unreadable state file is treated fail-closed: assume
            # engaged so a tamper cannot silently re-enable autonomy.
            _log.error("killswitch state unreadable — treating as ENGAGED: %s", e)
            _cache, _cache_key = None, None
            return _engaged_failsafe(f"state-unreadable ({e})")


def _write_state(state: Optional[dict]) -> None:
    """Atomically replace the state file (temp file + fsync + os.replace).

    A crash mid-write leaves the previous state intact; readers never see a
    partial file. ``None`` removes the file (test hygiene only — a release
    writes a release record instead).
    """
    global _cache, _cache_key, _sticky_engaged, _sticky_state
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if state is None:
        p.unlink(missing_ok=True)
        _cache, _cache_key = None, None
        _sticky_engaged, _sticky_state = False, None
        return
    payload = json.dumps(state, sort_keys=True, indent=2).encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=".killswitch.state.", suffix=".tmp",
                               dir=str(p.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:  # persist the rename itself (POSIX)
        dfd = os.open(str(p.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except Exception:
        pass
    _cache, _cache_key = None, None
    if state.get("engaged"):
        _sticky_engaged, _sticky_state = True, dict(state)
    else:
        _sticky_engaged, _sticky_state = False, None


# ---------------------------------------------------------------------------
# Engage / query
# ---------------------------------------------------------------------------

def engage(*, reason: str, actor: str,
           contain_classes: Optional[list[str]] = None) -> dict:
    """Engage the kill-switch (LG-IR-01/02). Idempotent; records reason+actor.

    Halts tool execution + inference and optionally contains named tool
    classes (LG-IR-02). Local-only (one atomic file write) — no network.
    Emits ``killswitch.activate`` to the ledger for forensic reconstruction
    (LG-IR-04/07) and trips the per-thread interrupt.
    """
    now = _now_iso()
    with _lock:
        prior = _read_state()
        state = {
            "schema": STATE_SCHEMA,
            "engaged": True,
            "reason": str(reason),
            "actor": str(actor),
            "contain_classes": list(contain_classes or []),
            "engaged_at": now,
        }
        if prior and prior.get("engaged"):
            # Re-engage keeps the original engagement time and widens (never
            # narrows) containment.
            state["engaged_at"] = prior.get("engaged_at") or now
            state["reengaged_at"] = now
            state["contain_classes"] = sorted(
                set(prior.get("contain_classes") or []) | set(state["contain_classes"]))
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

@dataclass
class _HaltDecision:
    """Dependency-free stand-in for ``ToolGuardrailDecision`` (same surface),
    used when the guardrail module itself cannot be imported."""

    action: str = "halt"
    code: str = "killswitch_engaged"
    message: str = ""
    tool_name: str = ""
    count: int = 0
    signature: Any = None

    @property
    def allows_execution(self) -> bool:
        return False

    @property
    def should_halt(self) -> bool:
        return True

    def to_metadata(self) -> dict[str, Any]:
        return {"action": self.action, "code": self.code,
                "message": self.message, "tool_name": self.tool_name,
                "count": self.count}


def halt_decision(function_name: str, *, code: str, message: str) -> Any:
    """A blocking tool decision; never raises."""
    try:
        from agent.tool_guardrails import ToolGuardrailDecision
        return ToolGuardrailDecision(action="halt", code=code, message=message,
                                     tool_name=function_name)
    except Exception:
        return _HaltDecision(code=code, message=message,
                             tool_name=str(function_name))


def guard_tool_dispatch(function_name: str) -> Optional[Any]:
    """Return a blocking halt decision when engaged; else None (LG-IR-01).

    Fail-closed: an internal error while checking the switch DENIES the call
    (returns a halt decision) — an unverifiable kill-switch must not let a
    tool run.
    """
    try:
        engaged = is_engaged()
    except Exception as e:
        _log.error("killswitch tool guard error — denying %s (fail-closed): %s",
                   function_name, e)
        return halt_decision(
            function_name, code="killswitch_guard_error",
            message=("Blocked (fail-closed): the kill-switch state could not "
                     f"be checked ({type(e).__name__}); tool execution is "
                     "denied until it can (LG-IR-01)."))
    if not engaged:
        return None
    return halt_decision(
        function_name, code="killswitch_engaged",
        message=("Blocked (fail-safe): the kill-switch is ENGAGED — all "
                 "tool execution is suspended pending recovery "
                 "(LG-IR-01)."))


def assert_inference_live() -> None:
    """Raise :class:`KillSwitchEngaged` when engaged (LG-IR-01, inference seam).

    Fail-closed: an internal error while checking also raises.
    """
    try:
        st = _read_state()
    except Exception as e:  # pragma: no cover - _read_state already fails closed
        raise KillSwitchEngaged(
            f"inference halted — kill-switch state could not be checked ({e})")
    if st and st.get("engaged"):
        raise KillSwitchEngaged(
            f"inference halted — kill-switch engaged ({st.get('reason')})")


# ---------------------------------------------------------------------------
# Forensic preservation (LG-IR-04)
# ---------------------------------------------------------------------------

def preserve_forensics(*, actor: str, reason: str,
                       extra_files: Optional[dict[str, Path]] = None,
                       ledger_path: Optional[Path] = None) -> dict:
    """Snapshot the audit ledger + kill-switch state with a custody manifest.

    Uses the governance evidence store (:mod:`agent.incident_recovery`) —
    not the oss-forensics optional skill, which the governed profile denies.
    Returns the manifest dict (``evidence_dir`` / ``manifest_sha256`` keys).
    """
    from agent import incident_recovery as ir
    files: dict[str, Path] = {}
    led = Path(ledger_path) if ledger_path else ir.ledger_path_or_none()
    if led is not None and led.exists():
        files["agent-audit.log"] = led
    sp = _state_path()
    if sp.exists():
        files["killswitch.state"] = sp
    files.update(extra_files or {})
    return ir.preserve_forensics(files=files, actor=actor, reason=reason)


# ---------------------------------------------------------------------------
# Recovery (LG-IR-08) — verifies and restores the baseline itself
# ---------------------------------------------------------------------------

@dataclass
class RecoveryResult:
    ok: bool
    reason: str
    baseline_ref: Optional[str] = None
    baseline_commit: Optional[str] = None
    baseline_source: Optional[str] = None
    restored: list[str] = field(default_factory=list)
    evidence_dir: Optional[str] = None
    chain: Optional[dict] = None
    notes: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in (
            "ok", "reason", "baseline_ref", "baseline_commit",
            "baseline_source", "restored", "evidence_dir", "chain", "notes")}


def recover(*, actor: str, reason: str, baseline_tag: Optional[str] = None,
            repo_root: Optional[Path] = None,
            ledger_path: Optional[Path] = None,
            dry_run: bool = False) -> RecoveryResult:
    """Release the kill-switch ONLY after recovery verifies and restores.

    Fail-closed sequence — any failure keeps the halt in force:
      1. ``verify_chain()`` PASS over the audit ledger (LG-AU-08 / LG-IR-08);
      2. resolve the signed baseline (authorization-record pin, or the
         operator's ``baseline_tag``) in the local git checkout — no network;
      3. the baseline's own overlay passes the critical-key drift check
         (nothing has been written yet);
      4. preserve forensics (ledger, state, every file about to be replaced)
         with a SHA-256 custody manifest;
      5. restore the baseline-controlled files from the baseline commit;
      6. confirm the restored bytes match the baseline blobs;
      7. record the release (who/when/why/baseline) in the ledger — when the
         ledger is enabled an unrecordable release is refused;
      8. replace the halt with a release record.

    ``dry_run`` runs steps 1-3 and reports which files would be restored
    (in ``restored``) without writing anything or releasing.
    """
    if not str(actor or "").strip():
        raise ValueError("recover() requires an actor")
    if not str(reason or "").strip():
        raise ValueError("recover() requires a reason")
    from agent import incident_recovery as ir

    with _recovery_lock:
        current = state()
        if not current.get("engaged"):
            return RecoveryResult(ok=True,
                                  reason="kill-switch not engaged; nothing to release")

        def _refuse(why: str, **kw) -> RecoveryResult:
            if dry_run:
                return RecoveryResult(ok=False, reason=why, **kw)
            _log.critical("RECOVERY REFUSED — %s; kill-switch stays ENGAGED "
                          "(LG-IR-08 fail-closed)", why)
            _emit_recovery(kw.get("baseline_commit") or baseline_tag, actor,
                           ok=False, reason=why, operator_reason=reason)
            return RecoveryResult(ok=False, reason=why, **kw)

        # 1. audit chain
        chain = ir.verify_audit_chain(ledger_path)
        if not chain.ok:
            return _refuse(f"audit chain not verified: {chain.reason}",
                           chain=chain.as_dict())

        # 2. baseline
        try:
            baseline = ir.resolve_baseline(repo_root=repo_root, ref=baseline_tag)
        except ir.BaselineError as e:
            return _refuse(f"baseline not resolvable: {e}", chain=chain.as_dict())
        info: dict[str, Any] = dict(
            baseline_ref=baseline.ref, baseline_commit=baseline.commit,
            baseline_source=baseline.source, chain=chain.as_dict())

        # 3. the baseline itself must pass the critical-key drift check —
        #    checked before anything is written, so an unfit baseline never lands
        problems = ir.check_baseline_content(baseline)
        if problems:
            return _refuse("baseline failed verification: " + "; ".join(problems),
                           **info)

        if dry_run:
            try:
                would = ir.drifted_paths(baseline)
            except Exception as e:
                return _refuse(f"baseline comparison failed: {e}", **info)
            return RecoveryResult(ok=True, reason="dry run — nothing written; "
                                  "the kill-switch stays engaged",
                                  restored=would, notes=ir.code_drift_notes(baseline),
                                  **info)

        # 4. forensics before anything is overwritten
        try:
            drifted = ir.drifted_paths(baseline)
            extra = {f"displaced/{rel}": baseline.root / rel
                     for rel in drifted if (baseline.root / rel).exists()}
            manifest = preserve_forensics(actor=actor,
                                          reason=f"pre-recovery: {reason}",
                                          extra_files=extra,
                                          ledger_path=chain.ledger_path)
        except Exception as e:
            return _refuse(f"forensic preservation failed ({e}); refusing to "
                           "overwrite evidence", **info)
        info["evidence_dir"] = manifest.get("evidence_dir")

        # 5. restore
        try:
            restored = ir.restore_baseline(baseline, drifted)
        except Exception as e:
            return _refuse(f"baseline restore failed: {e}", **info)
        info["restored"] = restored

        # 6. the restored files must match the baseline blobs byte-for-byte
        problems = ir.verify_restored(baseline)
        if problems:
            return _refuse("restored baseline failed verification: "
                           + "; ".join(problems), **info)
        notes = ir.code_drift_notes(baseline)

        # 7. record the release (fail-closed when the ledger is enabled)
        release = {
            "schema": STATE_SCHEMA,
            "engaged": False,
            "released_at": _now_iso(),
            "released_by": str(actor),
            "release_reason": str(reason),
            "baseline_ref": baseline.ref,
            "baseline_commit": baseline.commit,
            "baseline_source": baseline.source,
            "restored": list(restored),
            "evidence_dir": info["evidence_dir"],
            "previous": {k: current.get(k) for k in (
                "reason", "actor", "engaged_at", "contain_classes")},
        }
        try:
            _emit_recovery(baseline.commit, actor, ok=True,
                           reason="verify_chain PASS + baseline restored and verified",
                           operator_reason=reason, release=release,
                           required=chain.ledger_enabled)
        except Exception as e:
            return _refuse(f"release could not be recorded in the audit ledger: {e}",
                           **info)

        # 8. clear the halt
        with _lock:
            _write_state(release)
        try:
            from tools.interrupt import set_interrupt
            set_interrupt(False)
        except Exception:
            pass
        _log.warning("KILL-SWITCH RELEASED by %s → baseline %s (%s); chain "
                     "verified; %d file(s) restored; full capability restored",
                     actor, baseline.ref, baseline.commit[:12], len(restored))
        return RecoveryResult(ok=True, reason="released", notes=notes, **info)


def recover_and_reenable(*, actor: str, reason: str = "recovery",
                         baseline_tag: Optional[str] = None,
                         repo_root: Optional[Path] = None,
                         ledger_path: Optional[Path] = None) -> bool:
    """Boolean wrapper over :func:`recover` (True = released)."""
    return recover(actor=actor, reason=reason, baseline_tag=baseline_tag,
                   repo_root=repo_root, ledger_path=ledger_path).ok


# ---------------------------------------------------------------------------
# Ledger emission
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
                         "contain_classes": state.get("contain_classes"),
                         "engaged_at": state.get("engaged_at")},
                subject={"principal": state.get("actor")},
                source_module="agent/killswitch.py:engage",
            )
    except Exception:
        pass


def _emit_recovery(baseline: Optional[str], actor: str, *, ok: bool,
                   reason: str, operator_reason: str = "",
                   release: Optional[dict] = None,
                   required: bool = False) -> None:
    """Record a recovery attempt. ``required`` makes a write failure raise
    (the caller then refuses the release); otherwise best-effort."""
    try:
        from agent import governance_audit as ga
        led = ga.get_ledger()
        if led is None:
            if required:
                raise RuntimeError("audit ledger unavailable")
            return
        outcome = {"status": "recovered" if ok else "recovery_refused",
                   "baseline": baseline, "reason": reason,
                   "operator_reason": operator_reason}
        if release:
            outcome.update({k: release.get(k) for k in (
                "released_at", "baseline_ref", "baseline_source",
                "restored", "evidence_dir", "previous")})
        rec = led.emit(
            "killswitch.activate",
            action="killswitch.recover",
            decision="allow" if ok else "deny",
            severity="notice" if ok else "critical",
            outcome=outcome,
            subject={"principal": actor},
            source_module="agent/killswitch.py:recover",
            risk_scope={"privileged"} if required else None,
        )
        if required and rec is None:
            raise RuntimeError("release record was not written")
    except Exception:
        if required:
            raise
