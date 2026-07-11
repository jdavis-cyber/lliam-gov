"""Lliam-GOV governance audit ledger — append-only, hash-chained (P1.1).

NEW ADDITIVE module (PATH-FREEZE honored): realizes the core of controls
LG-AU-01 (hash-chained append-only ledger), LG-AU-03 (auditable event set),
LG-AU-04 (standardized record schema), LG-AU-05 (redaction-on-write),
LG-AU-06 (UTC ms timestamps + monotonic sequence) and LG-AU-09 (fail-closed
on audit-write failure for the high-risk scope). Controlling design:
``Audit_and_Logging_Specification.md`` (governance package).

The ledger is JSONL at ``$LLIAM_HOME/logs/agent-audit.log`` (legacy
``$HERMES_HOME`` honored via :func:`lliam_constants.get_lliam_home`) —
OUTSIDE the workspace and on the ``agent/file_safety.py`` write-denylist
(LG-AU-07), so the agent's own file tools cannot rewrite its own record.

Each record carries ``prev_hash`` (SHA-256 of the prior record's canonical
bytes; genesis = 64 zeros) and ``record_hash`` (SHA-256 over the canonical
serialization of the record with ``record_hash`` omitted), forming a
tamper-evident chain: any edit, deletion, or reorder breaks every
downstream hash.

Scope notes (build-plan step boundaries):
  * P1.2 (LG-AU-02/10) wires :func:`emit` into the tool-dispatch chokepoint
    and the ACP/dashboard-auth bridges — this module only provides the
    emitter surface.
  * P1.3 (LG-AU-08) adds ``verify_chain()`` + startup/CI/cron verification;
    :func:`iter_records` and :func:`canonical_bytes` are the primitives it
    builds on (tests verify the chain independently today).
  * P1.4 (LG-IA-02) binds the real agent NPE identity; until then callers
    may pass ``actor`` explicitly and the default actor is an unbound stub.

This module does NOT alter ``lliam_cli/dashboard_auth/audit.py`` — that
remains the auth-event writer (its never-block-auth semantics are
preserved; the LG-AU-10 forward/bridge lands with P1.2).

Capability preservation: the ledger is a write-only side channel, disabled
unless the effective config enables it (``audit.ledger_enabled``, set by
the governance overlay ``cli-config.gov.yaml``). The only behavioral
change it introduces is the intended LG-AU-09 guarantee: a *high-risk*
action whose audit record cannot be written must not proceed — callers
gate on :class:`AuditWriteError`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
import datetime as _dt
from pathlib import Path
from typing import Any, Iterator, Optional

_log = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Schema constants (LG-AU-04)
# --------------------------------------------------------------------------

SCHEMA_VERSION = "lg-au/1"
GENESIS_PREV_HASH = "0" * 64
HASH_ALGO = "sha256"

# Auditable event taxonomy (LG-AU-03) — the L2 floor set. Mirrors the
# ``audit.events`` enumeration in cli-config.gov.yaml; each event names an
# existing decision point (see the specification §2 table).
AUDITABLE_EVENTS: frozenset[str] = frozenset({
    "tool.dispatch",
    "tool.result",
    "approval.decision",
    "provider.call",
    "mcp.call",
    "policy.violation",
    "config.load",
    "skill.load",
    "mcp.load",
    "secret.access",
    "memory.write",
    "session.start",
    "session.stop",
    "agent.lifecycle",
    "killswitch.activate",
    "security.error",
})

SEVERITIES = ("info", "notice", "warning", "critical")

# Default severity per event type (spec §2, "Severity (typical)").
_DEFAULT_SEVERITY: dict[str, str] = {
    "approval.decision": "notice",
    "policy.violation": "warning",
    "config.load": "notice",
    "skill.load": "notice",
    "mcp.load": "notice",
    "secret.access": "notice",
    "memory.write": "notice",
    "agent.lifecycle": "notice",
    "killswitch.activate": "warning",
    "security.error": "critical",
}

# Risk classes gated fail-closed by default (LG-AU-09, spec §9).
DEFAULT_FAIL_CLOSED_SCOPE = frozenset({
    "mutating", "privileged", "egress", "high_impact",
})

_DECISIONS = frozenset({"allow", "deny", "approve", "timeout", "halt", "n/a"})


class AuditWriteError(RuntimeError):
    """The audit record could not be written (LG-AU-09).

    Raised for events whose ``risk_scope`` intersects the fail-closed scope:
    the caller must treat the gated action as blocked — an action that
    executes off-the-books is, for accountability purposes, an action that
    cannot be defended.
    """


# --------------------------------------------------------------------------
# Config access (mirrors the Phase-0 gov-module pattern: lazy, fail-safe)
# --------------------------------------------------------------------------

def _audit_config() -> dict:
    """``audit:`` block from the effective (overlay-aware) config, or {}."""
    try:
        from lliam_cli import config as _cfg
        return dict(_cfg.load_config().get("audit") or {})
    except Exception:
        return {}


def ledger_enabled(cfg: Optional[dict] = None) -> bool:
    """True when the governance ledger is active (default False — the

    low-side/shipped profile never writes a ledger; the gov overlay
    activates it via ``audit.ledger_enabled: true``)."""
    cfg = _audit_config() if cfg is None else cfg
    return bool(cfg.get("ledger_enabled", False))


def resolve_ledger_path(cfg: Optional[dict] = None) -> Path:
    """Ledger path from config, defaulting to ``<home>/logs/agent-audit.log``.

    A ``$HERMES_HOME`` / ``$LLIAM_HOME`` prefix in the configured value is
    resolved through :func:`lliam_constants.get_lliam_home` (NOT raw env
    expansion) so profile/default-home semantics stay consistent with the
    rest of the system.
    """
    cfg = _audit_config() if cfg is None else cfg
    from lliam_constants import get_lliam_home

    raw = str(cfg.get("ledger_path") or "").strip()
    home = get_lliam_home()
    if not raw:
        return home / "logs" / "agent-audit.log"
    for token in ("$HERMES_HOME", "$LLIAM_HOME"):
        if raw.startswith(token):
            return home / raw[len(token):].lstrip("/\\")
    return Path(os.path.expanduser(raw))


# --------------------------------------------------------------------------
# Canonical serialization + hashing (LG-AU-01)
# --------------------------------------------------------------------------

def canonical_bytes(record: dict) -> bytes:
    """Canonical serialization: ``record_hash`` omitted, deterministic key

    order, compact separators, UTF-8. This is the byte string both
    ``record_hash`` and the next record's ``prev_hash`` commit to."""
    body = {k: v for k, v in record.items() if k != "record_hash"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Redaction-on-write (LG-AU-05)
# --------------------------------------------------------------------------

def _redact_value(value: Any) -> Any:
    """Recursively redact strings via the Phase-0 hard boundary.

    ``force=True`` is mandatory here: redaction on the persistence boundary
    must not be disableable at runtime (the ``_REDACT_ENABLED`` snapshot in
    ``agent/redact.py`` cannot be flipped mid-session, and ``force`` makes
    this path independent of it entirely).
    """
    from agent.redact import redact_sensitive_text

    if isinstance(value, str):
        return redact_sensitive_text(value, force=True)
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(v) for v in value]
    return value


def _redact_object(obj: Optional[dict]) -> Optional[dict]:
    """Redact a record sub-object before persistence.

    Where redaction masked anything, a stable ``content_hash`` (SHA-256 of
    the canonical serialization of the ORIGINAL object) is retained so an
    investigator can still correlate same-value occurrences without the
    value ever touching disk (spec §5.2).
    """
    if not obj:
        return obj
    redacted = _redact_value(obj)
    if redacted != obj:
        original_bytes = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        redacted["content_hash"] = f"sha256:{_sha256_hex(original_bytes)}"
    return redacted


# --------------------------------------------------------------------------
# The ledger
# --------------------------------------------------------------------------

def _new_correlation_id() -> str:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"sess-{ts}-{uuid.uuid4().hex[:8]}"


# Process-level default correlation id — joins all records of one run until
# the P1.2 chokepoint threads real per-operation trace ids through.
_SESSION_CORRELATION_ID = _new_correlation_id()


class GovernanceLedger:
    """Append-only hash-chained JSONL ledger (one instance per file).

    Thread-safe. The chain tail (``seq`` + ``prev_hash``) is recovered from
    the last well-formed line on first append, so restarts continue the
    chain instead of forking it. An unreadable/corrupt tail refuses ALL
    chained appends (fail-closed) — appending onto a broken chain would
    silently destroy tamper evidence.
    """

    def __init__(
        self,
        path: Optional[Path] = None,
        *,
        redact_before_persist: bool = True,
        fail_closed: bool = True,
        fail_closed_scope: frozenset[str] = DEFAULT_FAIL_CLOSED_SCOPE,
    ) -> None:
        cfg = _audit_config() if path is None else {}
        self.path = resolve_ledger_path(cfg) if path is None else Path(path)
        algo = str(cfg.get("hash_algo") or HASH_ALGO).lower()
        if algo != HASH_ALGO:
            raise ValueError(
                f"audit.hash_algo={algo!r} unsupported — the LG-AU-01 chain "
                f"is pinned to {HASH_ALGO}"
            )
        self.redact_before_persist = bool(
            cfg.get("redact_before_persist", redact_before_persist)
        )
        self.fail_closed = bool(cfg.get("fail_closed", fail_closed))
        scope = cfg.get("fail_closed_scope")
        self.fail_closed_scope = (
            frozenset(scope) if scope else frozenset(fail_closed_scope)
        )
        self._lock = threading.Lock()
        self._seq: Optional[int] = None          # lazy — loaded from tail
        self._prev_hash: Optional[str] = None

    # -- tail recovery ----------------------------------------------------

    def _load_tail_locked(self) -> None:
        """Recover (seq, prev_hash) from the last line of the ledger."""
        if self._seq is not None:
            return
        try:
            if not self.path.exists() or self.path.stat().st_size == 0:
                self._seq, self._prev_hash = 0, GENESIS_PREV_HASH
                return
            with open(self.path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 65536))
                tail_lines = f.read().splitlines()
            last = next(
                (ln for ln in reversed(tail_lines) if ln.strip()), None
            )
            if last is None:
                self._seq, self._prev_hash = 0, GENESIS_PREV_HASH
                return
            rec = json.loads(last.decode("utf-8"))
            self._seq = int(rec["seq"])
            self._prev_hash = str(rec["record_hash"])
        except Exception as e:
            # Corrupt/unreadable tail: the chain head is unknown, so no
            # chained append is possible. Surface as a write failure — the
            # LG-AU-09 policy in emit() decides block vs. warn.
            raise AuditWriteError(
                f"audit ledger tail unreadable at {self.path}: {e}"
            ) from e

    # -- record construction (LG-AU-04) ------------------------------------

    def build_record(
        self,
        event: str,
        *,
        action: str,
        decision: str = "n/a",
        outcome: Optional[dict] = None,
        actor: Optional[dict] = None,
        subject: Optional[dict] = None,
        resource: Optional[dict] = None,
        parameters: Optional[dict] = None,
        approver: Optional[dict] = None,
        source_module: str,
        correlation_id: Optional[str] = None,
        severity: Optional[str] = None,
        seq: int,
        prev_hash: str,
    ) -> dict:
        """Build one schema-versioned, redacted, hash-sealed record."""
        if event not in AUDITABLE_EVENTS:
            raise ValueError(f"unknown auditable event: {event!r}")
        if decision not in _DECISIONS:
            raise ValueError(f"unknown decision: {decision!r}")
        sev = severity or _DEFAULT_SEVERITY.get(event, "info")
        if sev not in SEVERITIES:
            raise ValueError(f"unknown severity: {sev!r}")

        outcome = outcome or {"status": "success", "class": None}
        if self.redact_before_persist:
            parameters = _redact_object(parameters)
            outcome = _redact_object(outcome)

        record: dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "seq": seq,
            "event_id": str(uuid.uuid4()),
            "correlation_id": correlation_id or _SESSION_CORRELATION_ID,
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "event": event,
            "severity": sev,
            # Real NPE identity binding (instance_id = code+config+model
            # hash) lands with P1.4 / agent_identity.py.
            "actor": actor or {"type": "npe", "instance_id": None},
            "subject": subject or {"principal": None},
            "action": action,
            "decision": decision,
            "outcome": outcome,
            "source_module": source_module,
            "prev_hash": prev_hash,
        }
        if resource is not None:
            record["resource"] = resource
        if parameters is not None:
            record["parameters"] = parameters
        if approver is not None:
            record["approver"] = approver
        record["record_hash"] = _sha256_hex(canonical_bytes(record))
        return record

    # -- append (LG-AU-01 / LG-AU-09) ---------------------------------------

    def emit(
        self,
        event: str,
        *,
        action: str,
        source_module: str,
        risk_scope: Optional[set[str]] = None,
        **fields: Any,
    ) -> Optional[dict]:
        """Append one event to the ledger; return the sealed record.

        ``risk_scope`` carries the gated action's risk classes (e.g.
        ``{"mutating"}``). On a write failure, an event whose risk scope
        intersects ``fail_closed_scope`` raises :class:`AuditWriteError`
        (the caller must block the action — LG-AU-09); all other events log
        a redacted warning and return None (bounded availability trade:
        only consequential actions are hard-gated).
        """
        risk = frozenset(risk_scope or ())
        must_block = self.fail_closed and bool(risk & self.fail_closed_scope)
        try:
            with self._lock:
                self._load_tail_locked()
                record = self.build_record(
                    event,
                    action=action,
                    source_module=source_module,
                    seq=self._seq + 1,
                    prev_hash=self._prev_hash,
                    **fields,
                )
                line = json.dumps(
                    record, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False,
                ) + "\n"
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
                self._seq += 1
                self._prev_hash = record["record_hash"]
                return record
        except (ValueError, TypeError):
            raise  # malformed call — a programming error, never swallowed
        except Exception as e:
            if must_block:
                raise AuditWriteError(
                    f"audit append failed for {event} ({action}); "
                    f"high-risk scope {sorted(risk)} is fail-closed: {e}"
                ) from e
            # Message carries no argument values — nothing to redact leaks.
            _log.warning(
                "governance audit append failed (non-gated event %s): %s",
                event, e,
            )
            return None


# --------------------------------------------------------------------------
# Module-level surface (process singleton over the configured ledger)
# --------------------------------------------------------------------------

_ledger_singleton: Optional[GovernanceLedger] = None
_singleton_lock = threading.Lock()


def get_ledger() -> Optional[GovernanceLedger]:
    """Process ledger for the configured path, or None when disabled."""
    global _ledger_singleton
    if not ledger_enabled():
        return None
    with _singleton_lock:
        if _ledger_singleton is None:
            _ledger_singleton = GovernanceLedger()
        return _ledger_singleton


def emit(
    event: str,
    *,
    action: str,
    source_module: str,
    risk_scope: Optional[set[str]] = None,
    **fields: Any,
) -> Optional[dict]:
    """Emit one governance audit event (no-op unless the ledger is enabled).

    This is the surface the P1.2 chokepoint wiring calls. Raises
    :class:`AuditWriteError` per LG-AU-09 when a high-risk record cannot be
    persisted.
    """
    ledger = get_ledger()
    if ledger is None:
        return None
    return ledger.emit(
        event,
        action=action,
        source_module=source_module,
        risk_scope=risk_scope,
        **fields,
    )


def iter_records(path: Optional[Path] = None) -> Iterator[dict]:
    """Yield parsed ledger records in file order (P1.3 verify primitive)."""
    p = Path(path) if path is not None else resolve_ledger_path()
    if not p.exists():
        return
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)
