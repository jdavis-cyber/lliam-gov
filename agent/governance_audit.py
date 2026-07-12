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

Multi-writer safety (post-review hardening): every append takes an
EXCLUSIVE OS file lock (``flock``/``msvcrt``) on the ledger file and
re-reads the chain tail under that lock before sealing, so concurrent
processes (CLI agent, gateway, cron sessions sharing one home) extend one
linear chain instead of forking it. A torn trailing fragment from a
crashed writer (bytes after the last newline) is repaired by truncating
the fragment — never a sealed record — and the repair itself is recorded
as a ``security.error`` event before the requested record.

Hard invariants (not configurable at runtime):
  * Redaction-on-write always runs — there is no knob that disables the
    persistence-boundary redaction (LG-AU-05).
  * Every free-form record field is redacted, not just parameters.
  * A configured ``audit.ledger_path`` outside ``<home>/logs`` is refused
    (falls back to the default) so the ledger can never silently leave
    the LG-AU-07 write-denylist.
  * Once the ledger has been enabled in a process it stays enabled
    (sticky-on): a mid-session config flip or config-load failure cannot
    quietly disable auditing — the flip attempt is itself recorded.

Scope notes (build-plan step boundaries): the dispatch-chokepoint wiring
lives in ``agent/governance_audit_hooks.py`` (P1.2); ``verify_chain()`` +
startup/CI verification land in P1.3 (:func:`iter_records` and
:func:`canonical_bytes` are its primitives); real agent NPE identity
binding lands in P1.4. This module does NOT alter
``lliam_cli/dashboard_auth/audit.py`` — that remains the auth-event writer.

Accepted residuals (recorded for the deviation register): in-process code
can bypass the module entirely via direct ``open()`` (mitigated by §7
placement/denylist for file TOOLS, fully addressed by external anchoring
in P1.3+); ``content_hash`` is an unsalted SHA-256 of the original value
and is offline-brute-forceable for LOW-ENTROPY secrets (HMAC keying needs
the P1.4 managed-secrets work).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import threading
import uuid
import datetime as _dt
from pathlib import Path
from typing import Any, IO, Iterator, Optional

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

_TAIL_WINDOW_INITIAL = 65536
_TAIL_WINDOW_MAX = 16 * 1024 * 1024


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

def _audit_config_or_none() -> Optional[dict]:
    """``audit:`` block from the effective config; None on config FAILURE.

    Distinguishing "config loaded, audit absent/disabled" ({}) from "the
    config system itself failed" (None) lets :func:`get_ledger` apply the
    sticky-on rule instead of failing open on a load error.
    """
    try:
        from lliam_cli import config as _cfg
        return dict(_cfg.load_config().get("audit") or {})
    except Exception:
        return None


def _audit_config() -> dict:
    return _audit_config_or_none() or {}


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

    Containment invariant: the resolved path must live under
    ``<home>/logs`` — the directory the LG-AU-07 write-denylist protects.
    A configured path outside it is REFUSED (logged at critical, default
    used instead) so a config edit can never silently move the ledger off
    the denylist.
    """
    cfg = _audit_config() if cfg is None else cfg
    from lliam_constants import get_lliam_home

    home = get_lliam_home()
    default = home / "logs" / "agent-audit.log"
    raw = str(cfg.get("ledger_path") or "").strip()
    if not raw:
        return default
    candidate: Optional[Path] = None
    for token in ("$HERMES_HOME", "$LLIAM_HOME"):
        if raw == token or raw.startswith(token + "/") or raw.startswith(token + "\\"):
            candidate = home / raw[len(token):].lstrip("/\\")
            break
    if candidate is None:
        candidate = Path(os.path.expanduser(raw))
    logs_root = os.path.realpath(str(home / "logs"))
    resolved = os.path.realpath(str(candidate))
    contained = os.path.normcase(resolved) == os.path.normcase(logs_root) or (
        os.path.normcase(resolved).startswith(os.path.normcase(logs_root) + os.sep)
    )
    if not contained:
        _log.critical(
            "audit.ledger_path %r is outside <home>/logs and would leave the "
            "LG-AU-07 write-denylist — refused; using the default ledger path",
            raw,
        )
        return default
    return candidate


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


def _jsonify(value: Any) -> Any:
    """Coerce arbitrary caller data to JSON-native types BEFORE sealing.

    Real tool arguments/results carry bytes, datetimes, Paths, sets…
    (data-driven, not programming errors). Sealing must be deterministic
    and never crash the caller, so everything is normalized here; only
    taxonomy violations (unknown event/decision/severity) remain
    programming errors that raise.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(k): _jsonify(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonify(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(str(v) for v in value)
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    return str(value)


# --------------------------------------------------------------------------
# Redaction-on-write (LG-AU-05) — unconditional, no runtime disable knob
# --------------------------------------------------------------------------

def _redact_value(value: Any) -> Any:
    """Recursively redact strings via the Phase-0 hard boundary.

    ``force=True`` is mandatory here: redaction on the persistence boundary
    must not be disableable at runtime — and this module exposes NO
    configuration that skips this pass. Dict KEYS are redacted as well as
    values (a credential can sit in key position).
    """
    from agent.redact import redact_sensitive_text

    if isinstance(value, str):
        return redact_sensitive_text(value, force=True)
    if isinstance(value, dict):
        return {
            (redact_sensitive_text(k, force=True) if isinstance(k, str) else k):
                _redact_value(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value


def _redact_object(obj: Optional[dict], *, content_hash: bool) -> Optional[dict]:
    """Redact a record sub-object before persistence (input pre-jsonified).

    For evidentiary fields (``parameters``/``outcome``) a stable
    ``content_hash`` (SHA-256 of the canonical serialization of the
    ORIGINAL object) is retained where redaction masked anything, so an
    investigator can still correlate same-value occurrences without the
    value touching disk (spec §5.2). Residual: unsalted SHA-256 is an
    offline-bruteforce oracle for LOW-entropy originals — accepted until
    HMAC key material exists (P1.4).
    """
    if not obj:
        return obj
    redacted = _redact_value(obj)
    if content_hash and redacted != obj:
        original_bytes = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        redacted["content_hash"] = f"sha256:{_sha256_hex(original_bytes)}"
    return redacted


# --------------------------------------------------------------------------
# OS file locking (multi-writer chain integrity)
# --------------------------------------------------------------------------

if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
    import msvcrt

    def _lock_file(f: IO[bytes]) -> None:
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)

    def _unlock_file(f: IO[bytes]) -> None:
        try:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
else:
    import fcntl

    def _lock_file(f: IO[bytes]) -> None:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)

    def _unlock_file(f: IO[bytes]) -> None:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass


# --------------------------------------------------------------------------
# The ledger
# --------------------------------------------------------------------------

def _new_correlation_id() -> str:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"sess-{ts}-{uuid.uuid4().hex[:8]}"


# Process-level default correlation id — joins all records of one run when
# the caller does not thread a per-operation trace id through.
_SESSION_CORRELATION_ID = _new_correlation_id()


class GovernanceLedger:
    """Append-only hash-chained JSONL ledger (one instance per file).

    Safe for concurrent writers across THREADS (instance lock) and across
    PROCESSES (exclusive OS file lock per append; the chain tail is
    re-read from disk under that lock every time, never trusted from
    memory). Restarts and concurrent writers therefore extend one linear
    chain instead of forking it.
    """

    def __init__(
        self,
        path: Optional[Path] = None,
        *,
        fail_closed: Optional[bool] = None,
        fail_closed_scope: Optional[frozenset[str]] = None,
        sync_fsync_gated: bool = True,
    ) -> None:
        cfg = _audit_config()
        self.path = Path(path) if path is not None else resolve_ledger_path(cfg)
        algo = str(cfg.get("hash_algo") or HASH_ALGO).lower()
        if algo != HASH_ALGO:
            raise ValueError(
                f"audit.hash_algo={algo!r} unsupported — the LG-AU-01 chain "
                f"is pinned to {HASH_ALGO}"
            )
        self.fail_closed = bool(
            cfg.get("fail_closed", True) if fail_closed is None else fail_closed
        )
        scope = (
            fail_closed_scope
            if fail_closed_scope is not None
            else cfg.get("fail_closed_scope")
        )
        self.fail_closed_scope = (
            frozenset(scope) if scope else DEFAULT_FAIL_CLOSED_SCOPE
        )
        # Gated records ALWAYS fsync before emit() returns — LG-AU-09's
        # "persisted before the action proceeds" must be more than
        # page-cache-deep. audit.sync_fsync additionally fsyncs every
        # record (spec §12 opt-in; buffered append is the default).
        self.sync_fsync_gated = bool(sync_fsync_gated)
        self.sync_fsync_all = bool(cfg.get("sync_fsync", False))
        self._lock = threading.Lock()

    # -- tail handling (under the exclusive file lock) ----------------------

    @staticmethod
    def _repair_torn_tail(f: IO[bytes]) -> Optional[str]:
        """Repair bytes after the last newline without deleting evidence.

        A crashed/interrupted writer can leave a partial line at EOF. The
        bytes may be either a complete sealed record whose LF terminator was
        not written, or an invalid partial fragment. Preserve the former by
        appending its terminator; truncate only the latter. Returns the repair
        kind for the caller's ``security.error`` event, or None when intact.
        """
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return None
        f.seek(size - 1)
        if f.read(1) == b"\n":
            return None
        # Find the last newline scanning backward in growing windows.
        window = _TAIL_WINDOW_INITIAL
        while True:
            start = max(0, size - window)
            f.seek(start)
            chunk = f.read(size - start)
            idx = chunk.rfind(b"\n")
            if idx != -1:
                keep = start + idx + 1
                break
            if start == 0:
                keep = 0  # the whole file is one unterminated fragment
                break
            window *= 4
        fragment = chunk[idx + 1:] if idx != -1 else chunk
        try:
            rec = json.loads(fragment.decode("utf-8"))
            sealed = str(rec["record_hash"])
            valid_seal = _sha256_hex(canonical_bytes(rec)) == sealed
        except Exception:
            valid_seal = False
        if valid_seal:
            f.seek(0, os.SEEK_END)
            f.write(b"\n")
            return "terminator_appended"
        f.truncate(keep)
        return "fragment_truncated"

    @staticmethod
    def _read_tail(f: IO[bytes]) -> tuple[int, str]:
        """Return (last_seq, last_record_hash); (0, GENESIS) when empty.

        The window grows until the final line is fully captured, so a
        record larger than the initial window is handled, not treated as
        corruption. The recovered record's seal is RECOMPUTED — a
        syntactically valid but forged tail must not become the chain
        head for new records.
        """
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return 0, GENESIS_PREV_HASH
        window = _TAIL_WINDOW_INITIAL
        while True:
            start = max(0, size - window)
            f.seek(start)
            chunk = f.read(size - start)
            body = chunk[:-1] if chunk.endswith(b"\n") else chunk
            idx = body.rfind(b"\n")
            if idx == -1 and start > 0:
                if window >= _TAIL_WINDOW_MAX:
                    raise AuditWriteError(
                        "audit ledger tail line exceeds the maximum recovery "
                        f"window ({_TAIL_WINDOW_MAX} bytes)"
                    )
                window *= 4
                continue
            last_line = body[idx + 1:] if idx != -1 else body
            break
        if not last_line.strip():
            return 0, GENESIS_PREV_HASH
        try:
            rec = json.loads(last_line.decode("utf-8"))
            seq = int(rec["seq"])
            sealed = str(rec["record_hash"])
        except Exception as e:
            raise AuditWriteError(
                "audit ledger tail unreadable (complete but unparseable last "
                f"line): {e}"
            ) from e
        recomputed = _sha256_hex(canonical_bytes(rec))
        if recomputed != sealed:
            raise AuditWriteError(
                f"audit ledger tail seal mismatch at seq {seq} — the chain "
                "head cannot be trusted (possible tamper)"
            )
        return seq, sealed

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
        trace: Optional[dict] = None,
        source_module: str,
        correlation_id: Optional[str] = None,
        severity: Optional[str] = None,
        seq: int,
        prev_hash: str,
    ) -> dict:
        """Build one schema-versioned, redacted, hash-sealed record.

        EVERY free-form field is jsonified then redacted (LG-AU-05) —
        not only parameters/outcome. ``parameters``/``outcome`` retain a
        ``content_hash`` where masking occurred (evidentiary fields).
        """
        if event not in AUDITABLE_EVENTS:
            raise ValueError(f"unknown auditable event: {event!r}")
        if decision not in _DECISIONS:
            raise ValueError(f"unknown decision: {decision!r}")
        sev = severity or _DEFAULT_SEVERITY.get(event, "info")
        if sev not in SEVERITIES:
            raise ValueError(f"unknown severity: {sev!r}")

        outcome = _jsonify(outcome or {"status": "success", "class": None})
        parameters = _jsonify(parameters) if parameters is not None else None
        outcome = _redact_object(outcome, content_hash=True)
        parameters = _redact_object(parameters, content_hash=True)

        record: dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "seq": seq,
            "event_id": str(uuid.uuid4()),
            "correlation_id": _redact_value(
                _jsonify(correlation_id or _SESSION_CORRELATION_ID)
            ),
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "event": event,
            "severity": sev,
            # Real NPE identity binding (instance_id = code+config+model
            # hash) lands with P1.4 / agent_identity.py.
            "actor": _redact_value(_jsonify(actor or {"type": "npe", "instance_id": None})),
            "subject": _redact_value(_jsonify(subject or {"principal": None})),
            "action": _redact_value(_jsonify(action)),
            "decision": decision,
            "outcome": outcome,
            "source_module": str(source_module),
            "prev_hash": prev_hash,
        }
        if resource is not None:
            record["resource"] = _redact_value(_jsonify(resource))
        if parameters is not None:
            record["parameters"] = parameters
        if approver is not None:
            record["approver"] = _redact_value(_jsonify(approver))
        if trace is not None:
            record["trace"] = _redact_value(_jsonify(trace))
        record["record_hash"] = _sha256_hex(canonical_bytes(record))
        return record

    # -- append (LG-AU-01 / LG-AU-09) ---------------------------------------

    def _append_locked(self, f: IO[bytes], record_fields: dict) -> dict:
        """Seal + append one record; caller holds instance + file locks."""
        repair_kind = self._repair_torn_tail(f)
        seq, prev_hash = self._read_tail(f)
        if repair_kind:
            repair_error = (
                "valid sealed trailing record was missing its LF terminator; "
                "terminator appended"
                if repair_kind == "terminator_appended"
                else "invalid unterminated trailing fragment truncated "
                     "(crashed writer); no sealed record removed"
            )
            note = self.build_record(
                "security.error",
                action="ledger.torn_write_repair",
                outcome={
                    "status": "success",
                    "class": "torn_write_repair",
                    "error": repair_error,
                },
                source_module="agent/governance_audit.py:_repair_torn_tail",
                seq=seq + 1,
                prev_hash=prev_hash,
            )
            f.seek(0, os.SEEK_END)
            f.write((json.dumps(
                note, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ) + "\n").encode("utf-8"))
            seq, prev_hash = note["seq"], note["record_hash"]
        record = self.build_record(
            **record_fields, seq=seq + 1, prev_hash=prev_hash,
        )
        f.seek(0, os.SEEK_END)
        f.write((json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ) + "\n").encode("utf-8"))
        f.flush()
        return record

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
        only consequential actions are hard-gated). Gated records are
        fsynced before this method returns.

        Taxonomy violations (unknown event/decision/severity) are
        programming errors and raise ``ValueError`` — validated up front,
        BEFORE the write path, so they can never masquerade as a write
        failure.
        """
        # Taxonomy validation first: these raise regardless of risk scope.
        if event not in AUDITABLE_EVENTS:
            raise ValueError(f"unknown auditable event: {event!r}")
        decision = fields.get("decision", "n/a")
        if decision not in _DECISIONS:
            raise ValueError(f"unknown decision: {decision!r}")
        sev = fields.get("severity")
        if sev is not None and sev not in SEVERITIES:
            raise ValueError(f"unknown severity: {sev!r}")

        risk = frozenset(risk_scope or ())
        must_block = self.fail_closed and bool(risk & self.fail_closed_scope)
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a+b") as f:
                    _lock_file(f)
                    try:
                        record = self._append_locked(f, {
                            "event": event,
                            "action": action,
                            "source_module": source_module,
                            **fields,
                        })
                        if self.sync_fsync_all or (must_block and self.sync_fsync_gated):
                            os.fsync(f.fileno())
                    finally:
                        _unlock_file(f)
                return record
        except AuditWriteError as e:
            if must_block:
                raise AuditWriteError(
                    f"audit append failed for {event} ({action}); "
                    f"high-risk scope {sorted(risk)} is fail-closed: {e}"
                ) from e
            _log.warning(
                "governance audit append failed (non-gated event %s): %s",
                event, e,
            )
            return None
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


class _PoisonedLedger:
    """Stand-in when the real ledger cannot be constructed (config error).

    Fail-closed, never fail-open: gated emits raise, low-risk emits warn.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        self.fail_closed = True
        self.fail_closed_scope = DEFAULT_FAIL_CLOSED_SCOPE

    def emit(self, event: str, *, risk_scope: Optional[set[str]] = None, **_: Any):
        risk = frozenset(risk_scope or ())
        if risk & self.fail_closed_scope:
            raise AuditWriteError(
                f"audit ledger unavailable ({self.reason}); high-risk scope "
                f"{sorted(risk)} is fail-closed"
            )
        _log.warning(
            "governance audit unavailable (%s); non-gated event %s dropped",
            self.reason, event,
        )
        return None


# --------------------------------------------------------------------------
# Module-level surface (process singleton over the configured ledger)
# --------------------------------------------------------------------------

_ledger_singleton: Optional[Any] = None
_singleton_lock = threading.Lock()
_was_enabled = False
_disable_flip_logged = False


def get_ledger() -> Optional[Any]:
    """Process ledger for the configured path, or None when disabled.

    Sticky-on: once the ledger has been enabled in this process, a later
    config flip to disabled — or a config-load failure — does NOT disable
    it. The flip attempt is recorded to the ledger itself as a
    ``security.error`` (once) and auditing continues. Mid-session silent
    disablement is the worst failure mode for a tamper-evidence system.
    """
    global _ledger_singleton, _was_enabled, _disable_flip_logged
    cfg = _audit_config_or_none()
    enabled_now = bool(cfg and cfg.get("ledger_enabled", False))
    if cfg is not None and not enabled_now and not _was_enabled:
        return None
    with _singleton_lock:
        if _ledger_singleton is None:
            if cfg is None:
                reason = "config load failure"
                _log.critical("governance ledger unavailable: %s", reason)
                _ledger_singleton = _PoisonedLedger(reason)
            else:
                try:
                    _ledger_singleton = GovernanceLedger()
                except Exception as e:
                    _log.critical("governance ledger construction failed: %s", e)
                    _ledger_singleton = _PoisonedLedger(str(e))
        if _was_enabled and not enabled_now and not _disable_flip_logged:
            _disable_flip_logged = True
            reason = (
                "config load failure" if cfg is None
                else "audit.ledger_enabled flipped false mid-session"
            )
            _log.critical(
                "governance ledger disable attempt ignored (sticky-on): %s",
                reason,
            )
            try:
                _ledger_singleton.emit(
                    "security.error",
                    action="ledger.disable_attempt",
                    outcome={"status": "blocked", "class": "sticky_on",
                             "error": reason},
                    source_module="agent/governance_audit.py:get_ledger",
                )
            except Exception:
                pass
        if enabled_now:
            _was_enabled = True
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


# --------------------------------------------------------------------------
# Chain-integrity verification (LG-AU-08, P1.3)
# --------------------------------------------------------------------------

_PARSE_ERROR = object()  # sentinel: an unparseable ledger line (a break)


def _iter_records_guarded(path: Path):
    """Yield ``(index, record)`` pairs; a bad line yields ``_PARSE_ERROR``.

    Unlike :func:`iter_records` (which raises ``JSONDecodeError`` on a
    corrupt line — appropriate for callers that want to fail hard),
    verification must treat a corrupt line as a detectable break, not an
    exception the caller might swallow as benign.
    """
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for index, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                yield index, json.loads(line)
            except (json.JSONDecodeError, ValueError):
                yield index, _PARSE_ERROR
                return


class ChainVerificationResult:
    """Outcome of :func:`verify_chain`.

    ``ok`` is True only when every checked record's ``record_hash`` matches
    a recompute of its canonical bytes AND its ``prev_hash`` links to the
    prior record AND ``seq`` is contiguous. ``break_seq`` / ``reason`` name
    the FIRST failure so an operator/CI can point at the exact record.
    """

    __slots__ = ("ok", "checked", "total", "break_seq", "break_index", "reason", "ledger_path")

    def __init__(
        self,
        *,
        ok: bool,
        checked: int,
        total: int,
        break_seq: Optional[int] = None,
        break_index: Optional[int] = None,
        reason: Optional[str] = None,
        ledger_path: Optional[str] = None,
    ) -> None:
        self.ok = ok
        self.checked = checked
        self.total = total
        self.break_seq = break_seq
        self.break_index = break_index
        self.reason = reason
        self.ledger_path = ledger_path

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "checked": self.checked,
            "total": self.total,
            "break_seq": self.break_seq,
            "break_index": self.break_index,
            "reason": self.reason,
            "ledger_path": self.ledger_path,
        }

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        if self.ok:
            return f"<ChainVerification PASS checked={self.checked}>"
        return (
            f"<ChainVerification FAIL at seq={self.break_seq} "
            f"index={self.break_index}: {self.reason}>"
        )


def verify_chain(
    path: Optional[Path] = None,
    *,
    start_after_seq: int = 0,
    start_prev_hash: str = GENESIS_PREV_HASH,
) -> ChainVerificationResult:
    """Walk the ledger and validate every ``prev_hash`` + ``record_hash`` link.

    Returns a :class:`ChainVerificationResult`; the FIRST break stops the
    walk and is reported (an operator only needs the earliest tamper point,
    and later hashes are meaningless once the chain is broken). A missing or
    empty ledger verifies as PASS with ``total=0`` — there is nothing to
    tamper with.

    Segment verification (``start_after_seq`` / ``start_prev_hash``) lets a
    caller verify only the records after a known-good anchor, so startup
    cost stays O(segment) once external anchoring exists (spec §4.3); the
    default verifies the whole chain. When ``start_after_seq > 0`` the
    anchor record's on-disk ``record_hash`` must match the caller-supplied
    ``start_prev_hash`` (the trusted anchor value) AND recompute to its own
    seal — otherwise the anchor itself is reported as the break, so the
    trusted anchor is never taken on faith.

    An unparseable ledger line is a FAIL (a corrupt line is a tamper
    signal, not a benign error) — this method never raises on ledger
    content, so callers cannot mistake corruption for "nothing to verify".

    Accepted residual (deferred to external anchoring, spec §4.2): a
    consistent PREFIX left by suffix-truncation or a whole-file deletion
    verifies as PASS — an internal hash chain has no high-water mark of its
    own. ``checked``/``total`` are returned so a caller holding an external
    record count can detect shrinkage; the standing detective control for
    full-file rewrite/truncation is external anchoring + this count.
    """
    p = Path(path) if path is not None else resolve_ledger_path()
    checked = 0
    total = 0
    expected_prev = start_prev_hash
    expected_seq = start_after_seq + 1
    started = start_after_seq == 0
    for index, record in _iter_records_guarded(p):
        if record is _PARSE_ERROR:
            return ChainVerificationResult(
                ok=False, checked=checked, total=total + 1, break_index=index,
                reason="unparseable ledger line (corruption or partial write)",
                ledger_path=str(p),
            )
        total += 1
        seq = record.get("seq")
        # Fast-forward to the segment start when verifying after an anchor.
        if not started:
            if seq == start_after_seq:
                sealed = record.get("record_hash")
                if _sha256_hex(canonical_bytes(record)) != sealed:
                    return ChainVerificationResult(
                        ok=False, checked=checked, total=total,
                        break_seq=seq, break_index=index,
                        reason="anchor record seal mismatch (anchor itself edited)",
                        ledger_path=str(p),
                    )
                if start_prev_hash != GENESIS_PREV_HASH and sealed != start_prev_hash:
                    return ChainVerificationResult(
                        ok=False, checked=checked, total=total,
                        break_seq=seq, break_index=index,
                        reason=(
                            "anchor record_hash does not match the trusted "
                            "start_prev_hash (forged/wrong anchor)"
                        ),
                        ledger_path=str(p),
                    )
                started = True
                expected_prev = str(sealed)
                expected_seq = start_after_seq + 1
            continue
        if not isinstance(seq, int) or seq != expected_seq:
            return ChainVerificationResult(
                ok=False, checked=checked, total=total,
                break_seq=seq if isinstance(seq, int) else None,
                break_index=index,
                reason=f"non-contiguous seq: expected {expected_seq}, got {seq!r}",
                ledger_path=str(p),
            )
        prev = record.get("prev_hash")
        if prev != expected_prev:
            return ChainVerificationResult(
                ok=False, checked=checked, total=total, break_seq=seq,
                break_index=index,
                reason=(
                    f"prev_hash mismatch: expected {expected_prev}, "
                    f"got {prev!r} (deletion/reorder/insert)"
                ),
                ledger_path=str(p),
            )
        sealed = record.get("record_hash")
        recomputed = _sha256_hex(canonical_bytes(record))
        if sealed != recomputed:
            return ChainVerificationResult(
                ok=False, checked=checked, total=total, break_seq=seq,
                break_index=index,
                reason="record_hash mismatch: record content was edited in place",
                ledger_path=str(p),
            )
        checked += 1
        expected_prev = str(sealed)
        expected_seq = seq + 1
    if not started and start_after_seq != 0:
        return ChainVerificationResult(
            ok=False, checked=checked, total=total,
            reason=f"anchor seq {start_after_seq} not found in ledger",
            ledger_path=str(p),
        )
    return ChainVerificationResult(
        ok=True, checked=checked, total=total, ledger_path=str(p),
    )
