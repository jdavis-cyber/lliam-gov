"""Append-only hash-chained audit logger for Lliam-GOV.

Plan §5.2. Maps to control matrix rows ``SP800-171_3.3.1``, ``3.3.2``,
``3.3.4``, ``3.3.8``, ``3.3.9``; ``ISO27001_A.8.15``, ``A.8.16``;
``ISO42001_Clause_7.5``, ``ISO42001_Clause_9.1``; and
``ISO42001_A.6.2.8``.

Audit records are JSONL at ``~/.lliam-gov/audit/tool-calls-YYYY-MM.jsonl``.
Each line is canonical key-sorted JSON. ``prev_hash`` is the SHA-256 digest
of the prior canonical line; the first record in every monthly file uses
``GENESIS_HASH``. Raw tool parameters are never written — only
``params_hash`` is persisted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import threading
from typing import Any

try:
    import fcntl  # POSIX advisory inter-process file locking
except ImportError:  # pragma: no cover - non-POSIX platforms (e.g. Windows)
    fcntl = None  # type: ignore[assignment]

from hermes_constants import get_hermes_home


AUDIT_FILE_PREFIX = "tool-calls"
AUDIT_FILE_SUFFIX = ".jsonl"
HASH_PREFIX = "sha256:"
_shared_audit_logger: AuditLogger | None = None
_shared_audit_logger_lock = threading.Lock()


def _flock_exclusive(fd: int) -> None:
    """Take an exclusive advisory lock on ``fd`` (no-op off POSIX)."""

    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX)


def _flock_release(fd: int) -> None:
    """Release the advisory lock on ``fd`` (no-op off POSIX)."""

    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)


class AuditLoggerError(Exception):
    """Base class for audit-logger failures."""


class AuditLoggerOpenError(AuditLoggerError):
    """Raised when the audit logger cannot open its append-only file."""


class AuditLoggerWriteError(AuditLoggerError):
    """Raised when an audit record cannot be written durably."""


class AuditChainError(AuditLoggerError):
    """Raised when audit-chain verification detects tampering/corruption."""


@dataclass(frozen=True)
class AuditWriteResult:
    """Result returned after a record is appended."""

    path: Path
    record_hash: str
    record: dict[str, Any]


@dataclass(frozen=True)
class AuditChainVerification:
    """Summary returned after verifying a JSONL audit chain."""

    path: Path
    record_count: int
    last_hash: str


def canonical_json(value: Any) -> str:
    """Return deterministic JSON suitable for hashing and JSONL storage."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_text(value: str) -> str:
    return HASH_PREFIX + hashlib.sha256(value.encode("utf-8")).hexdigest()


def params_hash(params: Any) -> str:
    """Hash tool parameters as canonical JSON without storing raw values."""

    return sha256_text(canonical_json(params))


def verify_audit_chain(
    path: str | Path,
    *,
    expected_last_hash: str | None = None,
) -> AuditChainVerification:
    """Verify ``prev_hash`` across a monthly JSONL audit file.

    The first record in each monthly file must point at
    :data:`AuditLogger.GENESIS_HASH`. For every later record, ``prev_hash``
    must equal the SHA-256 digest of the previous canonical line.
    """

    audit_path = Path(path)
    previous_hash = AuditLogger.GENESIS_HASH
    count = 0

    try:
        lines = audit_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AuditChainError(f"cannot read audit chain {audit_path}: {exc}") from exc

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditChainError(
                f"invalid JSON at {audit_path}:{line_number}: {exc}"
            ) from exc

        observed_prev = record.get("prev_hash")
        if line_number == 1 and observed_prev != AuditLogger.GENESIS_HASH:
            raise AuditChainError(
                f"genesis prev_hash mismatch at {audit_path}:{line_number}"
            )
        if observed_prev != previous_hash:
            raise AuditChainError(
                "prev_hash mismatch at "
                f"{audit_path}:{line_number}: expected {previous_hash}, "
                f"got {observed_prev}"
            )

        canonical_line = canonical_json(record)
        previous_hash = sha256_text(canonical_line)
        count += 1

    if expected_last_hash is not None and previous_hash != expected_last_hash:
        raise AuditChainError(
            "last_hash mismatch at "
            f"{audit_path}: expected {expected_last_hash}, got {previous_hash}"
        )

    return AuditChainVerification(
        path=audit_path,
        record_count=count,
        last_hash=previous_hash,
    )


class AuditLogger:
    """Append JSONL audit records with monthly hash chains."""

    GENESIS_HASH = "sha256:" + ("0" * 64)

    def __init__(
        self,
        *,
        audit_dir: str | Path | None = None,
        session_id: str | None = None,
        principal: str | None = None,
        host: str | None = None,
        pid: int | None = None,
        agent_version: str | None = None,
    ) -> None:
        self.audit_dir = (
            Path(audit_dir) if audit_dir is not None else get_hermes_home() / "audit"
        )
        self.archive_dir = self.audit_dir / "archive"
        self.session_id = session_id
        if principal is None:
            # Authenticated OS principal (euid -> passwd), not spoofable env
            # vars (LG-4.1 / AI-218). Explicit principal args win (tests,
            # gateway-attributed events).
            from lliam_gov.security.principal import get_principal

            principal = get_principal().username
        self.principal = principal
        self.host = host or socket.gethostname()
        self.pid = pid or os.getpid()
        self.agent_version = agent_version or _agent_version()
        self._current_month: str | None = None
        self._previous_hash = self.GENESIS_HASH
        self._lock = threading.RLock()

    def log_event(
        self,
        *,
        event_type: str,
        session_id: str | None = None,
        principal: str | None = None,
        host: str | None = None,
        pid: int | None = None,
        agent_version: str | None = None,
        model_id: str | None = None,
        tool_name: str | None = None,
        tool_call_id: str | None = None,
        params: Any | None = None,
        marker: str | None = None,
        destination: str | None = None,
        duration_ms: int | None = None,
        blocked: bool = False,
        block_reason: str | None = None,
        error: str | None = None,
        at: datetime | None = None,
    ) -> AuditWriteResult:
        """Append one audit event, failing closed on open/write errors."""

        with self._lock:
            event_time = _utc(at)
            month = event_time.strftime("%Y-%m")
            self._ensure_month(month)
            path = self._audit_path(month)

            record: dict[str, Any] = {
                "timestamp_ms_utc": int(event_time.timestamp() * 1000),
                "session_id": session_id or self.session_id,
                "principal": principal or self.principal,
                "host": host or self.host,
                "pid": pid or self.pid,
                "agent_version": agent_version or self.agent_version,
                "model_id": model_id,
                "event_type": event_type,
                "tool_name": tool_name,
                "tool_call_id": tool_call_id,
                "params_hash": params_hash({} if params is None else params),
                # CUI chain-of-custody fields (LG-4.6): marker + destination
                # are readable evidence; payload content stays hashed.
                "marker": marker,
                "destination": destination,
                "duration_ms": duration_ms,
                "blocked": blocked,
                "block_reason": block_reason,
                "error": error,
                "prev_hash": self._previous_hash,
            }

            # ``prev_hash`` set above is only a cache-derived placeholder. The
            # authoritative value is recomputed inside ``_append_chained`` from
            # the file's real tail while holding an inter-process lock
            # (issue #69), so a concurrent app+CLI write can never fork the
            # hash chain into a false "tamper" state.
            result = self._append_chained(path, record)
            self._previous_hash = result.record_hash
            return result

    def verify_current_month(self) -> AuditChainVerification:
        with self._lock:
            if self._current_month is None:
                return AuditChainVerification(
                    path=self._audit_path(_utc(None).strftime("%Y-%m")),
                    record_count=0,
                    last_hash=self.GENESIS_HASH,
                )
            return verify_audit_chain(self._audit_path(self._current_month))

    def _ensure_month(self, month: str) -> None:
        self._ensure_dirs()
        if self._current_month == month:
            return

        self._archive_prior_active_files(month)
        path = self._audit_path(month)
        if path.is_file():
            verification = verify_audit_chain(path)
            self._previous_hash = verification.last_hash
        else:
            self._previous_hash = self.GENESIS_HASH
        self._current_month = month

    def _ensure_dirs(self) -> None:
        for directory in (self.audit_dir, self.archive_dir):
            try:
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(directory, 0o700)
            except OSError as exc:
                raise AuditLoggerOpenError(
                    f"cannot prepare audit directory {directory}: {exc}"
                ) from exc

    def _archive_prior_active_files(self, target_month: str) -> None:
        pattern = f"{AUDIT_FILE_PREFIX}-*{AUDIT_FILE_SUFFIX}"
        for path in self.audit_dir.glob(pattern):
            if not path.is_file():
                continue
            month = _month_from_path(path)
            if month is None or month >= target_month:
                continue
            archive_path = self.archive_dir / path.name
            try:
                if archive_path.exists():
                    os.chmod(archive_path, 0o600)
                    archive_path.unlink()
                path.replace(archive_path)
                os.chmod(archive_path, 0o400)
            except OSError as exc:
                raise AuditLoggerOpenError(
                    f"cannot rotate audit file {path} to {archive_path}: {exc}"
                ) from exc

    def _append_chained(self, path: Path, record: dict[str, Any]) -> AuditWriteResult:
        """Append one record, chaining from the file's *real* tail.

        Correctness under concurrent writers (issue #69): the desktop app and a
        ``hermes`` CLI turn are separate processes, each with its own in-memory
        ``_previous_hash``. To stop their writes forking the chain we:

        1. take an exclusive ``flock`` on the monthly file (serialises across
           processes, not just threads), then
        2. *while holding the lock* re-read the actual last line and derive
           ``prev_hash`` from it — never from the possibly-stale cache, then
        3. write under ``O_APPEND`` (atomic at end-of-file) and ``fsync``,
           then release.

        Read-tail and write therefore live in one critical section, so two
        writers serialise and the chain stays single-threaded on disk.
        """

        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
        try:
            fd = os.open(path, flags, 0o600)
        except OSError as exc:
            raise AuditLoggerOpenError(f"cannot open audit log {path}: {exc}") from exc

        try:
            os.chmod(path, 0o600)
            _flock_exclusive(fd)
            try:
                record["prev_hash"] = self._tail_hash(fd)
                line = canonical_json(record)
                record_hash = sha256_text(line)
                os.write(fd, (line + "\n").encode("utf-8"))
                os.fsync(fd)
            finally:
                _flock_release(fd)
        except OSError as exc:
            raise AuditLoggerWriteError(
                f"cannot write audit log {path}: {exc}"
            ) from exc
        finally:
            os.close(fd)

        return AuditWriteResult(path=path, record_hash=record_hash, record=record)

    @staticmethod
    def _tail_hash(fd: int) -> str:
        """Return ``sha256:`` of the last non-empty line currently in ``fd``.

        Reads backwards from EOF, so the cost is the size of the final record
        rather than the whole month. Returns :data:`GENESIS_HASH` for an empty
        file. Must be called while holding the file's exclusive lock so the
        tail reflects every prior writer (issue #69).
        """

        size = os.fstat(fd).st_size
        if size == 0:
            return AuditLogger.GENESIS_HASH

        chunk = 8192
        data = b""
        pos = size
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            data = os.pread(fd, step, pos) + data
            stripped = data.rstrip(b"\n")
            if b"\n" in stripped or pos == 0:
                last_line = stripped.rsplit(b"\n", 1)[-1]
                if not last_line:
                    return AuditLogger.GENESIS_HASH
                return sha256_text(last_line.decode("utf-8"))
        return AuditLogger.GENESIS_HASH

    def _audit_path(self, month: str) -> Path:
        return self.audit_dir / f"{AUDIT_FILE_PREFIX}-{month}{AUDIT_FILE_SUFFIX}"


def get_shared_audit_logger(
    *,
    audit_dir: str | Path | None = None,
    session_id: str | None = None,
    principal: str | None = None,
) -> AuditLogger:
    """Return the process-wide audit logger used by session and tool events."""

    # Production root refusal (LG-4.1): the shared audit logger is the choke
    # point every governed operation passes through.
    from lliam_gov.security.principal import require_principal

    require_principal()

    global _shared_audit_logger
    target_dir = (
        Path(audit_dir) if audit_dir is not None else get_hermes_home() / "audit"
    )
    with _shared_audit_logger_lock:
        if (
            _shared_audit_logger is None
            or _shared_audit_logger.audit_dir != target_dir
        ):
            _shared_audit_logger = AuditLogger(
                audit_dir=target_dir,
                session_id=session_id,
                principal=principal,
            )
        return _shared_audit_logger


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _month_from_path(path: Path) -> str | None:
    name = path.name
    prefix = f"{AUDIT_FILE_PREFIX}-"
    if not name.startswith(prefix) or not name.endswith(AUDIT_FILE_SUFFIX):
        return None
    month = name[len(prefix) : -len(AUDIT_FILE_SUFFIX)]
    if len(month) != 7 or month[4] != "-":
        return None
    return month


def _agent_version() -> str:
    try:
        from importlib.metadata import version

        return version("lliam-gov")
    except Exception:
        return f"unknown-python-{platform.python_version()}"


__all__ = [
    "AuditChainError",
    "AuditChainVerification",
    "AuditLogger",
    "AuditLoggerError",
    "AuditLoggerOpenError",
    "AuditLoggerWriteError",
    "AuditWriteResult",
    "canonical_json",
    "params_hash",
    "verify_audit_chain",
]
