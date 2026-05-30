"""``EncryptedFile`` — AES-256-GCM encryption-at-rest for persisted state.

Plan §5.1, LG-3.7 / AI-215 (the encryption-at-rest linchpin). This module is the
**abstraction**; routing the individual persisted-state writers (session state,
credential/auth cache, backups) through it is the companion slice.

Every persisted write goes through :class:`EncryptedFile`, which encrypts with the
process-wide :class:`~lliam_gov.security.key_manager.KeyManager`
(AES-256-GCM, Keychain-anchored key) and writes **atomically** (temp file in the
same directory, ``fsync``, ``os.replace``) at mode ``0600`` under dirs created
``0700`` — matching the audit logger's on-disk posture.

Reads fail closed on tampering: a corrupted ciphertext raises
``cryptography.exceptions.InvalidTag`` rather than returning partial/altered
plaintext. A one-way migration helper (:meth:`EncryptedFile.migrate_plaintext`)
converts a legacy cleartext file in place.

FIPS: :func:`get_shared_key_manager` runs the §5.1 FIPS hard gate
(:func:`lliam_gov.security.runtime_guard.fips_check`) before any key material is
derived, so a non-FIPS production backend fails closed. Development hosts opt out
with ``LLIAM_GOV_ALLOW_NON_FIPS=1``.

Maps to: SP 800-171 3.5.10, 3.8.9, 3.13.11, 3.13.16; ISO/IEC 27001 A.8.24;
ISO/IEC 42001 A.4.3.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from lliam_gov.security.key_manager import KeyManager
from lliam_gov.security.runtime_guard import fips_check

_FILE_MODE = 0o600
_DIR_MODE = 0o700

_shared_key_manager: KeyManager | None = None
_shared_key_manager_lock = threading.Lock()


class EncryptedFileError(Exception):
    """Base class for :class:`EncryptedFile` failures."""


class PlaintextDetectedError(EncryptedFileError):
    """A read expected ciphertext but the file is not in the wire format."""


def get_shared_key_manager() -> KeyManager:
    """Return the process-wide initialized :class:`KeyManager`.

    Runs the FIPS hard gate before deriving key material (fail-closed on a
    non-FIPS backend unless ``LLIAM_GOV_ALLOW_NON_FIPS=1``), then lazily creates
    and ``init()``-s a single shared manager. This is the encryption counterpart
    to ``audit_logger.get_shared_audit_logger``.
    """
    global _shared_key_manager
    with _shared_key_manager_lock:
        if _shared_key_manager is None:
            fips_check()
            manager = KeyManager()
            manager.init()
            _shared_key_manager = manager
        return _shared_key_manager


def reset_shared_key_manager() -> None:
    """Drop the cached shared manager (used after rotate-key and in tests)."""
    global _shared_key_manager
    with _shared_key_manager_lock:
        _shared_key_manager = None


class EncryptedFile:
    """A file whose contents are encrypted at rest with AES-256-GCM.

    Args:
        path: Destination path. Parent directories are created ``0700`` on write.
        key_manager: Key manager to use; defaults to the process-wide shared
            manager. Tests inject a ``KeyManager`` backed by a fake keyring.
    """

    def __init__(
        self, path: str | Path, *, key_manager: KeyManager | None = None
    ) -> None:
        self.path = Path(path)
        self._key_manager = key_manager

    # ── key access ───────────────────────────────────────────────────────

    @property
    def key_manager(self) -> KeyManager:
        return self._key_manager or get_shared_key_manager()

    # ── existence / removal ──────────────────────────────────────────────

    def exists(self) -> bool:
        return self.path.is_file()

    def unlink(self, *, missing_ok: bool = True) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            if not missing_ok:
                raise

    # ── byte I/O ─────────────────────────────────────────────────────────

    def write_bytes(self, data: bytes) -> None:
        """Encrypt ``data`` and write it atomically at mode 0600."""
        ciphertext = self.key_manager.encrypt(data)
        self._atomic_write(ciphertext)

    def read_bytes(self) -> bytes:
        """Decrypt and return the file contents.

        Raises ``cryptography.exceptions.InvalidTag`` on tampering and
        :class:`PlaintextDetectedError` if the file is not in the wire format
        (use :meth:`migrate_plaintext` to convert a legacy cleartext file).
        """
        raw = self.path.read_bytes()
        if not self.key_manager.is_encrypted(raw):
            raise PlaintextDetectedError(
                f"{self.path} is not an encrypted Lliam-GOV file; "
                "use migrate_plaintext() to convert legacy cleartext."
            )
        return self.key_manager.decrypt(raw)

    # ── text / JSON convenience ──────────────────────────────────────────

    def write_text(self, text: str, *, encoding: str = "utf-8") -> None:
        self.write_bytes(text.encode(encoding))

    def read_text(self, *, encoding: str = "utf-8") -> str:
        return self.read_bytes().decode(encoding)

    def write_json(self, obj: Any, *, sort_keys: bool = False) -> None:
        self.write_text(json.dumps(obj, sort_keys=sort_keys, separators=(",", ":")))

    def read_json(self) -> Any:
        return json.loads(self.read_text())

    # ── migration ────────────────────────────────────────────────────────

    def migrate_plaintext(self) -> bool:
        """Encrypt an existing legacy cleartext file in place, atomically.

        Returns ``True`` if a plaintext file was migrated, ``False`` if the file
        is already encrypted (idempotent) or absent. The read-then-atomic-write
        means an interrupted migration leaves the original intact.
        """
        if not self.path.is_file():
            return False
        raw = self.path.read_bytes()
        if self.key_manager.is_encrypted(raw):
            return False
        self._atomic_write(self.key_manager.encrypt(raw))
        return True

    # ── internals ────────────────────────────────────────────────────────

    def _atomic_write(self, payload: bytes) -> None:
        directory = self.path.parent
        directory.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        # Temp file in the SAME directory so os.replace is a same-filesystem
        # atomic rename (cross-device would not be atomic).
        fd, tmp_name = _mkstemp_secure(directory, self.path.name)
        tmp_path = Path(tmp_name)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.chmod(tmp_path, _FILE_MODE)
            os.replace(tmp_path, self.path)
        except OSError:
            tmp_path.unlink(missing_ok=True)
            raise
        # fsync the directory so the rename is durable across a crash.
        try:
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            # Directory fsync is a durability nicety; not all platforms permit
            # opening a directory for fsync. The rename itself already landed.
            pass


def _mkstemp_secure(directory: Path, base_name: str) -> tuple[int, str]:
    import tempfile

    return tempfile.mkstemp(prefix=f".{base_name}.", suffix=".tmp", dir=str(directory))


__all__ = [
    "EncryptedFile",
    "EncryptedFileError",
    "PlaintextDetectedError",
    "get_shared_key_manager",
    "reset_shared_key_manager",
]
