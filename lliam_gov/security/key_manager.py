"""AES-256-GCM encryption at rest with macOS-Keychain-backed key material.

Plan §5.1. Maps to control matrix rows ``SP800-171_3.5.10``, ``3.8.9``,
``3.13.11``, ``3.13.16``; ``ISO27001_A.8.24``; ``ISO42001_A.4.3``.

Wire format (returned by :meth:`KeyManager.encrypt`)::

    [ version:1 | iv:12 | auth_tag:16 | ciphertext:N ]

Key derivation:

* A 32-byte machine secret and a 16-byte salt are generated on first boot
  and persisted in the macOS Keychain under service ``lliam-gov`` /
  accounts ``encryption-secret`` and ``encryption-salt``.
* The AES-256 key is scrypt-derived (``N=16384, r=8, p=1, dkLen=32``)
  from those values and held only in process memory — never written to
  disk.

The TypeScript reference at ``lliam_ai_agent/src/security/key-manager.ts``
informed the wire format. Two intentional departures: (a) Python's
``cryptography`` package, when linked against a FIPS-validated OpenSSL,
satisfies the §5.1 FIPS hard requirement that Node's ``node:crypto``
cannot — the probe lives in :mod:`lliam_gov.security.runtime_guard`;
(b) tests inject a fake keyring backend so the real Keychain is never
touched by the suite.
"""

from __future__ import annotations

import os
import secrets
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ─── Constants ──────────────────────────────────────────────────────────────

DEFAULT_KEYCHAIN_SERVICE = "lliam-gov"
KEYCHAIN_ACCOUNT_SECRET = "encryption-secret"
KEYCHAIN_ACCOUNT_SALT = "encryption-salt"

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32  # AES-256
IV_LENGTH = 12  # 96-bit nonce (GCM-recommended)
TAG_LENGTH = 16  # 128-bit GCM auth tag

# Wire-format version. Bump only on a breaking change to the layout; the
# byte is checked at decrypt and old versions are rejected so a stale
# ciphertext can't be silently misinterpreted under a new layout.
FORMAT_VERSION = 0x01

SECRET_NBYTES = 32
SALT_NBYTES = 16

_VERSION_BYTE_LEN = 1
_HEADER_LEN = _VERSION_BYTE_LEN + IV_LENGTH + TAG_LENGTH


# ─── Keyring backend protocol ───────────────────────────────────────────────

class KeyringBackend(Protocol):
    """Minimal surface used by :class:`KeyManager`.

    The default backend is the ``keyring`` package's module-level API,
    which resolves to the macOS Keychain on the deployment host. Tests
    inject an in-memory fake.
    """

    def get_password(self, service: str, account: str) -> str | None: ...
    def set_password(self, service: str, account: str, password: str) -> None: ...
    def delete_password(self, service: str, account: str) -> None: ...


class _DefaultKeyringBackend:
    """Adapter that delegates to the installed ``keyring`` package."""

    def get_password(self, service: str, account: str) -> str | None:
        import keyring
        return keyring.get_password(service, account)

    def set_password(self, service: str, account: str, password: str) -> None:
        import keyring
        keyring.set_password(service, account, password)

    def delete_password(self, service: str, account: str) -> None:
        import keyring
        from keyring.errors import PasswordDeleteError
        try:
            keyring.delete_password(service, account)
        except PasswordDeleteError:
            pass


# ─── Errors ─────────────────────────────────────────────────────────────────

class KeyManagerError(Exception):
    """Base class for key-manager failures."""


class UnsupportedFormatVersion(KeyManagerError):
    """Decrypt was called on a buffer whose version byte we don't recognize."""


class NotInitializedError(KeyManagerError):
    """encrypt/decrypt was called before :meth:`KeyManager.init`."""


# ─── KeyManager ─────────────────────────────────────────────────────────────

class KeyManager:
    """Encrypt/decrypt bytes with a Keychain-anchored AES-256-GCM key.

    Lifecycle::

        km = KeyManager()
        km.init()                       # load-or-generate Keychain material
        ct = km.encrypt(b"plaintext")
        pt = km.decrypt(ct)
    """

    def __init__(
        self,
        *,
        service: str = DEFAULT_KEYCHAIN_SERVICE,
        backend: KeyringBackend | None = None,
    ) -> None:
        self._service = service
        self._backend: KeyringBackend = backend or _DefaultKeyringBackend()
        self._derived_key: bytes | None = None

    # ── public API ──────────────────────────────────────────────────────

    def init(self) -> None:
        """Load or generate the Keychain secret + salt and derive the key.

        Idempotent: re-calling re-derives from the current Keychain state,
        which is how :meth:`rotate_key` clients pick up the new material.
        """
        secret, salt = self._get_or_create_secret()
        self._derived_key = self._derive_key(secret, salt)

    def is_ready(self) -> bool:
        return self._derived_key is not None

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` and return ``[version|iv|tag|ct]``."""
        key = self._require_key()
        iv = secrets.token_bytes(IV_LENGTH)
        # AESGCM.encrypt returns ciphertext || auth_tag concatenated; we
        # split the tag back out so the wire format puts it in the header
        # (decrypt cost is one less slice on the hot path, and tampering
        # with the tag is detected before any ciphertext bytes are touched).
        aead = AESGCM(key)
        ct_and_tag = aead.encrypt(iv, plaintext, associated_data=None)
        ciphertext = ct_and_tag[:-TAG_LENGTH]
        auth_tag = ct_and_tag[-TAG_LENGTH:]
        return bytes([FORMAT_VERSION]) + iv + auth_tag + ciphertext

    def decrypt(self, encrypted: bytes) -> bytes:
        """Decrypt a buffer produced by :meth:`encrypt`.

        Raises ``cryptography.exceptions.InvalidTag`` if the auth tag
        does not verify (tamper detection). Raises
        :class:`UnsupportedFormatVersion` for an unknown version byte.
        """
        key = self._require_key()
        if len(encrypted) < _HEADER_LEN:
            raise KeyManagerError("ciphertext shorter than header")
        version = encrypted[0]
        if version != FORMAT_VERSION:
            raise UnsupportedFormatVersion(
                f"unsupported encryption format version: {version:#x}"
            )
        iv = encrypted[_VERSION_BYTE_LEN : _VERSION_BYTE_LEN + IV_LENGTH]
        auth_tag = encrypted[
            _VERSION_BYTE_LEN + IV_LENGTH : _HEADER_LEN
        ]
        ciphertext = encrypted[_HEADER_LEN:]
        aead = AESGCM(key)
        return aead.decrypt(iv, ciphertext + auth_tag, associated_data=None)

    def is_encrypted(self, buffer: bytes) -> bool:
        """Cheap heuristic: looks like our wire format.

        Used by the (future) ``EncryptedFile`` migration path to detect
        legacy plaintext on disk. Not a security check — a plaintext
        whose first byte happens to be ``0x01`` will pass this test
        and fail decrypt loudly.
        """
        if len(buffer) < _HEADER_LEN + 1:
            return False
        return buffer[0] == FORMAT_VERSION

    def rotate_key(self) -> None:
        """Generate fresh Keychain material and clear the in-memory key.

        Atomic file re-keying (write-new + fsync + swap + unlink-old) is
        the caller's responsibility and lives at the ``EncryptedFile``
        layer (subsequent PR). After this returns the caller must call
        :meth:`init` again before encrypt/decrypt.
        """
        secret_hex = secrets.token_bytes(SECRET_NBYTES).hex()
        salt_hex = secrets.token_bytes(SALT_NBYTES).hex()
        self._backend.set_password(self._service, KEYCHAIN_ACCOUNT_SECRET, secret_hex)
        self._backend.set_password(self._service, KEYCHAIN_ACCOUNT_SALT, salt_hex)
        self._derived_key = None

    # ── internals ───────────────────────────────────────────────────────

    def _require_key(self) -> bytes:
        if self._derived_key is None:
            raise NotInitializedError(
                "KeyManager not initialized — call init() first."
            )
        return self._derived_key

    def _get_or_create_secret(self) -> tuple[bytes, bytes]:
        secret_hex = self._backend.get_password(self._service, KEYCHAIN_ACCOUNT_SECRET)
        salt_hex = self._backend.get_password(self._service, KEYCHAIN_ACCOUNT_SALT)
        if secret_hex is None or salt_hex is None:
            secret_hex = secrets.token_bytes(SECRET_NBYTES).hex()
            salt_hex = secrets.token_bytes(SALT_NBYTES).hex()
            self._backend.set_password(
                self._service, KEYCHAIN_ACCOUNT_SECRET, secret_hex
            )
            self._backend.set_password(
                self._service, KEYCHAIN_ACCOUNT_SALT, salt_hex
            )
        return bytes.fromhex(secret_hex), bytes.fromhex(salt_hex)

    @staticmethod
    def _derive_key(secret: bytes, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=KEY_LENGTH, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        return kdf.derive(secret)


__all__ = [
    "KeyManager",
    "KeyManagerError",
    "KeyringBackend",
    "NotInitializedError",
    "UnsupportedFormatVersion",
    "DEFAULT_KEYCHAIN_SERVICE",
    "KEYCHAIN_ACCOUNT_SECRET",
    "KEYCHAIN_ACCOUNT_SALT",
    "FORMAT_VERSION",
    "IV_LENGTH",
    "TAG_LENGTH",
]


# Suppress an unused-import lint if os ever gets dropped — keeping the
# import slot for the file-mode constants that EncryptedFile will need.
_ = os
