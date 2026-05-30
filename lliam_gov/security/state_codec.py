"""Encryption codec for persisted-state files (LG-3.7 / AI-215, PR 2 of 2).

Routes the credential/auth store (``~/.lliam-gov/auth.json``) through
AES-256-GCM at rest while keeping a single, safe migration story:

* **Decrypt-on-read is unconditional.** :func:`decode_state_bytes` inspects the
  first byte: a legacy plaintext JSON file starts with ``{`` (0x7b) and is
  returned verbatim; only a file in the :mod:`encrypted_file` wire format
  (version byte ``0x01``) is decrypted. The Keychain is therefore touched
  **only** when the file is actually encrypted — plaintext reads never trigger
  key derivation, so CI/dev hosts without a Keychain are unaffected.
* **Encrypt-on-write is gated** by :func:`state_encryption_enabled`
  (``LLIAM_GOV_ENCRYPT_STATE=1``). Default-off keeps dev/CI writing plaintext;
  the production profile and the AI-217 24-hour smoke run set it to ``1``.

This asymmetry means the flag can be flipped in either direction without a
manual migration step: turn it on and the next save encrypts; an already
encrypted file still decrypts on read even with the flag off.

Maps to: SP 800-171 3.5.10 (no plaintext credentials at rest), 3.8.9, 3.13.16;
ISO/IEC 27001 A.8.24; ISO/IEC 42001 A.4.3.
"""

from __future__ import annotations

import os

from lliam_gov.security.key_manager import (
    FORMAT_VERSION,
    IV_LENGTH,
    TAG_LENGTH,
    KeyManager,
)

STATE_ENCRYPTION_ENV = "LLIAM_GOV_ENCRYPT_STATE"

# Minimum length of a valid wire frame: version(1) + iv(12) + tag(16) + >=1 ct.
_MIN_FRAME_LEN = 1 + IV_LENGTH + TAG_LENGTH + 1


def state_encryption_enabled() -> bool:
    """True when persisted state should be encrypted on write."""
    return os.environ.get(STATE_ENCRYPTION_ENV) == "1"


def managed_state_paths() -> list:
    """Return the persisted-state files routed through encryption.

    Single source of truth for which files ``rotate-key`` re-keys. Currently the
    credential/auth store only (LG-3.7 scope, Jerome 2026-05-30); satellite
    credential files are added here as their routing PRs land.
    """
    from hermes_constants import get_hermes_home

    return [get_hermes_home() / "auth.json"]


def looks_encrypted(raw: bytes) -> bool:
    """Static check: does ``raw`` look like the EncryptedFile wire format?

    Plaintext JSON state files begin with ``{`` (0x7b); the wire format begins
    with the version byte (0x01). This never instantiates a key manager, so it
    is safe to call on every read regardless of Keychain availability.
    """
    return len(raw) >= _MIN_FRAME_LEN and raw[0] == FORMAT_VERSION


def decode_state_bytes(raw: bytes, *, key_manager: KeyManager | None = None) -> bytes:
    """Return plaintext bytes from a state file's raw on-disk bytes.

    Decrypts iff ``raw`` is in the wire format; otherwise returns it unchanged
    (legacy plaintext). A non-``None`` ``key_manager`` is used as-is (tests);
    otherwise the FIPS-gated shared manager is lazily resolved — but only when a
    decrypt is actually needed.
    """
    if not looks_encrypted(raw):
        return raw
    km = key_manager or _shared_km()
    return km.decrypt(raw)


def encode_state_bytes(
    plaintext: bytes, *, key_manager: KeyManager | None = None
) -> bytes:
    """Return on-disk bytes for ``plaintext``.

    Encrypts when :func:`state_encryption_enabled`; otherwise returns the
    plaintext unchanged. The Keychain is touched only in the encrypt path.
    """
    if not state_encryption_enabled():
        return plaintext
    km = key_manager or _shared_km()
    return km.encrypt(plaintext)


def _shared_km() -> KeyManager:
    # Imported lazily so importing this module never imports the key manager's
    # FIPS/Keychain machinery (keeps plaintext-only hosts import-clean).
    from lliam_gov.security.encrypted_file import get_shared_key_manager

    return get_shared_key_manager()


__all__ = [
    "STATE_ENCRYPTION_ENV",
    "decode_state_bytes",
    "encode_state_bytes",
    "looks_encrypted",
    "managed_state_paths",
    "state_encryption_enabled",
]
