"""Tests for ``lliam_gov.security.key_manager``.

Covers the Phase 3 §5.1 acceptance criteria called out in the handoff:
round-trip, tamper detection (auth-tag failure), key-derivation
determinism, and ``rotate_key`` atomicity (post-rotation init produces
a new derived key and old ciphertext fails to decrypt).
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from lliam_gov.security.key_manager import (
    DEFAULT_KEYCHAIN_SERVICE,
    FORMAT_VERSION,
    IV_LENGTH,
    KEYCHAIN_ACCOUNT_SALT,
    KEYCHAIN_ACCOUNT_SECRET,
    KeyManager,
    KeyManagerError,
    NotInitializedError,
    TAG_LENGTH,
    UnsupportedFormatVersion,
)


class FakeKeyring:
    """In-memory KeyringBackend so the real macOS Keychain is never touched."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, account: str) -> str | None:
        return self._store.get((service, account))

    def set_password(self, service: str, account: str, password: str) -> None:
        self._store[(service, account)] = password

    def delete_password(self, service: str, account: str) -> None:
        self._store.pop((service, account), None)


@pytest.fixture
def fake_backend() -> FakeKeyring:
    return FakeKeyring()


@pytest.fixture
def km(fake_backend: FakeKeyring) -> KeyManager:
    manager = KeyManager(service="lliam-gov-test", backend=fake_backend)
    manager.init()
    return manager


# ─── Round-trip ─────────────────────────────────────────────────────────────


def test_encrypt_decrypt_roundtrip(km: KeyManager) -> None:
    plaintext = b"the Hermes upstream is MIT; Lliam-GOV adds the overlay."
    ct = km.encrypt(plaintext)
    assert km.decrypt(ct) == plaintext


def test_wire_format_header(km: KeyManager) -> None:
    ct = km.encrypt(b"abc")
    assert ct[0] == FORMAT_VERSION
    # version(1) + iv(12) + tag(16) + ciphertext(3) = 32
    assert len(ct) == 1 + IV_LENGTH + TAG_LENGTH + 3


def test_encrypt_produces_distinct_ciphertexts(km: KeyManager) -> None:
    # Random IV per call must mean identical plaintexts produce distinct
    # ciphertexts — a deterministic IV would be a confidentiality bug
    # under GCM.
    a = km.encrypt(b"same")
    b = km.encrypt(b"same")
    assert a != b
    assert km.decrypt(a) == km.decrypt(b) == b"same"


# ─── Tamper detection ──────────────────────────────────────────────────────


def test_tampered_ciphertext_raises_invalid_tag(km: KeyManager) -> None:
    ct = bytearray(km.encrypt(b"sensitive"))
    # Flip a byte in the ciphertext region.
    ct[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        km.decrypt(bytes(ct))


def test_tampered_auth_tag_raises_invalid_tag(km: KeyManager) -> None:
    ct = bytearray(km.encrypt(b"sensitive"))
    # Auth-tag region is bytes [13 .. 29).
    ct[1 + IV_LENGTH] ^= 0x01
    with pytest.raises(InvalidTag):
        km.decrypt(bytes(ct))


def test_tampered_iv_raises_invalid_tag(km: KeyManager) -> None:
    ct = bytearray(km.encrypt(b"sensitive"))
    ct[1] ^= 0x01
    with pytest.raises(InvalidTag):
        km.decrypt(bytes(ct))


def test_truncated_ciphertext_raises_key_manager_error(km: KeyManager) -> None:
    with pytest.raises(KeyManagerError):
        km.decrypt(b"\x01short")


def test_unknown_version_byte_rejected(km: KeyManager) -> None:
    ct = bytearray(km.encrypt(b"abc"))
    ct[0] = 0xFF
    with pytest.raises(UnsupportedFormatVersion):
        km.decrypt(bytes(ct))


# ─── Derivation determinism ────────────────────────────────────────────────


def test_init_is_deterministic_for_fixed_secret(fake_backend: FakeKeyring) -> None:
    # Two managers pointed at the same Keychain material must derive the
    # same key — otherwise a process restart would lose decrypt access.
    a = KeyManager(service="svc", backend=fake_backend)
    a.init()
    ct = a.encrypt(b"persisted")

    b = KeyManager(service="svc", backend=fake_backend)
    b.init()
    assert b.decrypt(ct) == b"persisted"


def test_init_generates_secret_and_salt_on_first_boot(
    fake_backend: FakeKeyring,
) -> None:
    km = KeyManager(service="first-boot", backend=fake_backend)
    assert fake_backend.get_password("first-boot", KEYCHAIN_ACCOUNT_SECRET) is None
    km.init()
    secret = fake_backend.get_password("first-boot", KEYCHAIN_ACCOUNT_SECRET)
    salt = fake_backend.get_password("first-boot", KEYCHAIN_ACCOUNT_SALT)
    assert secret is not None and len(secret) == 64  # 32 bytes hex
    assert salt is not None and len(salt) == 32  # 16 bytes hex


# ─── Rotation ──────────────────────────────────────────────────────────────


def test_rotate_key_clears_in_memory_key_and_changes_material(
    fake_backend: FakeKeyring,
) -> None:
    km = KeyManager(service="rot", backend=fake_backend)
    km.init()
    old_secret = fake_backend.get_password("rot", KEYCHAIN_ACCOUNT_SECRET)
    old_salt = fake_backend.get_password("rot", KEYCHAIN_ACCOUNT_SALT)

    km.rotate_key()

    assert not km.is_ready()
    with pytest.raises(NotInitializedError):
        km.encrypt(b"nope")

    new_secret = fake_backend.get_password("rot", KEYCHAIN_ACCOUNT_SECRET)
    new_salt = fake_backend.get_password("rot", KEYCHAIN_ACCOUNT_SALT)
    assert new_secret != old_secret
    assert new_salt != old_salt


def test_rotate_key_invalidates_old_ciphertext(fake_backend: FakeKeyring) -> None:
    # An attacker who captured ciphertext under the old key must not be
    # able to decrypt it under the rotated key.
    km = KeyManager(service="rot2", backend=fake_backend)
    km.init()
    ct = km.encrypt(b"pre-rotation")

    km.rotate_key()
    km.init()  # re-derive from the new Keychain material

    with pytest.raises(InvalidTag):
        km.decrypt(ct)


def test_post_rotation_roundtrip(fake_backend: FakeKeyring) -> None:
    km = KeyManager(service="rot3", backend=fake_backend)
    km.init()
    km.rotate_key()
    km.init()
    new_ct = km.encrypt(b"post-rotation")
    assert km.decrypt(new_ct) == b"post-rotation"


# ─── Initialization guards ─────────────────────────────────────────────────


def test_encrypt_before_init_raises(fake_backend: FakeKeyring) -> None:
    km = KeyManager(service="x", backend=fake_backend)
    with pytest.raises(NotInitializedError):
        km.encrypt(b"x")


def test_decrypt_before_init_raises(fake_backend: FakeKeyring) -> None:
    km = KeyManager(service="x", backend=fake_backend)
    with pytest.raises(NotInitializedError):
        km.decrypt(b"\x01" * 32)


# ─── is_encrypted heuristic ────────────────────────────────────────────────


def test_is_encrypted_recognizes_own_output(km: KeyManager) -> None:
    assert km.is_encrypted(km.encrypt(b"x"))


def test_is_encrypted_rejects_obvious_plaintext(km: KeyManager) -> None:
    assert not km.is_encrypted(b"plain text, definitely not a wire frame")
    assert not km.is_encrypted(b"")
    assert not km.is_encrypted(b"\x01")  # too short


# ─── Default-service sanity ────────────────────────────────────────────────


def test_default_service_constant_is_lliam_gov() -> None:
    # Documents the contract with the Phase 4 install guide and the
    # upstream Lliam-OPS service-name divergence (Lliam-OPS uses "lliam").
    assert DEFAULT_KEYCHAIN_SERVICE == "lliam-gov"
