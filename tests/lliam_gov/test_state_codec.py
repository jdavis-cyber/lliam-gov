"""Tests for the persisted-state encryption codec (LG-3.7 / AI-215 PR 2).

Verifies the asymmetric contract: decrypt-on-read is unconditional and never
touches a key manager for plaintext; encrypt-on-write is gated by the env flag;
and a round-trip survives a flag flip in either direction.
"""

from __future__ import annotations

import pytest

from lliam_gov.security.key_manager import KeyManager
from lliam_gov.security.state_codec import (
    STATE_ENCRYPTION_ENV,
    decode_state_bytes,
    encode_state_bytes,
    looks_encrypted,
    state_encryption_enabled,
)


class _FakeKeyring:
    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service, account):
        return self._store.get((service, account))

    def set_password(self, service, account, password):
        self._store[(service, account)] = password

    def delete_password(self, service, account):
        self._store.pop((service, account), None)


@pytest.fixture
def km() -> KeyManager:
    m = KeyManager(service="codec-test", backend=_FakeKeyring())
    m.init()
    return m


def test_looks_encrypted_distinguishes_plaintext_json():
    assert looks_encrypted(b'{"providers": {}}') is False
    assert looks_encrypted(b"") is False
    assert looks_encrypted(b"\x01") is False  # too short to be a frame


def test_looks_encrypted_true_for_wire_format(km):
    frame = km.encrypt(b'{"providers": {}}')
    assert looks_encrypted(frame) is True


def test_decode_plaintext_is_passthrough_without_keymanager():
    # No key_manager passed and flag irrelevant: a plaintext file must decode
    # without ever resolving the shared (Keychain-backed) manager.
    raw = b'{"active_provider": "nous"}'
    assert decode_state_bytes(raw) == raw


def test_encode_decode_roundtrip_when_enabled(monkeypatch, km):
    monkeypatch.setenv(STATE_ENCRYPTION_ENV, "1")
    plaintext = b'{"providers": {"nous": {"agent_key": "secret"}}}'
    on_disk = encode_state_bytes(plaintext, key_manager=km)
    assert on_disk != plaintext
    assert b"secret" not in on_disk
    assert decode_state_bytes(on_disk, key_manager=km) == plaintext


def test_encode_is_passthrough_when_disabled(monkeypatch):
    monkeypatch.delenv(STATE_ENCRYPTION_ENV, raising=False)
    plaintext = b'{"providers": {}}'
    assert encode_state_bytes(plaintext) == plaintext


def test_flag_flip_off_still_decrypts_existing_ciphertext(monkeypatch, km):
    # Encrypt with the flag on, then read back with the flag off: decrypt-on-read
    # is unconditional, so an operator turning the flag off mid-life still loads.
    monkeypatch.setenv(STATE_ENCRYPTION_ENV, "1")
    frame = encode_state_bytes(b'{"a": 1}', key_manager=km)
    monkeypatch.delenv(STATE_ENCRYPTION_ENV, raising=False)
    assert decode_state_bytes(frame, key_manager=km) == b'{"a": 1}'


def test_state_encryption_enabled_reads_env(monkeypatch):
    monkeypatch.delenv(STATE_ENCRYPTION_ENV, raising=False)
    assert state_encryption_enabled() is False
    monkeypatch.setenv(STATE_ENCRYPTION_ENV, "1")
    assert state_encryption_enabled() is True
    monkeypatch.setenv(STATE_ENCRYPTION_ENV, "true")  # only "1" enables
    assert state_encryption_enabled() is False
