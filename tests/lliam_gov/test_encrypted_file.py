"""Tests for the EncryptedFile abstraction (LG-3.7 / AI-215, plan §5.1).

Covers: round-trip (bytes/text/json), at-rest confidentiality (plaintext never
on disk), tamper detection (fail-closed), atomic write (no partial file, mode
0600), legacy-plaintext migration, and the shared-key-manager FIPS gate.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from lliam_gov.security.encrypted_file import (
    EncryptedFile,
    PlaintextDetectedError,
    get_shared_key_manager,
    reset_shared_key_manager,
)
from lliam_gov.security.key_manager import KeyManager


class _FakeKeyring:
    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, account: str) -> str | None:
        return self._store.get((service, account))

    def set_password(self, service: str, account: str, password: str) -> None:
        self._store[(service, account)] = password

    def delete_password(self, service: str, account: str) -> None:
        self._store.pop((service, account), None)


@pytest.fixture
def km() -> KeyManager:
    manager = KeyManager(service="ef-test", backend=_FakeKeyring())
    manager.init()
    return manager


# ─── Round-trip ─────────────────────────────────────────────────────────────


def test_bytes_roundtrip(tmp_path, km):
    ef = EncryptedFile(tmp_path / "state.bin", key_manager=km)
    ef.write_bytes(b"\x00\x01secret payload\xff")
    assert ef.read_bytes() == b"\x00\x01secret payload\xff"


def test_text_roundtrip(tmp_path, km):
    ef = EncryptedFile(tmp_path / "note.txt", key_manager=km)
    ef.write_text("CUI-ish text — über/日本語")
    assert ef.read_text() == "CUI-ish text — über/日本語"


def test_json_roundtrip(tmp_path, km):
    ef = EncryptedFile(tmp_path / "state.json", key_manager=km)
    obj = {"session": "abc", "turns": [1, 2, 3], "nested": {"k": "v"}}
    ef.write_json(obj)
    assert ef.read_json() == obj


# ─── Confidentiality at rest ────────────────────────────────────────────────


def test_plaintext_never_on_disk(tmp_path, km):
    secret = "TOP-SECRET-TOKEN-xoxb-12345"
    ef = EncryptedFile(tmp_path / "creds.json", key_manager=km)
    ef.write_json({"token": secret})
    raw = (tmp_path / "creds.json").read_bytes()
    assert secret.encode() not in raw
    assert b"token" not in raw  # even JSON keys are encrypted


def test_file_mode_is_0600(tmp_path, km):
    ef = EncryptedFile(tmp_path / "state.bin", key_manager=km)
    ef.write_bytes(b"x")
    mode = stat.S_IMODE(os.stat(tmp_path / "state.bin").st_mode)
    assert mode == 0o600


def test_leaf_dir_created_0700(tmp_path, km):
    # The immediate parent of a persisted file is created 0700 — matching the
    # audit_logger._ensure_dirs idiom. (Path.mkdir(parents=True) only applies
    # the mode to the leaf, which is the convention this code follows.)
    nested = tmp_path / "a" / "b" / "c"
    ef = EncryptedFile(nested / "state.bin", key_manager=km)
    ef.write_bytes(b"x")
    assert stat.S_IMODE(os.stat(nested).st_mode) == 0o700


# ─── Tamper detection (fail-closed) ─────────────────────────────────────────


def test_tampered_file_raises_invalid_tag(tmp_path, km):
    path = tmp_path / "state.bin"
    ef = EncryptedFile(path, key_manager=km)
    ef.write_bytes(b"sensitive")
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0x01
    path.write_bytes(bytes(blob))
    with pytest.raises(InvalidTag):
        ef.read_bytes()


def test_reading_plaintext_file_raises(tmp_path, km):
    path = tmp_path / "legacy.json"
    path.write_text('{"plain": true}')
    ef = EncryptedFile(path, key_manager=km)
    with pytest.raises(PlaintextDetectedError):
        ef.read_bytes()


# ─── Atomicity ──────────────────────────────────────────────────────────────


def test_overwrite_leaves_no_temp_files(tmp_path, km):
    # Use a dedicated workspace subdir: the autouse _hermes_home_env fixture
    # drops a "hermes_test" dir in tmp_path, so we scope sibling checks here.
    ws = tmp_path / "ws"
    ws.mkdir()
    ef = EncryptedFile(ws / "state.bin", key_manager=km)
    ef.write_bytes(b"v1")
    ef.write_bytes(b"v2")
    assert ef.read_bytes() == b"v2"
    # No leaked temp siblings from the atomic write.
    assert sorted(p.name for p in ws.iterdir()) == ["state.bin"]
    assert not list(ws.glob("*.tmp"))


def test_overwrite_preserves_old_on_encrypt_failure(tmp_path, monkeypatch, km):
    ws = tmp_path / "ws"
    ws.mkdir()
    path = ws / "state.bin"
    ef = EncryptedFile(path, key_manager=km)
    ef.write_bytes(b"original")

    def _boom(_data):
        raise RuntimeError("encrypt failed")

    monkeypatch.setattr(ef.key_manager, "encrypt", _boom)
    with pytest.raises(RuntimeError):
        ef.write_bytes(b"new")
    # Original key still decrypts the untouched file.
    monkeypatch.undo()
    assert ef.read_bytes() == b"original"
    assert sorted(p.name for p in ws.iterdir()) == ["state.bin"]
    assert not list(ws.glob("*.tmp"))


# ─── Migration ──────────────────────────────────────────────────────────────


def test_migrate_plaintext_converts_in_place(tmp_path, km):
    path = tmp_path / "legacy.json"
    path.write_text('{"legacy": "data"}')
    ef = EncryptedFile(path, key_manager=km)
    assert ef.migrate_plaintext() is True
    # File is now ciphertext on disk but reads back as the original.
    assert b"legacy" not in path.read_bytes()
    assert ef.read_json() == {"legacy": "data"}


def test_migrate_is_idempotent(tmp_path, km):
    path = tmp_path / "state.bin"
    ef = EncryptedFile(path, key_manager=km)
    ef.write_bytes(b"already encrypted")
    assert ef.migrate_plaintext() is False
    assert ef.read_bytes() == b"already encrypted"


def test_migrate_absent_file_returns_false(tmp_path, km):
    ef = EncryptedFile(tmp_path / "nope.bin", key_manager=km)
    assert ef.migrate_plaintext() is False


# ─── exists / unlink ────────────────────────────────────────────────────────


def test_exists_and_unlink(tmp_path, km):
    ef = EncryptedFile(tmp_path / "state.bin", key_manager=km)
    assert ef.exists() is False
    ef.write_bytes(b"x")
    assert ef.exists() is True
    ef.unlink()
    assert ef.exists() is False
    ef.unlink()  # missing_ok default — no raise


# ─── Shared key manager + FIPS gate ─────────────────────────────────────────


def test_shared_key_manager_runs_fips_gate(monkeypatch):
    reset_shared_key_manager()
    calls = {"fips": 0}

    def _fake_fips():
        calls["fips"] += 1

    monkeypatch.setattr("lliam_gov.security.encrypted_file.fips_check", _fake_fips)
    # Avoid touching the real Keychain: stub KeyManager.init.
    monkeypatch.setattr(KeyManager, "init", lambda self: None)
    try:
        get_shared_key_manager()
        get_shared_key_manager()  # cached — fips gate runs once
        assert calls["fips"] == 1
    finally:
        reset_shared_key_manager()


def test_shared_key_manager_fails_closed_on_non_fips(monkeypatch):
    reset_shared_key_manager()
    from lliam_gov.security.runtime_guard import FipsNotAvailable

    def _boom():
        raise FipsNotAvailable("not fips")

    monkeypatch.setattr("lliam_gov.security.encrypted_file.fips_check", _boom)
    try:
        with pytest.raises(FipsNotAvailable):
            get_shared_key_manager()
    finally:
        reset_shared_key_manager()
