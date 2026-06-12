"""Backup encryption at rest — SP 800-171 3.8.9 (AI-279, WBS LG-3.9 held-back).

WHY these tests exist: 3.8.9 requires the confidentiality of backup CUI at
storage locations. A backup zip of the Lliam home contains credentials and
session state, so when persisted-state encryption is on
(``LLIAM_GOV_ENCRYPT_STATE=1``) the archive itself must never persist as
plaintext — including when encryption FAILS mid-backup (fail-closed).
"""

import os
import zipfile
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

from hermes_cli.backup import (
    ENCRYPTED_BACKUP_SUFFIX,
    decrypt_backup_archive,
    encrypt_backup_archive,
    run_backup,
    run_import,
)
from lliam_gov.security.key_manager import KeyManager


class _FakeKeyring:
    """In-memory keyring backend so tests never touch the real Keychain."""

    def __init__(self):
        self._store = {}

    def get_password(self, service, account):
        return self._store.get((service, account))

    def set_password(self, service, account, password):
        self._store[(service, account)] = password

    def delete_password(self, service, account):
        self._store.pop((service, account), None)


@pytest.fixture
def km():
    manager = KeyManager(service="backup-test", backend=_FakeKeyring())
    manager.init()
    return manager


@pytest.fixture
def hermes_home(tmp_path, monkeypatch):
    home = tmp_path / "lliam-home"
    home.mkdir()
    (home / "config.yaml").write_text("model:\n  provider: anthropic\n")
    (home / ".env").write_text("ANTHROPIC_API_KEY=sk-cui-secret\n")
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def _make_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("config.yaml", "model:\n  provider: anthropic\n")
        zf.writestr(".env", "ANTHROPIC_API_KEY=sk-cui-secret\n")
    return path


# ── encrypt/decrypt primitives ──────────────────────────────────────────────

def test_roundtrip_restores_identical_zip(tmp_path, km):
    zip_path = _make_zip(tmp_path / "b.zip")
    original = zip_path.read_bytes()

    enc = encrypt_backup_archive(zip_path, key_manager=km)
    tmp_zip = decrypt_backup_archive(enc, key_manager=km)
    try:
        assert tmp_zip.read_bytes() == original
        assert zipfile.is_zipfile(tmp_zip)
    finally:
        tmp_zip.unlink()


def test_plaintext_zip_removed_and_ciphertext_unreadable(tmp_path, km):
    zip_path = _make_zip(tmp_path / "b.zip")
    enc = encrypt_backup_archive(zip_path, key_manager=km)

    assert not zip_path.exists(), "plaintext zip must not remain at rest"
    assert enc.name.endswith(".zip" + ENCRYPTED_BACKUP_SUFFIX)
    raw = enc.read_bytes()
    assert not raw.startswith(b"PK"), "ciphertext must not be a readable zip"
    assert b"sk-cui-secret" not in raw, "CUI must not appear in the archive"


def test_encrypted_archive_mode_0600(tmp_path, km):
    enc = encrypt_backup_archive(_make_zip(tmp_path / "b.zip"), key_manager=km)
    assert (enc.stat().st_mode & 0o777) == 0o600


def test_encrypt_failure_deletes_plaintext_fail_closed(tmp_path, km):
    zip_path = _make_zip(tmp_path / "b.zip")
    with patch.object(km, "encrypt", side_effect=RuntimeError("keychain down")):
        with pytest.raises(RuntimeError):
            encrypt_backup_archive(zip_path, key_manager=km)
    assert not zip_path.exists(), (
        "fail-closed: an unencryptable backup must not leave plaintext CUI"
    )
    assert not (tmp_path / ("b.zip" + ENCRYPTED_BACKUP_SUFFIX)).exists()


def test_tampered_archive_fails_loudly(tmp_path, km):
    enc = encrypt_backup_archive(_make_zip(tmp_path / "b.zip"), key_manager=km)
    raw = bytearray(enc.read_bytes())
    raw[-1] ^= 0xFF
    enc.write_bytes(bytes(raw))
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        decrypt_backup_archive(enc, key_manager=km)


# ── run_backup / run_import integration ─────────────────────────────────────

def _run_backup_to(out_dir: Path) -> None:
    run_backup(Namespace(output=str(out_dir), quick=False))


def test_run_backup_plaintext_when_encryption_off(hermes_home, tmp_path, monkeypatch):
    monkeypatch.delenv("LLIAM_GOV_ENCRYPT_STATE", raising=False)
    out = tmp_path / "out"
    out.mkdir()
    _run_backup_to(out)
    produced = list(out.iterdir())
    assert len(produced) == 1 and produced[0].suffix == ".zip"
    assert zipfile.is_zipfile(produced[0])


def test_run_backup_encrypts_when_enabled(hermes_home, tmp_path, monkeypatch, km):
    monkeypatch.setenv("LLIAM_GOV_ENCRYPT_STATE", "1")
    monkeypatch.setattr(
        "hermes_cli.backup._backup_key_manager", lambda key_manager=None: km
    )
    out = tmp_path / "out"
    out.mkdir()
    _run_backup_to(out)
    produced = list(out.iterdir())
    assert len(produced) == 1, "exactly one artifact — no plaintext sibling"
    enc = produced[0]
    assert enc.name.endswith(".zip" + ENCRYPTED_BACKUP_SUFFIX)
    assert not zipfile.is_zipfile(enc)
    assert b"sk-cui-secret" not in enc.read_bytes()


def test_run_backup_fail_closed_exits_nonzero(hermes_home, tmp_path, monkeypatch, km):
    monkeypatch.setenv("LLIAM_GOV_ENCRYPT_STATE", "1")

    def _broken(key_manager=None):
        raise RuntimeError("keychain unavailable")

    monkeypatch.setattr("hermes_cli.backup._backup_key_manager", _broken)
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(SystemExit) as exc_info:
        _run_backup_to(out)
    assert exc_info.value.code == 1
    assert list(out.iterdir()) == [], "no artifact (plaintext or partial) remains"


def test_run_import_decrypts_encrypted_backup(hermes_home, tmp_path, monkeypatch, km):
    monkeypatch.setenv("LLIAM_GOV_ENCRYPT_STATE", "1")
    monkeypatch.setattr(
        "hermes_cli.backup._backup_key_manager", lambda key_manager=None: km
    )
    out = tmp_path / "out"
    out.mkdir()
    _run_backup_to(out)
    enc = next(out.iterdir())

    restore_home = tmp_path / "restore-home"
    monkeypatch.setenv("HERMES_HOME", str(restore_home))
    run_import(Namespace(zipfile=str(enc), force=True))

    assert (restore_home / "config.yaml").is_file()
    assert (restore_home / ".env").read_text() == "ANTHROPIC_API_KEY=sk-cui-secret\n"
    leftovers = [
        p for p in Path(tempfile_dir()).glob("lliam-backup-*.zip") if p.is_file()
    ]
    assert leftovers == [], "decrypted temp zip must be removed after import"


def tempfile_dir() -> str:
    import tempfile

    return tempfile.gettempdir()
