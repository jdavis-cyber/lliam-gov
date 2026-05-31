"""Tests for the rotate-key CLI (LG-3.8 / AI-216)."""

from __future__ import annotations

import argparse
import json

import pytest

from hermes_cli.key_cli import cmd_rotate_key
from lliam_gov.security import encrypted_file
from lliam_gov.security.key_manager import KeyManager


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
def enc_env(monkeypatch, tmp_path):
    monkeypatch.setenv("LLIAM_GOV_ALLOW_NON_FIPS", "1")
    monkeypatch.setenv("LLIAM_GOV_ENCRYPT_STATE", "1")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    km = KeyManager(service="rotate-cli-test", backend=_FakeKeyring())
    km.init()
    monkeypatch.setattr(encrypted_file, "_shared_key_manager", km)
    yield km
    encrypted_file.reset_shared_key_manager()


def test_rotate_key_refuses_when_encryption_disabled(monkeypatch, capsys):
    monkeypatch.setenv("LLIAM_GOV_ALLOW_NON_FIPS", "1")
    monkeypatch.delenv("LLIAM_GOV_ENCRYPT_STATE", raising=False)
    rc = cmd_rotate_key(argparse.Namespace())
    assert rc == 1
    assert "state encryption is disabled" in capsys.readouterr().err


def test_rotate_key_reencrypts_store_and_audits(enc_env, capsys):
    from hermes_cli import auth as auth_mod

    # Seed an encrypted credential store.
    auth_mod._save_auth_store({
        "providers": {"nous": {"agent_key": "k1"}},
        "active_provider": "nous",
    })
    auth_file = auth_mod._auth_file_path()
    before = auth_file.read_bytes()
    assert before[0] == 0x01  # encrypted

    rc = cmd_rotate_key(argparse.Namespace())
    assert rc == 0
    out = capsys.readouterr().out
    assert "Rotated encryption key" in out

    # Re-encrypted (bytes differ) but still loads to the same plaintext.
    after = auth_file.read_bytes()
    assert after != before
    assert after[0] == 0x01
    loaded = auth_mod._load_auth_store()
    assert loaded["providers"]["nous"]["agent_key"] == "k1"


def test_rotate_key_writes_audit_event(enc_env):
    from hermes_cli import auth as auth_mod
    from hermes_constants import get_hermes_home

    auth_mod._save_auth_store({"providers": {}, "active_provider": None})
    assert cmd_rotate_key(argparse.Namespace()) == 0

    audit_dir = get_hermes_home() / "audit"
    rows: list[dict] = []
    for path in audit_dir.glob("tool-calls-*.jsonl"):
        rows.extend(
            json.loads(line) for line in path.read_text().splitlines() if line.strip()
        )
    assert any(r["event_type"] == "key_rotation" for r in rows)
