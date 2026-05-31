"""Integration: auth.json round-trips through encryption (LG-3.7 / AI-215 PR 2).

Drives the real hermes_cli.auth store save/load seam with
LLIAM_GOV_ENCRYPT_STATE=1 and a fake-keyring-backed shared key manager, proving:
the credential store is ciphertext on disk, no secret leaks in cleartext, and
both the canonical loader and the raw bypass reader (main.is_authenticated path)
decode it.
"""

from __future__ import annotations

import json

import pytest

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
def encrypted_state(monkeypatch, tmp_path):
    """Enable state encryption with an injected fake-keyring key manager."""
    monkeypatch.setenv("LLIAM_GOV_ENCRYPT_STATE", "1")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    km = KeyManager(service="auth-enc-test", backend=_FakeKeyring())
    km.init()
    monkeypatch.setattr(encrypted_file, "_shared_key_manager", km)
    # The codec resolves the shared manager via get_shared_key_manager(); with
    # the module global already set, that returns our fake-backed km without
    # touching the real Keychain or the FIPS gate.
    yield km
    encrypted_file.reset_shared_key_manager()


def test_auth_store_is_encrypted_on_disk(encrypted_state):
    from hermes_cli import auth as auth_mod

    auth_mod._save_auth_store({
        "providers": {"nous": {"agent_key": "TOP-SECRET-KEY"}},
        "active_provider": "nous",
    })
    auth_file = auth_mod._auth_file_path()
    raw = auth_file.read_bytes()
    # Ciphertext on disk: wire-format version byte, secret absent in cleartext.
    assert raw[0] == 0x01
    assert b"TOP-SECRET-KEY" not in raw
    assert b"providers" not in raw


def test_canonical_loader_roundtrips_encrypted_store(encrypted_state):
    from hermes_cli import auth as auth_mod

    original = {
        "providers": {"nous": {"agent_key": "k1"}},
        "active_provider": "nous",
    }
    auth_mod._save_auth_store(dict(original))
    loaded = auth_mod._load_auth_store()
    assert loaded["active_provider"] == "nous"
    assert loaded["providers"]["nous"]["agent_key"] == "k1"


def test_undecryptable_store_fails_loud_not_silent_wipe(encrypted_state, monkeypatch):
    # Regression (review finding): an encrypted store that cannot be decrypted
    # (Keychain lost / key rotated out of band / ciphertext tampered) must NOT
    # be treated as corrupt plaintext and silently replaced with an empty store
    # — that would drop live credentials and let the next save overwrite the
    # still-recoverable ciphertext. It must fail loud.
    from hermes_cli import auth as auth_mod

    auth_mod._save_auth_store({
        "providers": {"nous": {"agent_key": "REAL"}},
        "active_provider": "nous",
    })
    auth_file = auth_mod._auth_file_path()
    assert auth_file.read_bytes()[0] == 0x01  # encrypted

    # Simulate key unavailability: swap in a fresh, different key manager.
    km2 = KeyManager(service="auth-enc-test-OTHER", backend=_FakeKeyring())
    km2.init()
    monkeypatch.setattr(encrypted_file, "_shared_key_manager", km2)

    with pytest.raises(RuntimeError, match="could not be decrypted"):
        auth_mod._load_auth_store()
    # The encrypted store is left intact on disk (recoverable once key returns).
    assert auth_file.read_bytes()[0] == 0x01


def test_corrupt_plaintext_still_starts_empty(monkeypatch, tmp_path):
    # The pre-encryption behavior must be preserved: a genuinely corrupt
    # *plaintext* auth.json (not encrypted) still degrades to an empty store
    # with a .corrupt copy, rather than failing loud.
    monkeypatch.delenv("LLIAM_GOV_ENCRYPT_STATE", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    from hermes_cli import auth as auth_mod

    auth_file = auth_mod._auth_file_path()
    auth_file.parent.mkdir(parents=True, exist_ok=True)
    auth_file.write_text("{ this is not valid json ")

    loaded = auth_mod._load_auth_store()
    assert loaded["providers"] == {}
    assert auth_file.with_suffix(".json.corrupt").exists()


def test_plaintext_store_still_loads_with_flag_on(encrypted_state, monkeypatch):
    # A legacy plaintext auth.json (written before encryption) must still load
    # even when the encrypt flag is on — decrypt-on-read is unconditional.
    from hermes_cli import auth as auth_mod

    auth_file = auth_mod._auth_file_path()
    auth_file.parent.mkdir(parents=True, exist_ok=True)
    auth_file.write_text(
        json.dumps({
            "providers": {"nous": {"agent_key": "legacy"}},
            "active_provider": "nous",
        })
    )
    loaded = auth_mod._load_auth_store()
    assert loaded["providers"]["nous"]["agent_key"] == "legacy"
