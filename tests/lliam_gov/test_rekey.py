"""Tests for rekey_files() — atomic key rotation (LG-3.8 / AI-216, plan §5.1)."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from lliam_gov.security.encrypted_file import EncryptedFile, rekey_files
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
def km() -> KeyManager:
    m = KeyManager(service="rekey-test", backend=_FakeKeyring())
    m.init()
    return m


def test_rekey_reencrypts_and_preserves_plaintext(tmp_path, km):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    EncryptedFile(a, key_manager=km).write_bytes(b"alpha")
    EncryptedFile(b, key_manager=km).write_bytes(b"beta")
    before_a = a.read_bytes()

    rekeyed = rekey_files([a, b], key_manager=km)

    assert set(rekeyed) == {a, b}
    # Ciphertext changed (new key/iv) but plaintext is intact under the new key.
    assert a.read_bytes() != before_a
    assert EncryptedFile(a, key_manager=km).read_bytes() == b"alpha"
    assert EncryptedFile(b, key_manager=km).read_bytes() == b"beta"


def test_old_key_cannot_decrypt_after_rekey(tmp_path):
    backend = _FakeKeyring()
    km = KeyManager(service="rk2", backend=backend)
    km.init()
    path = tmp_path / "c.bin"
    EncryptedFile(path, key_manager=km).write_bytes(b"secret")
    captured = path.read_bytes()

    rekey_files([path], key_manager=km)

    # A stale manager pinned to the OLD material must fail to decrypt the
    # captured pre-rotation ciphertext (forward secrecy across rotation).
    stale = KeyManager(service="rk2-stale", backend=_FakeKeyring())
    stale.init()
    with pytest.raises((InvalidTag, Exception)):
        stale.decrypt(captured)


def test_rekey_skips_absent_and_plaintext(tmp_path, km):
    enc = tmp_path / "enc.bin"
    plain = tmp_path / "plain.json"
    absent = tmp_path / "nope.bin"
    EncryptedFile(enc, key_manager=km).write_bytes(b"x")
    plain.write_text('{"plain": true}')

    rekeyed = rekey_files([enc, plain, absent], key_manager=km)

    assert rekeyed == [enc]
    assert plain.read_text() == '{"plain": true}'  # untouched
