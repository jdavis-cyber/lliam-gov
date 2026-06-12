"""Runtime guard Phase 4 expansion — LG-4.4 / AI-221.

WHY: §5.5 requires the runtime to refuse to operate from an exposed
workspace, with a leaky umask, or without reachable key material. Each
check must fail CLOSED on its negative case — these tests pin both
directions so a refactor can't silently turn a refusal into a warning.
(The Phase 3 FIPS gate has its own suite in test_runtime_guard.py.)
"""

import os

import pytest

from lliam_gov.security.runtime_guard import (
    KeychainUnavailable,
    RuntimeGuardError,
    UmaskTooPermissive,
    WorkspaceNotHardened,
    keychain_check,
    production_posture_check,
    sync_path_warning,
    umask_check,
    workspace_check,
)

posix_only = pytest.mark.skipif(
    not hasattr(os, "geteuid"), reason="POSIX-only guard semantics"
)


@pytest.fixture
def home_0700(tmp_path, monkeypatch):
    home = tmp_path / "lliam-home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


# ── workspace ───────────────────────────────────────────────────────────────


@posix_only
def test_workspace_0700_owned_passes(home_0700):
    workspace_check(home_0700)


@posix_only
def test_workspace_group_readable_fails_closed(home_0700):
    os.chmod(home_0700, 0o750)
    with pytest.raises(WorkspaceNotHardened, match="grants"):
        workspace_check(home_0700)


@posix_only
def test_workspace_world_writable_fails_closed(home_0700):
    os.chmod(home_0700, 0o707)
    with pytest.raises(WorkspaceNotHardened):
        workspace_check(home_0700)


@posix_only
def test_workspace_wrong_owner_fails_closed(home_0700, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(home_0700).st_uid + 1)
    with pytest.raises(WorkspaceNotHardened, match="owned by uid"):
        workspace_check(home_0700)


@posix_only
def test_workspace_missing_fails_closed(tmp_path):
    with pytest.raises(WorkspaceNotHardened, match="not statable"):
        workspace_check(tmp_path / "absent")


# ── umask ───────────────────────────────────────────────────────────────────


@pytest.fixture
def restore_umask():
    saved = os.umask(0o022)
    os.umask(saved)
    yield
    os.umask(saved)


def test_umask_strict_is_left_alone(restore_umask):
    os.umask(0o077)
    assert umask_check() == 0o077
    assert os.umask(0o077) == 0o077  # unchanged


def test_umask_loose_is_tightened_by_default(restore_umask):
    os.umask(0o022)
    assert umask_check() == 0o077
    assert os.umask(0o077) == 0o077  # now in effect


def test_umask_tighten_never_loosens_owner_bits(restore_umask):
    os.umask(0o100)  # operator masked owner-exec deliberately
    assert umask_check() == 0o177
    assert os.umask(0o077) == 0o177


def test_umask_probe_mode_raises_without_mutating(restore_umask):
    os.umask(0o022)
    with pytest.raises(UmaskTooPermissive):
        umask_check(enforce=False)
    assert os.umask(0o022) == 0o022  # untouched


# ── keychain ────────────────────────────────────────────────────────────────


def test_keychain_probe_passes_with_working_manager(monkeypatch):
    from lliam_gov.security import encrypted_file
    from lliam_gov.security.key_manager import KeyManager

    class _FakeKeyring:
        def __init__(self):
            self._s = {}

        def get_password(self, s, a):
            return self._s.get((s, a))

        def set_password(self, s, a, p):
            self._s[(s, a)] = p

        def delete_password(self, s, a):
            self._s.pop((s, a), None)

    km = KeyManager(service="guard-test", backend=_FakeKeyring())
    km.init()
    monkeypatch.setattr(encrypted_file, "get_shared_key_manager", lambda: km)
    keychain_check()


def test_keychain_probe_fails_closed_when_unreachable(monkeypatch):
    from lliam_gov.security import encrypted_file

    def _broken():
        raise RuntimeError("keychain locked")

    monkeypatch.setattr(encrypted_file, "get_shared_key_manager", _broken)
    with pytest.raises(KeychainUnavailable, match="fail-closed"):
        keychain_check()


# ── sync-path warning ───────────────────────────────────────────────────────


def test_sync_path_warns_under_icloud(tmp_path):
    p = tmp_path / "Mobile Documents" / "lliam-home"
    assert "cloud-synced" in (sync_path_warning(p) or "")


def test_sync_path_quiet_on_local_path(home_0700):
    assert sync_path_warning(home_0700) is None


# ── composite production posture ────────────────────────────────────────────


@posix_only
def test_production_posture_requires_encrypt_state(home_0700, monkeypatch):
    monkeypatch.setenv("LLIAM_GOV_ALLOW_NON_FIPS", "1")
    monkeypatch.delenv("LLIAM_GOV_ENCRYPT_STATE", raising=False)
    with pytest.raises(RuntimeGuardError, match="ENCRYPT_STATE"):
        production_posture_check()


@posix_only
def test_production_posture_full_pass(home_0700, monkeypatch, restore_umask):
    from lliam_gov.security import encrypted_file
    from lliam_gov.security.key_manager import KeyManager

    class _FakeKeyring:
        def __init__(self):
            self._s = {}

        def get_password(self, s, a):
            return self._s.get((s, a))

        def set_password(self, s, a, p):
            self._s[(s, a)] = p

        def delete_password(self, s, a):
            self._s.pop((s, a), None)

    km = KeyManager(service="guard-test", backend=_FakeKeyring())
    km.init()
    monkeypatch.setattr(encrypted_file, "get_shared_key_manager", lambda: km)
    monkeypatch.setenv("LLIAM_GOV_ALLOW_NON_FIPS", "1")
    monkeypatch.setenv("LLIAM_GOV_ENCRYPT_STATE", "1")
    assert production_posture_check() == []
