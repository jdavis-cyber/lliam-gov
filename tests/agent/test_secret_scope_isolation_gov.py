"""Per-profile credential isolation under the gov profile (LG-IA-03, P1.4).

Demonstrates the fail-closed guarantee the gov overlay activates via
gateway.multiplex_profiles: profile A's credential is not visible to profile
B, and an unscoped read in multiplex mode raises UnscopedSecretError rather
than leaking whichever value is in os.environ.
"""

from __future__ import annotations

import pytest

import agent.secret_scope as ss


@pytest.fixture(autouse=True)
def _multiplex_on():
    prev = ss.is_multiplex_active()
    ss.set_multiplex_active(True)  # what gateway.multiplex_profiles: true does
    yield
    ss.set_multiplex_active(prev)


def test_profile_a_credential_not_visible_to_profile_b():
    scope_a = {"PROVIDER_API_KEY": "secret-A"}
    scope_b = {"PROVIDER_API_KEY": "secret-B"}

    tok = ss.set_secret_scope(scope_a)
    try:
        assert ss.get_secret("PROVIDER_API_KEY") == "secret-A"
    finally:
        ss.reset_secret_scope(tok)

    tok = ss.set_secret_scope(scope_b)
    try:
        val = ss.get_secret("PROVIDER_API_KEY")
        assert val == "secret-B"
        assert val != "secret-A", "profile B must not see profile A's credential"
    finally:
        ss.reset_secret_scope(tok)


def test_unscoped_read_fails_closed(monkeypatch):
    # A stray value in os.environ must NOT leak when no scope is installed.
    monkeypatch.setenv("PROVIDER_API_KEY", "leaked-from-environ")
    with pytest.raises(ss.UnscopedSecretError):
        ss.get_secret("PROVIDER_API_KEY")


def test_global_env_still_reads_environ(monkeypatch):
    # Genuinely-global deployment vars are not profile secrets and keep working.
    monkeypatch.setenv("HERMES_HOME", "/tmp/whatever")
    assert ss.get_secret("HERMES_HOME") == "/tmp/whatever"


def test_terminal_ssh_credentials_are_not_global(monkeypatch):
    """LG-IA-03 allowlist minimization: TERMINAL_SSH_* are per-profile SSH
    credentials, NOT global deployment settings — they must fail closed on an
    unscoped read under multiplex instead of leaking os.environ cross-profile."""
    monkeypatch.setenv("TERMINAL_SSH_KEY", "/home/a/.ssh/id_rsa")
    with pytest.raises(ss.UnscopedSecretError):
        ss.get_secret("TERMINAL_SSH_KEY")
    # A scoped read resolves the profile's own value.
    tok = ss.set_secret_scope({"TERMINAL_SSH_KEY": "/home/b/.ssh/id_rsa"})
    try:
        assert ss.get_secret("TERMINAL_SSH_KEY") == "/home/b/.ssh/id_rsa"
    finally:
        ss.reset_secret_scope(tok)


def test_non_credential_terminal_settings_stay_global(monkeypatch):
    # The 30+ legit TERMINAL_ deployment settings must remain global (not
    # broken by the SSH carve-out).
    monkeypatch.setenv("TERMINAL_BACKEND", "docker")
    assert ss.get_secret("TERMINAL_BACKEND") == "docker"
