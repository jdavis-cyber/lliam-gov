"""Privileged-user ACL on audit/rotate CLIs — SP 800-171 3.3.9 (AI-280).

WHY: 3.3.9 requires audit-logging management to be limited to a subset of
privileged users. These tests pin the policy itself — owner-of-home is the
anchor, the allowlist can only narrow, and every ambiguous condition denies
(fail-closed) — so a refactor that quietly widens access fails here.
"""

import os
import sys
from argparse import Namespace

import pytest

from lliam_gov.security.privileged_access import (
    PRIVILEGED_USERS_ENV,
    PrivilegedAccessError,
    require_privileged_user,
)

pytestmark = pytest.mark.skipif(
    not hasattr(os, "geteuid"), reason="POSIX-only privilege model"
)


@pytest.fixture
def lliam_home(tmp_path, monkeypatch):
    home = tmp_path / "lliam-home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv(PRIVILEGED_USERS_ENV, raising=False)
    return home


def test_home_owner_is_privileged(lliam_home):
    require_privileged_user("test-op")  # current euid created the dir


def test_non_owner_denied(lliam_home, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(lliam_home).st_uid + 1)
    with pytest.raises(PrivilegedAccessError, match="does not own"):
        require_privileged_user("test-op")


def test_missing_home_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "nope"))
    monkeypatch.delenv(PRIVILEGED_USERS_ENV, raising=False)
    with pytest.raises(PrivilegedAccessError, match="cannot determine"):
        require_privileged_user("test-op")


def test_allowlist_admits_listed_owner(lliam_home, monkeypatch):
    import pwd

    me = pwd.getpwuid(os.geteuid()).pw_name
    monkeypatch.setenv(PRIVILEGED_USERS_ENV, f"someoneelse, {me}")
    require_privileged_user("test-op")


def test_allowlist_denies_unlisted_owner(lliam_home, monkeypatch):
    monkeypatch.setenv(PRIVILEGED_USERS_ENV, "someoneelse")
    with pytest.raises(PrivilegedAccessError, match="not in"):
        require_privileged_user("test-op")


def test_allowlist_cannot_widen_access(lliam_home, monkeypatch):
    """A listed user who does not own the home is still denied."""
    import pwd

    me = pwd.getpwuid(os.geteuid()).pw_name
    monkeypatch.setenv(PRIVILEGED_USERS_ENV, me)
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(lliam_home).st_uid + 1)
    with pytest.raises(PrivilegedAccessError, match="does not own"):
        require_privileged_user("test-op")


# ── CLI integration: denial paths exit 1 with the 3.3.9 message ────────────


def test_audit_cli_denies_non_owner(lliam_home, monkeypatch, capsys):
    from hermes_cli.audit_cli import cmd_audit

    monkeypatch.setattr(os, "geteuid", lambda: os.stat(lliam_home).st_uid + 1)
    rc = cmd_audit(Namespace(audit_command="verify-jsonl", input="x.jsonl"))
    assert rc == 1
    assert "3.3.9" in capsys.readouterr().err


def test_rotate_key_denies_non_owner(lliam_home, monkeypatch, capsys):
    from hermes_cli.key_cli import cmd_rotate_key

    monkeypatch.setattr(os, "geteuid", lambda: os.stat(lliam_home).st_uid + 1)
    rc = cmd_rotate_key(Namespace())
    assert rc == 1
    assert "3.3.9" in capsys.readouterr().err


def test_audit_cli_owner_proceeds_past_gate(lliam_home, capsys):
    """Positive path: the owner reaches the real subcommand (which then
    fails on the missing input file, NOT on the privilege gate)."""
    from hermes_cli.audit_cli import cmd_audit

    rc = cmd_audit(
        Namespace(
            audit_command="verify-jsonl",
            input=str(lliam_home / "missing.jsonl"),
            expected_last_hash=None,
        )
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "3.3.9" not in err, "owner must not be blocked by the ACL"
    assert "verification failed" in err
