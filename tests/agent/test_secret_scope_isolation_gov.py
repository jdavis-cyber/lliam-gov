"""Per-profile credential isolation under the gov profile (LG-IA-03, P1.4).

Demonstrates the fail-closed guarantee the gov overlay activates via
gateway.multiplex_profiles: profile A's credential is not visible to profile
B, and an unscoped read in multiplex mode raises UnscopedSecretError rather
than leaking whichever value is in os.environ.
"""

from __future__ import annotations

import json

import pytest

import agent.secret_scope as ss
from tools import terminal_tool


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


def test_terminal_env_config_uses_active_profile_ssh_scope(monkeypatch):
    """The real terminal resolver must not reuse profile A's process env."""
    profile_a = {
        "TERMINAL_SSH_HOST": "profile-a.example",
        "TERMINAL_SSH_USER": "profile-a",
        "TERMINAL_SSH_PORT": "2201",
        "TERMINAL_SSH_KEY": "/profiles/a/id_ed25519",
    }
    for name, value in profile_a.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("TERMINAL_TIMEOUT", "91")

    profile_b = {
        "TERMINAL_SSH_HOST": "profile-b.example",
        "TERMINAL_SSH_USER": "profile-b",
        "TERMINAL_SSH_PORT": "2202",
        "TERMINAL_SSH_KEY": "/profiles/b/id_ed25519",
        # Noncredential TERMINAL_* settings remain process-global even if a
        # profile scope happens to contain a conflicting value.
        "TERMINAL_TIMEOUT": "999",
    }
    tok = ss.set_secret_scope(profile_b)
    try:
        config = terminal_tool._get_env_config()
    finally:
        ss.reset_secret_scope(tok)

    assert (
        config["ssh_host"], config["ssh_user"], config["ssh_port"], config["ssh_key"]
    ) == (
        "profile-b.example", "profile-b", 2202, "/profiles/b/id_ed25519"
    )
    assert config["timeout"] == 91


def test_terminal_env_config_fails_closed_for_unscoped_ssh(monkeypatch):
    monkeypatch.setenv("TERMINAL_SSH_HOST", "must-not-leak.example")
    with pytest.raises(ss.UnscopedSecretError):
        terminal_tool._get_env_config()


def test_terminal_ssh_environment_cache_isolated_by_profile_identity(monkeypatch):
    """A→B→A must create two SSH envs and route each command correctly."""
    created = []

    class FakeSSHEnvironment:
        cwd = "~"

        def __init__(self, ssh_config):
            self.ssh_config = dict(ssh_config)
            self.cleaned = False

        def execute(self, command, **kwargs):
            return {
                "output": self.ssh_config["host"],
                "returncode": 0,
            }

        def cleanup(self):
            self.cleaned = True

    def fake_create_environment(**kwargs):
        env = FakeSSHEnvironment(kwargs["ssh_config"])
        created.append(env)
        return env

    monkeypatch.setenv("TERMINAL_ENV", "ssh")
    monkeypatch.setattr(terminal_tool, "_active_environments", {})
    monkeypatch.setattr(terminal_tool, "_last_activity", {})
    monkeypatch.setattr(terminal_tool, "_creation_locks", {})
    monkeypatch.setattr(terminal_tool, "_environment_keys_by_owner", {})
    monkeypatch.setattr(terminal_tool, "_environment_owners_by_key", {})
    monkeypatch.setattr(terminal_tool, "_create_environment", fake_create_environment)
    monkeypatch.setattr(terminal_tool, "_start_cleanup_thread", lambda: None)
    monkeypatch.setattr(
        terminal_tool,
        "_check_all_guards",
        lambda *_args, **_kwargs: {"approved": True},
    )

    profile_a = {
        "TERMINAL_SSH_HOST": "profile-a.example",
        "TERMINAL_SSH_USER": "alice",
        "TERMINAL_SSH_PORT": "2201",
        "TERMINAL_SSH_KEY": "/profiles/a/id_ed25519",
    }
    profile_b = {
        "TERMINAL_SSH_HOST": "profile-b.example",
        "TERMINAL_SSH_USER": "bob",
        "TERMINAL_SSH_PORT": "2202",
        "TERMINAL_SSH_KEY": "/profiles/b/id_ed25519",
    }

    outputs = []
    for profile in (profile_a, profile_b, profile_a):
        tok = ss.set_secret_scope(profile)
        try:
            result = terminal_tool.terminal_tool("pwd", task_id="shared-session")
        finally:
            ss.reset_secret_scope(tok)
        outputs.append(json.loads(result)["output"])

    assert outputs == ["profile-a.example", "profile-b.example", "profile-a.example"]
    assert [env.ssh_config["host"] for env in created] == [
        "profile-a.example", "profile-b.example"
    ]
    assert len(terminal_tool._active_environments) == 2
    assert len(terminal_tool._creation_locks) == 2
    assert all("profile-a" not in key and "profile-b" not in key
               for key in terminal_tool._active_environments)

    profile_a_key = next(
        key for key, env in terminal_tool._active_environments.items()
        if env.ssh_config["host"] == "profile-a.example"
    )
    terminal_tool.cleanup_vm(profile_a_key)

    assert created[0].cleaned is True
    assert created[1].cleaned is False
    assert len(terminal_tool._active_environments) == 1
    assert len(terminal_tool._creation_locks) == 1
    assert profile_a_key not in terminal_tool._environment_owners_by_key
    assert all(
        profile_a_key not in keys
        for keys in terminal_tool._environment_keys_by_owner.values()
    )


def test_unscoped_raw_session_cleanup_uses_durable_ssh_ownership(monkeypatch):
    import tools.file_tools as file_tools

    class FakeSSHEnvironment:
        cwd = "~"

        def __init__(self):
            self.cleaned = False

        def execute(self, command, **kwargs):
            return {"output": "ok", "returncode": 0}

        def cleanup(self):
            self.cleaned = True

    created = []
    monkeypatch.setenv("TERMINAL_ENV", "ssh")
    monkeypatch.setattr(terminal_tool, "_active_environments", {})
    monkeypatch.setattr(terminal_tool, "_last_activity", {})
    monkeypatch.setattr(terminal_tool, "_creation_locks", {})
    monkeypatch.setattr(terminal_tool, "_environment_keys_by_owner", {})
    monkeypatch.setattr(terminal_tool, "_environment_owners_by_key", {})
    monkeypatch.setattr(file_tools, "_file_ops_cache", {})
    monkeypatch.setattr(
        terminal_tool,
        "_create_environment",
        lambda **kwargs: created.append(FakeSSHEnvironment()) or created[-1],
    )
    monkeypatch.setattr(terminal_tool, "_start_cleanup_thread", lambda: None)
    monkeypatch.setattr(
        terminal_tool, "_check_all_guards", lambda *_a, **_k: {"approved": True}
    )

    tok = ss.set_secret_scope({
        "TERMINAL_SSH_HOST": "profile-a.example",
        "TERMINAL_SSH_USER": "alice",
        "TERMINAL_SSH_KEY": "/profiles/a/id_ed25519",
    })
    try:
        terminal_tool.terminal_tool("pwd", task_id="raw-session-a")
        environment_key = next(iter(terminal_tool._active_environments))
        file_tools._file_ops_cache[environment_key] = object()
    finally:
        ss.reset_secret_scope(tok)

    terminal_tool.cleanup_vm("raw-session-a")

    assert created[0].cleaned is True
    assert terminal_tool._active_environments == {}
    assert terminal_tool._last_activity == {}
    assert terminal_tool._creation_locks == {}
    assert terminal_tool._environment_keys_by_owner == {}
    assert terminal_tool._environment_owners_by_key == {}
    assert file_tools._file_ops_cache == {}


def test_shared_ssh_environment_waits_for_final_raw_owner(monkeypatch):
    class FakeSSHEnvironment:
        cwd = "~"

        def __init__(self):
            self.cleanup_calls = 0

        def execute(self, command, **kwargs):
            return {"output": "ok", "returncode": 0}

        def cleanup(self):
            self.cleanup_calls += 1

    env = FakeSSHEnvironment()
    monkeypatch.setenv("TERMINAL_ENV", "ssh")
    monkeypatch.setattr(terminal_tool, "_active_environments", {})
    monkeypatch.setattr(terminal_tool, "_last_activity", {})
    monkeypatch.setattr(terminal_tool, "_creation_locks", {})
    monkeypatch.setattr(terminal_tool, "_environment_keys_by_owner", {})
    monkeypatch.setattr(terminal_tool, "_environment_owners_by_key", {})
    monkeypatch.setattr(terminal_tool, "_create_environment", lambda **kwargs: env)
    monkeypatch.setattr(terminal_tool, "_start_cleanup_thread", lambda: None)
    monkeypatch.setattr(
        terminal_tool, "_check_all_guards", lambda *_a, **_k: {"approved": True}
    )

    tok = ss.set_secret_scope({
        "TERMINAL_SSH_HOST": "shared.example",
        "TERMINAL_SSH_USER": "alice",
        "TERMINAL_SSH_KEY": "/profiles/shared/id_ed25519",
    })
    try:
        terminal_tool.terminal_tool("pwd", task_id="raw-session-a")
        terminal_tool.terminal_tool("pwd", task_id="raw-session-b")
        environment_key = next(iter(terminal_tool._active_environments))
    finally:
        ss.reset_secret_scope(tok)

    terminal_tool.cleanup_vm("raw-session-a")
    assert terminal_tool._active_environments[environment_key] is env
    assert env.cleanup_calls == 0
    assert terminal_tool._environment_owners_by_key[environment_key] == {
        "raw-session-b"
    }

    terminal_tool.cleanup_vm("raw-session-b")
    assert env.cleanup_calls == 1
    assert terminal_tool._active_environments == {}
    assert terminal_tool._environment_keys_by_owner == {}
    assert terminal_tool._environment_owners_by_key == {}


def test_idle_cleanup_purges_environment_ownership_indexes(monkeypatch):
    env = type("Environment", (), {"cleanup": lambda self: None})()
    key = "default::ssh:opaque"
    monkeypatch.setattr(terminal_tool, "_active_environments", {key: env})
    monkeypatch.setattr(terminal_tool, "_last_activity", {key: 0.0})
    monkeypatch.setattr(terminal_tool, "_creation_locks", {key: object()})
    monkeypatch.setattr(
        terminal_tool, "_environment_keys_by_owner", {"raw-session": {key}}
    )
    monkeypatch.setattr(
        terminal_tool, "_environment_owners_by_key", {key: {"raw-session"}}
    )

    terminal_tool._cleanup_inactive_envs(lifetime_seconds=0)

    assert terminal_tool._active_environments == {}
    assert terminal_tool._creation_locks == {}
    assert terminal_tool._environment_keys_by_owner == {}
    assert terminal_tool._environment_owners_by_key == {}


def test_cleanup_all_purges_orphaned_environment_ownership_indexes(
    monkeypatch, tmp_path,
):
    monkeypatch.setattr(terminal_tool, "_active_environments", {})
    monkeypatch.setattr(terminal_tool, "_last_activity", {})
    monkeypatch.setattr(terminal_tool, "_creation_locks", {})
    monkeypatch.setattr(
        terminal_tool,
        "_environment_keys_by_owner",
        {"raw-session": {"default::ssh:stale"}},
    )
    monkeypatch.setattr(
        terminal_tool,
        "_environment_owners_by_key",
        {"default::ssh:stale": {"raw-session"}},
    )
    monkeypatch.setattr(terminal_tool, "_get_scratch_dir", lambda: tmp_path)

    assert terminal_tool.cleanup_all_environments() == 0
    assert terminal_tool._environment_keys_by_owner == {}
    assert terminal_tool._environment_owners_by_key == {}


def test_file_and_code_paths_register_raw_owners_for_shared_ssh_env(monkeypatch):
    import tools.code_execution_tool as code_execution_tool
    import tools.file_tools as file_tools

    env = type("Environment", (), {"cwd": "~"})()
    monkeypatch.setenv("TERMINAL_ENV", "ssh")
    monkeypatch.setattr(terminal_tool, "_active_environments", {})
    monkeypatch.setattr(terminal_tool, "_last_activity", {})
    monkeypatch.setattr(terminal_tool, "_creation_locks", {})
    monkeypatch.setattr(terminal_tool, "_environment_keys_by_owner", {})
    monkeypatch.setattr(terminal_tool, "_environment_owners_by_key", {})
    monkeypatch.setattr(terminal_tool, "_create_environment", lambda **kwargs: env)
    monkeypatch.setattr(terminal_tool, "_start_cleanup_thread", lambda: None)
    monkeypatch.setattr(file_tools, "_file_ops_cache", {})

    tok = ss.set_secret_scope({
        "TERMINAL_SSH_HOST": "shared.example",
        "TERMINAL_SSH_USER": "alice",
        "TERMINAL_SSH_KEY": "/profiles/shared/id_ed25519",
    })
    try:
        file_tools._get_file_ops("file-owner")
        claimed_env, env_type = code_execution_tool._get_or_create_env("code-owner")
    finally:
        ss.reset_secret_scope(tok)

    environment_key = next(iter(terminal_tool._active_environments))
    assert claimed_env is env
    assert env_type == "ssh"
    assert terminal_tool._environment_owners_by_key[environment_key] == {
        "file-owner", "code-owner"
    }


def test_file_tracking_never_falls_back_to_raw_task_cache_for_ssh(monkeypatch):
    """A legacy raw-task cache entry cannot cross an SSH identity boundary."""
    import tools.file_tools as file_tools

    class CachedOps:
        cwd = "/wrong-profile"
        env = None

    monkeypatch.setenv("TERMINAL_ENV", "ssh")
    monkeypatch.setattr(file_tools, "_file_ops_cache", {"shared-session": CachedOps()})
    monkeypatch.setattr(file_tools, "_last_known_cwd", {"shared-session": "/wrong-profile"})

    tok = ss.set_secret_scope({
        "TERMINAL_SSH_HOST": "profile-a.example",
        "TERMINAL_SSH_USER": "alice",
    })
    try:
        assert file_tools._get_live_tracking_cwd("shared-session") is None
        assert file_tools._last_known_cwd_for("shared-session") is None
    finally:
        ss.reset_secret_scope(tok)


def test_ssh_cwd_override_never_mutates_legacy_raw_task_environment(monkeypatch):
    """Lifecycle helpers must obey the same SSH identity-only lookup rule."""
    legacy_env = type("LegacyEnvironment", (), {"cwd": "/wrong-profile"})()
    monkeypatch.setenv("TERMINAL_ENV", "ssh")
    monkeypatch.setattr(
        terminal_tool, "_active_environments", {"shared-session": legacy_env}
    )
    monkeypatch.setattr(terminal_tool, "_task_env_overrides", {})

    tok = ss.set_secret_scope({
        "TERMINAL_SSH_HOST": "profile-a.example",
        "TERMINAL_SSH_USER": "alice",
    })
    try:
        terminal_tool.register_task_env_overrides(
            "shared-session", {"cwd": "/profile-a"}
        )
    finally:
        ss.reset_secret_scope(tok)

    assert legacy_env.cwd == "/wrong-profile"
