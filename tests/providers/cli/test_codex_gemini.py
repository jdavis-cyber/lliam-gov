"""Tests for the Codex and Gemini CLI adapters + registry (AI-328).

Driven with fake which/run/$HOME/env/auth_probe injections, covering installed
/ authenticated / missing / expired-auth cases and the AI-334 token-safety
invariant. Mirrors the Claude Code adapter tests.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from providers.cli.codex import CodexCLIProvider
from providers.cli.gemini import GeminiCLIProvider
from providers.cli.contract import CLIProvider, Readiness
from providers.cli import registry


# ── parametrized across both adapters ──────────────────────────────────────

CASES = [
    (CodexCLIProvider, "codex", (".codex", "auth.json"), "OPENAI_API_KEY", "codex login"),
    (
        GeminiCLIProvider,
        "gemini",
        (".gemini", "oauth_creds.json"),
        "GEMINI_API_KEY",
        "gemini  # complete the browser sign-in on first run",
    ),
]


def _which_for(binary):
    def _which(name):
        return f"/usr/local/bin/{binary}" if name == binary else None

    return _which


def _run_version(argv):
    return subprocess.CompletedProcess(argv, 0, stdout="9.9.9\n", stderr="")


def _write_creds(tmp_path: Path, rel: tuple[str, str], content="not-json {{{"):
    p = tmp_path.joinpath(*rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


@pytest.mark.parametrize("cls,binary,cred_rel,env_var,auth_hint", CASES)
def test_detect_installed(tmp_path, cls, binary, cred_rel, env_var, auth_hint):
    p = cls(which=_which_for(binary), run=_run_version, home=tmp_path, env={})
    d = p.detect()
    assert d.installed is True
    assert d.path == f"/usr/local/bin/{binary}"
    assert d.version == "9.9.9"


@pytest.mark.parametrize("cls,binary,cred_rel,env_var,auth_hint", CASES)
def test_detect_missing(tmp_path, cls, binary, cred_rel, env_var, auth_hint):
    p = cls(which=lambda n: None, run=_run_version, home=tmp_path, env={})
    assert p.detect().installed is False


@pytest.mark.parametrize("cls,binary,cred_rel,env_var,auth_hint", CASES)
def test_ready_with_credentials(tmp_path, cls, binary, cred_rel, env_var, auth_hint):
    _write_creds(tmp_path, cred_rel)
    p = cls(which=_which_for(binary), run=_run_version, home=tmp_path, env={})
    report = p.probe()
    assert report.readiness is Readiness.READY
    assert report.auth.authenticated is True
    assert report.default_model  # each adapter declares a default


@pytest.mark.parametrize("cls,binary,cred_rel,env_var,auth_hint", CASES)
def test_not_authenticated_hint(tmp_path, cls, binary, cred_rel, env_var, auth_hint):
    p = cls(which=_which_for(binary), run=_run_version, home=tmp_path, env={})
    report = p.probe()
    assert report.readiness is Readiness.NOT_AUTHENTICATED
    assert report.setup_hint == auth_hint


@pytest.mark.parametrize("cls,binary,cred_rel,env_var,auth_hint", CASES)
def test_env_token_presence(tmp_path, cls, binary, cred_rel, env_var, auth_hint):
    p = cls(which=_which_for(binary), run=_run_version, home=tmp_path, env={env_var: "x"})
    assert p.check_auth().authenticated is True


@pytest.mark.parametrize("cls,binary,cred_rel,env_var,auth_hint", CASES)
def test_token_never_read(tmp_path, cls, binary, cred_rel, env_var, auth_hint):
    # Invalid contents — must still resolve as authenticated from presence alone.
    _write_creds(tmp_path, cred_rel, content="garbage {{{ not json")
    p = cls(which=_which_for(binary), run=_run_version, home=tmp_path, env={})
    assert p.check_auth().authenticated is True


@pytest.mark.parametrize("cls,binary,cred_rel,env_var,auth_hint", CASES)
def test_expired_probe(tmp_path, cls, binary, cred_rel, env_var, auth_hint):
    p = cls(
        which=_which_for(binary),
        run=_run_version,
        home=tmp_path,
        env={},
        auth_probe=lambda: "expired",
    )
    report = p.probe()
    assert report.auth.expired is True
    assert report.readiness is Readiness.NOT_AUTHENTICATED


def test_codex_honors_codex_home(tmp_path):
    alt = tmp_path / "alt-codex"
    (alt).mkdir()
    (alt / "auth.json").write_text("x")
    p = CodexCLIProvider(
        which=_which_for("codex"), run=_run_version, home=tmp_path, env={"CODEX_HOME": str(alt)}
    )
    assert p.check_auth().authenticated is True


# ── registry ───────────────────────────────────────────────────────────────


def test_registry_lists_three_providers():
    providers = registry.all_providers()
    ids = {p.capabilities.id for p in providers}
    assert ids == {"claude-code", "codex", "gemini"}
    for p in providers:
        assert isinstance(p, CLIProvider)


def test_registry_get_provider():
    assert registry.get_provider("codex").capabilities.id == "codex"
    assert registry.get_provider("nope") is None


def test_registry_probe_all_returns_reports():
    reports = registry.probe_all()
    assert len(reports) == 3
    assert all(r.to_dict()["id"] for r in reports)
