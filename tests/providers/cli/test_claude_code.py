"""Tests for the Claude Code CLI provider adapter (AI-328).

Drives the adapter with fake ``which`` / ``run`` / ``$HOME`` / ``env`` /
``auth_probe`` injections, covering installed / authenticated / missing /
expired-auth / failure cases, plus the AI-334 token-safety invariant.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from providers.cli.claude_code import ClaudeCodeCLIProvider
from providers.cli.contract import Readiness


def _which_found(name: str):
    return "/usr/local/bin/claude" if name == "claude" else None


def _which_missing(name: str):
    return None


def _run_version(argv):
    return subprocess.CompletedProcess(argv, 0, stdout="1.0.42 (Claude Code)\n", stderr="")


def _make(tmp_path: Path, *, which=_which_found, run=_run_version, env=None, auth_probe=None):
    return ClaudeCodeCLIProvider(
        which=which, run=run, home=tmp_path, env=env or {}, auth_probe=auth_probe
    )


def _write_creds(tmp_path: Path, content: str = '{"token": "secret"}') -> Path:
    creds = tmp_path / ".claude" / ".credentials.json"
    creds.parent.mkdir(parents=True, exist_ok=True)
    creds.write_text(content)
    return creds


def test_detect_installed_with_version(tmp_path):
    p = _make(tmp_path)
    d = p.detect()
    assert d.installed is True
    assert d.path == "/usr/local/bin/claude"
    assert d.version == "1.0.42 (Claude Code)"


def test_detect_missing(tmp_path):
    p = _make(tmp_path, which=_which_missing)
    assert p.detect().installed is False


def test_ready_when_installed_and_credentials_present(tmp_path):
    _write_creds(tmp_path)
    report = _make(tmp_path).probe()
    assert report.readiness is Readiness.READY
    assert report.auth.authenticated is True
    assert report.auth.source == "claude_code_cli_credentials"
    assert report.default_model == "sonnet"
    assert report.error is None


def test_not_authenticated_when_no_credentials(tmp_path):
    report = _make(tmp_path).probe()
    assert report.readiness is Readiness.NOT_AUTHENTICATED
    assert report.setup_hint == "claude setup-token"


def test_not_installed_short_circuits_auth(tmp_path):
    _write_creds(tmp_path)  # creds exist but CLI is gone
    report = _make(tmp_path, which=_which_missing).probe()
    assert report.readiness is Readiness.NOT_INSTALLED
    assert report.setup_hint == "npm install -g @anthropic-ai/claude-code"


def test_expired_auth_probe_marks_not_authenticated(tmp_path):
    report = _make(tmp_path, auth_probe=lambda: "expired").probe()
    assert report.auth.authenticated is True
    assert report.auth.expired is True
    assert report.readiness is Readiness.NOT_AUTHENTICATED


def test_unauthenticated_auth_probe(tmp_path):
    report = _make(tmp_path, auth_probe=lambda: "unauthenticated").probe()
    assert report.readiness is Readiness.NOT_AUTHENTICATED


def test_env_token_presence_is_authenticated(tmp_path):
    p = _make(tmp_path, env={"ANTHROPIC_API_KEY": "sk-whatever"})
    auth = p.check_auth()
    assert auth.authenticated is True
    assert auth.source == "env:ANTHROPIC_API_KEY"


def test_token_value_is_never_read(tmp_path):
    """AI-334: auth detection must not parse/read the credential contents."""
    # Deliberately invalid JSON — if the adapter tried to parse it, this would
    # raise. Auth detection must succeed purely from file presence.
    _write_creds(tmp_path, content="this is not json at all {{{")
    auth = _make(tmp_path).check_auth()
    assert auth.authenticated is True


def test_detect_version_failure_is_tolerated(tmp_path):
    def _run_boom(argv):
        raise OSError("boom")

    d = _make(tmp_path, run=_run_boom).detect()
    assert d.installed is True
    assert d.version is None


def test_build_argv_includes_model(tmp_path):
    from providers.cli.contract import ExecutionRequest

    p = _make(tmp_path)
    argv = p._build_argv(ExecutionRequest(prompt="hi", model="opus"))
    assert argv == ["claude", "-p", "hi", "--model", "opus"]
