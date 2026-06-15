"""Tests for the AI-334 subprocess hardening boundary.

Exercises the real subprocess runtime against fake CLI scripts so the env
allowlist, explicit/temp cwd, output-size limit, and redacted audit hook are
genuinely enforced (not mocked).
"""

from __future__ import annotations

import os
from pathlib import Path

from providers.cli.contract import (
    ENV_ALLOWLIST,
    AuthResult,
    BaseCLIProvider,
    DetectResult,
    ExecutionRequest,
    InvocationMode,
    ProviderCapabilities,
    ProviderErrorKind,
    build_isolated_env,
)


def _script(tmp_path: Path, name: str, body: str) -> list[str]:
    p = tmp_path / name
    p.write_text("#!/bin/bash\n" + body)
    return ["bash", str(p)]


class _ScriptProvider(BaseCLIProvider):
    install_hint = "install-me"
    auth_hint = "log-in"

    def __init__(self, argv: list[str]):
        self._argv = argv

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            id="script",
            display_name="Script CLI",
            invocation_mode=InvocationMode.NON_INTERACTIVE,
            supports_streaming=True,
            supports_cancellation=True,
        )

    def detect(self) -> DetectResult:
        return DetectResult(installed=True)

    def check_auth(self) -> AuthResult:
        return AuthResult(authenticated=True)

    def _build_argv(self, request: ExecutionRequest) -> list[str]:
        return list(self._argv)


# ── env allowlist ─────────────────────────────────────────────────────────────
def test_build_isolated_env_drops_secrets():
    base = {
        "PATH": "/usr/bin",
        "HOME": "/home/x",
        "ANTHROPIC_API_KEY": "sk-ant-leak",
        "OPENAI_API_KEY": "sk-leak",
        "AWS_SECRET_ACCESS_KEY": "leak",
        "SOME_TOKEN": "leak",
    }
    env = build_isolated_env(base=base)
    assert env == {"PATH": "/usr/bin", "HOME": "/home/x"}
    for secret in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "SOME_TOKEN"):
        assert secret not in env


def test_allowlist_excludes_api_key_names():
    assert not any(
        "API_KEY" in v or "TOKEN" in v or "SECRET" in v for v in ENV_ALLOWLIST
    )


def test_isolated_env_at_runtime_hides_parent_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-shouldnotleak")
    p = _ScriptProvider(_script(tmp_path, "env.sh", 'echo "KEY=[${ANTHROPIC_API_KEY}]"\n'))
    res = p.execute(ExecutionRequest(prompt="hi", isolate_env=True))
    assert res.ok is True
    assert "sk-ant-shouldnotleak" not in res.stdout
    assert "KEY=[]" in res.stdout


def test_non_isolated_env_passes_through(tmp_path, monkeypatch):
    monkeypatch.setenv("LLIAM_TEST_MARKER", "present")
    p = _ScriptProvider(_script(tmp_path, "env.sh", 'echo "M=[${LLIAM_TEST_MARKER}]"\n'))
    res = p.execute(ExecutionRequest(prompt="hi", isolate_env=False))
    assert "M=[present]" in res.stdout


# ── explicit cwd ──────────────────────────────────────────────────────────────
def test_default_cwd_is_temp_not_process_cwd(tmp_path):
    # No cwd given → runs in a fresh temp dir, NOT Lliam-GOV's process cwd.
    p = _ScriptProvider(_script(tmp_path, "pwd.sh", "pwd\n"))
    res = p.execute(ExecutionRequest(prompt="hi"))
    assert res.ok is True
    where = res.stdout.strip()
    assert where != os.getcwd()
    assert "lliam-prov-" in where


def test_default_cwd_temp_is_cleaned_up(tmp_path):
    p = _ScriptProvider(_script(tmp_path, "pwd.sh", "pwd\n"))
    res = p.execute(ExecutionRequest(prompt="hi"))
    where = res.stdout.strip()
    assert not os.path.exists(where)  # removed after execution


def test_explicit_cwd_is_honored(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    p = _ScriptProvider(_script(tmp_path, "pwd.sh", "pwd\n"))
    res = p.execute(ExecutionRequest(prompt="hi", cwd=str(work)))
    assert os.path.realpath(res.stdout.strip()) == os.path.realpath(str(work))
    assert work.exists()  # caller-owned cwd is never deleted


# ── output-size limit ─────────────────────────────────────────────────────────
def test_output_limit_aborts(tmp_path):
    # Emit far more than the cap; runtime must abort with OUTPUT_LIMIT.
    p = _ScriptProvider(
        _script(tmp_path, "flood.sh", "for i in $(seq 1 100000); do echo 'xxxxxxxxxxxxxxxx'; done\n")
    )
    res = p.execute(ExecutionRequest(prompt="hi", max_output_bytes=2000, timeout_s=10))
    assert res.ok is False
    assert res.error.kind is ProviderErrorKind.OUTPUT_LIMIT


def test_within_output_limit_ok(tmp_path):
    p = _ScriptProvider(_script(tmp_path, "small.sh", "echo hello\n"))
    res = p.execute(ExecutionRequest(prompt="hi", max_output_bytes=1_000_000))
    assert res.ok is True
    assert "hello" in res.stdout


# ── redacted audit hook ───────────────────────────────────────────────────────
def test_audit_hook_fires_on_failure_with_redaction(tmp_path):
    events: list[dict] = []
    p = _ScriptProvider(
        _script(tmp_path, "boom.sh", "echo 'ANTHROPIC_API_KEY=sk-ant-secret012345' >&2\nexit 4\n")
    )
    p.audit_hook = events.append
    res = p.execute(ExecutionRequest(prompt="hi"))
    assert res.ok is False
    assert len(events) == 1
    summary = events[0]
    assert summary["event"] == "provider_execution_failure"
    assert summary["error_kind"] == ProviderErrorKind.PROVIDER_EXECUTION.value
    assert summary["exit_code"] == 4
    # Secret must be redacted out of the audit record; prompt is never included.
    assert "sk-ant-secret012345" not in summary["stderr_snippet"]
    assert "prompt" not in summary


def test_audit_hook_not_called_on_success(tmp_path):
    events: list[dict] = []
    p = _ScriptProvider(_script(tmp_path, "ok.sh", "echo fine\n"))
    p.audit_hook = events.append
    res = p.execute(ExecutionRequest(prompt="hi"))
    assert res.ok is True
    assert events == []
