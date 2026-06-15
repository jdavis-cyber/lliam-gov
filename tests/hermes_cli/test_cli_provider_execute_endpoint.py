"""Tests for POST /api/providers/cli/{id}/execute (AI-328 selectability)."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

import providers.cli as cli
from providers.cli.contract import ExecutionResult, ProviderError, ProviderErrorKind
from hermes_cli.web_server import CliExecuteRequest, execute_cli_provider


class _FakeProvider:
    def __init__(self, result: ExecutionResult):
        self._result = result
        self.last_request = None

    def execute(self, request):
        self.last_request = request
        return self._result


def test_execute_success(monkeypatch):
    fake = _FakeProvider(ExecutionResult(ok=True, stdout="pong", exit_code=0))
    monkeypatch.setattr(cli, "get_provider", lambda pid: fake)
    out = execute_cli_provider("claude-code", CliExecuteRequest(prompt="ping"))
    assert out["ok"] is True
    assert out["stdout"] == "pong"
    assert out["error"] is None
    assert fake.last_request.prompt == "ping"


def test_execute_maps_error(monkeypatch):
    err = ProviderError(ProviderErrorKind.PROVIDER_AUTH, "not logged in", remediation="claude setup-token")
    monkeypatch.setattr(cli, "get_provider", lambda pid: _FakeProvider(ExecutionResult(ok=False, error=err)))
    out = execute_cli_provider("claude-code", CliExecuteRequest(prompt="ping"))
    assert out["ok"] is False
    assert out["error"]["kind"] == "provider_auth"
    assert out["error"]["remediation"] == "claude setup-token"


def test_execute_unknown_provider(monkeypatch):
    monkeypatch.setattr(cli, "get_provider", lambda pid: None)
    with pytest.raises(HTTPException) as ei:
        execute_cli_provider("nope", CliExecuteRequest(prompt="ping"))
    assert ei.value.status_code == 404


def test_execute_requires_prompt(monkeypatch):
    monkeypatch.setattr(cli, "get_provider", lambda pid: _FakeProvider(ExecutionResult(ok=True)))
    with pytest.raises(HTTPException) as ei:
        execute_cli_provider("claude-code", CliExecuteRequest(prompt="   "))
    assert ei.value.status_code == 400


def test_execute_clamps_timeout(monkeypatch):
    fake = _FakeProvider(ExecutionResult(ok=True, stdout="x"))
    monkeypatch.setattr(cli, "get_provider", lambda pid: fake)
    execute_cli_provider("codex", CliExecuteRequest(prompt="ping", timeout_s=99999))
    assert fake.last_request.timeout_s == 600.0  # clamped to max
