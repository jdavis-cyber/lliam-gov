"""Tests for the streaming/cancellable execution runtime (AI-327/AI-328).

Drives BaseCLIProvider.stream()/execute() against real fake CLI scripts so the
subprocess streaming, error classification, timeout, and cancellation paths are
genuinely exercised (not mocked).
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from providers.cli.contract import (
    AuthResult,
    BaseCLIProvider,
    CancelToken,
    DetectResult,
    ExecutionRequest,
    InvocationMode,
    ProviderCapabilities,
    ProviderErrorKind,
    ResultEventKind,
)


def _script(tmp_path: Path, name: str, body: str) -> list[str]:
    p = tmp_path / name
    p.write_text("#!/bin/bash\n" + body)
    return ["bash", str(p)]


class _ScriptProvider(BaseCLIProvider):
    install_hint = "install-me"
    auth_hint = "log-in"

    def __init__(self, argv: list[str], *, ready: bool = True, installed: bool = True):
        self._argv = argv
        self._ready = ready
        self._installed = installed

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
        return DetectResult(installed=self._installed)

    def check_auth(self) -> AuthResult:
        return AuthResult(authenticated=self._ready)

    def _build_argv(self, request: ExecutionRequest) -> list[str]:
        return list(self._argv)


def test_stream_emits_text_events_then_done(tmp_path):
    p = _ScriptProvider(_script(tmp_path, "ok.sh", "echo line1\necho line2\necho line3\n"))
    events = list(p.stream(ExecutionRequest(prompt="hi")))
    texts = [e.text for e in events if e.kind is ResultEventKind.TEXT]
    assert texts == ["line1", "line2", "line3"]
    done = events[-1]
    assert done.kind is ResultEventKind.DONE
    assert done.data["ok"] is True
    assert done.data["exit_code"] == 0


def test_execute_collects_stdout(tmp_path):
    p = _ScriptProvider(_script(tmp_path, "ok.sh", "echo hello\necho world\n"))
    res = p.execute(ExecutionRequest(prompt="hi"))
    assert res.ok is True
    assert res.exit_code == 0
    assert res.stdout == "hello\nworld"
    assert res.error is None


def test_execute_maps_generic_failure(tmp_path):
    p = _ScriptProvider(_script(tmp_path, "boom.sh", "echo oops >&2\nexit 3\n"))
    res = p.execute(ExecutionRequest(prompt="hi"))
    assert res.ok is False
    assert res.exit_code == 3
    assert res.error.kind is ProviderErrorKind.PROVIDER_EXECUTION
    assert "oops" in res.stderr


def test_execute_classifies_rate_limit(tmp_path):
    p = _ScriptProvider(_script(tmp_path, "rl.sh", "echo 'Error: rate limit exceeded (429)' >&2\nexit 1\n"))
    res = p.execute(ExecutionRequest(prompt="hi"))
    assert res.error.kind is ProviderErrorKind.PROVIDER_RATE_LIMIT
    assert res.error.retryable is True


def test_execute_classifies_auth_failure(tmp_path):
    p = _ScriptProvider(_script(tmp_path, "auth.sh", "echo 'not logged in, please run login' >&2\nexit 1\n"))
    res = p.execute(ExecutionRequest(prompt="hi"))
    assert res.error.kind is ProviderErrorKind.PROVIDER_AUTH


def test_execute_times_out(tmp_path):
    p = _ScriptProvider(_script(tmp_path, "slow.sh", "sleep 5\necho late\n"))
    start = time.monotonic()
    res = p.execute(ExecutionRequest(prompt="hi", timeout_s=0.3))
    elapsed = time.monotonic() - start
    assert res.ok is False
    assert res.error.kind is ProviderErrorKind.TIMEOUT
    assert res.error.retryable is True
    assert elapsed < 4  # bailed out well before the 5s sleep


def test_execute_cancels(tmp_path):
    p = _ScriptProvider(_script(tmp_path, "slow.sh", "sleep 5\necho late\n"))
    cancel = CancelToken()
    timer = threading.Timer(0.3, cancel.cancel)
    timer.start()
    start = time.monotonic()
    res = p.execute(ExecutionRequest(prompt="hi", timeout_s=10), cancel=cancel)
    elapsed = time.monotonic() - start
    timer.cancel()
    assert res.ok is False
    assert res.error.kind is ProviderErrorKind.CANCELLED
    assert elapsed < 4


def test_stream_refuses_when_not_installed(tmp_path):
    p = _ScriptProvider(["bash", "-c", "echo nope"], installed=False)
    events = list(p.stream(ExecutionRequest(prompt="hi")))
    assert events[0].kind is ResultEventKind.ERROR
    assert events[0].error.kind is ProviderErrorKind.PROVIDER_NOT_INSTALLED
    assert events[-1].kind is ResultEventKind.DONE
    assert events[-1].data["ok"] is False


def test_stream_refuses_when_not_authenticated(tmp_path):
    p = _ScriptProvider(["bash", "-c", "echo nope"], ready=False)
    res = _ScriptProvider(["bash", "-c", "echo nope"], ready=False).execute(
        ExecutionRequest(prompt="hi")
    )
    assert res.ok is False
    assert res.error.kind is ProviderErrorKind.PROVIDER_AUTH
