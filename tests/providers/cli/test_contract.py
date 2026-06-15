"""Tests for the CLI-provider capability contract (AI-327).

Covers the pure readiness-normalization function and the BaseCLIProvider
wiring (probe + execute gating + error taxonomy), driven by mocked probes.
"""

from __future__ import annotations

import pytest

from providers.cli.contract import (
    AuthResult,
    BaseCLIProvider,
    DetectResult,
    ExecutionRequest,
    InvocationMode,
    ProviderCapabilities,
    ProviderErrorKind,
    Readiness,
    normalize_readiness,
)


@pytest.mark.parametrize(
    "detect,auth,expected",
    [
        (DetectResult(False), AuthResult(False), Readiness.NOT_INSTALLED),
        (DetectResult(False), AuthResult(True), Readiness.NOT_INSTALLED),
        (DetectResult(True), AuthResult(False), Readiness.NOT_AUTHENTICATED),
        (DetectResult(True), AuthResult(True, expired=True), Readiness.NOT_AUTHENTICATED),
        (DetectResult(True), AuthResult(True), Readiness.READY),
    ],
)
def test_normalize_readiness_matrix(detect, auth, expected):
    assert normalize_readiness(detect, auth) is expected


class _FakeProvider(BaseCLIProvider):
    install_hint = "install me"
    auth_hint = "log in"

    def __init__(self, detect: DetectResult, auth: AuthResult, models=()):
        self._detect = detect
        self._auth = auth
        self._models = tuple(models)

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            id="fake",
            display_name="Fake CLI",
            invocation_mode=InvocationMode.NON_INTERACTIVE,
        )

    def detect(self) -> DetectResult:
        return self._detect

    def check_auth(self) -> AuthResult:
        return self._auth

    def list_models(self) -> tuple[str, ...]:
        return self._models

    def _build_argv(self, request: ExecutionRequest) -> list[str]:
        # Echo keeps the execution path real but hermetic.
        return ["printf", "%s", request.prompt]


def test_probe_not_installed_sets_error_and_hint():
    p = _FakeProvider(DetectResult(False), AuthResult(False))
    report = p.probe()
    assert report.readiness is Readiness.NOT_INSTALLED
    assert report.error.kind is ProviderErrorKind.PROVIDER_NOT_INSTALLED
    assert report.setup_hint == "install me"
    assert report.models == ()


def test_probe_not_authenticated_sets_auth_error():
    p = _FakeProvider(DetectResult(True, path="/x"), AuthResult(False))
    report = p.probe()
    assert report.readiness is Readiness.NOT_AUTHENTICATED
    assert report.error.kind is ProviderErrorKind.PROVIDER_AUTH
    assert report.setup_hint == "log in"


def test_probe_ready_lists_models_and_is_json_safe():
    p = _FakeProvider(
        DetectResult(True, path="/x", version="1.2.3"),
        AuthResult(True, source="creds"),
        models=["a", "b"],
    )
    report = p.probe()
    assert report.readiness is Readiness.READY
    assert report.error is None
    assert report.models == ("a", "b")
    d = report.to_dict()
    assert d["readiness"] == "ready"  # str-enum serializes cleanly
    assert d["detect"]["version"] == "1.2.3"


def test_execute_refuses_when_not_ready():
    p = _FakeProvider(DetectResult(True, path="/x"), AuthResult(False))
    result = p.execute(ExecutionRequest(prompt="hi"))
    assert result.ok is False
    assert result.error.kind is ProviderErrorKind.PROVIDER_AUTH


def test_execute_runs_when_ready():
    p = _FakeProvider(DetectResult(True, path="/x"), AuthResult(True))
    result = p.execute(ExecutionRequest(prompt="hello", isolate_env=True))
    assert result.ok is True
    assert result.exit_code == 0
    assert "hello" in result.stdout
