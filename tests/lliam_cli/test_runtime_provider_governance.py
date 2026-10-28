"""Runtime provider governance applies to the resolved endpoint, not startup only."""

from __future__ import annotations

import textwrap

import pytest

from lliam_cli.auth import AuthError
import lliam_cli.provider_allowlist as pa
import lliam_cli.runtime_provider as rp


_POLICY = textwrap.dedent(
    """
    enforcement:
      paths:
        primary: {enforce: true}
      require_for_cui: {data_residency: us, no_train: true, tls_required: true}
    providers:
      - id: lmstudio
        provider_class: local
        base_url_hosts: ["127.0.0.1", "localhost"]
        data_residency: local
        no_train: true
        cui_eligible: true
    """
)


@pytest.fixture
def strict_runtime(tmp_path, monkeypatch):
    policy = tmp_path / "provider-allowlist.yaml"
    policy.write_text(_POLICY, encoding="utf-8")
    cfg = {"security": {
        "posture": "strict",
        "provider_allowlist_enforce": True,
        "provider_allowlist_path": str(policy),
    }}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    monkeypatch.setattr("lliam_cli.provider_allowlist._security_cfg", lambda: cfg["security"])
    pa.reset_provider_allowlist_cache()
    yield
    pa.reset_provider_allowlist_cache()


def test_runtime_endpoint_is_checked_after_resolution(strict_runtime, monkeypatch):
    monkeypatch.setattr(rp, "_resolve_runtime_provider_unchecked", lambda **kw: {
        "provider": "custom",
        "requested_provider": "lmstudio",
        "base_url": "https://unapproved.example/v1",
        "api_key": "unused",
    })
    with pytest.raises(AuthError, match="blocked by governance"):
        rp.resolve_runtime_provider(requested="lmstudio")


def test_runtime_approved_endpoint_passes(strict_runtime, monkeypatch):
    expected = {
        "provider": "custom",
        "requested_provider": "lmstudio",
        "base_url": "http://127.0.0.1:1234/v1",
        "api_key": "unused",
    }
    monkeypatch.setattr(rp, "_resolve_runtime_provider_unchecked", lambda **kw: expected)
    assert rp.resolve_runtime_provider(requested="lmstudio") is expected


def test_path_specific_policy_is_forwarded(strict_runtime, monkeypatch):
    monkeypatch.setattr(rp, "_resolve_runtime_provider_unchecked", lambda **kw: {
        "provider": "custom", "requested_provider": "lmstudio",
        "base_url": "http://127.0.0.1:1234/v1", "api_key": "unused",
    })
    seen = {}
    original = pa.validate_provider

    def capture(*args, **kwargs):
        seen["path"] = kwargs.get("path")
        return original(*args, **kwargs)

    monkeypatch.setattr(pa, "validate_provider", capture)
    rp.resolve_runtime_provider(requested="lmstudio", governance_path="moa")
    assert seen["path"] == "moa"


def test_explicit_runtime_model_must_be_attested(strict_runtime, monkeypatch):
    monkeypatch.setattr(rp, "_resolve_runtime_provider_unchecked", lambda **kw: {
        "provider": "custom", "requested_provider": "lmstudio",
        "base_url": "http://127.0.0.1:1234/v1", "api_key": "unused",
    })
    monkeypatch.setattr(rp, "load_config", lambda: {"security": {"model_manifest_path": "manifest.yaml"}})
    monkeypatch.setattr(
        "agent.attestation.runtime_model_attested",
        lambda _mid: type("Verdict", (), {"valid": False, "reason": "not signed"})(),
    )
    with pytest.raises(AuthError, match="Runtime model blocked"):
        rp.resolve_runtime_provider(requested="lmstudio", target_model="model-b")
