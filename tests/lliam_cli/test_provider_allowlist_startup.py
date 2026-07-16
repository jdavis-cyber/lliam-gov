"""P3.1 — provider-allowlist startup enforcement gate (LG-MP-02).

Validates the CONFIGURED providers on all five routing paths at startup and
fails closed (raises) under strict posture + `provider_allowlist_enforce` when
any path names a non-allowlisted provider/host. This is the single low-risk
enforcement seam (mirrors the P1.5 control-plane-auth gate) that keeps the hot
resolution path untouched. Advisory (returns findings) when non-strict or the
flag is off.
"""

from __future__ import annotations

import textwrap

import pytest

import lliam_cli.security_audit_startup as sas


_POLICY = textwrap.dedent(
    """
    metadata: {default_disposition: deny}
    enforcement:
      paths:
        primary: {enforce: true, on_violation: deny}
        fallback: {enforce: true, on_violation: deny}
        moa: {enforce: true, on_violation: deny}
        auxiliary: {enforce: true, on_violation: deny}
        delegation: {enforce: true, on_violation: deny}
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


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    import lliam_cli.provider_allowlist as pa
    pa.reset_provider_allowlist_cache()
    monkeypatch.setattr(sas, "_PROVIDER_ALLOWLIST_CHECKED", False, raising=False)
    yield
    pa.reset_provider_allowlist_cache()


def _cfg(tmp_path, extra):
    policy = tmp_path / "provider-allowlist.yaml"
    policy.write_text(_POLICY, encoding="utf-8")
    base = {"security": {"posture": "strict",
                         "provider_allowlist_enforce": True,
                         "provider_allowlist_path": str(policy)}}
    base.update(extra)
    return base


def test_allowlisted_primary_passes(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, {"model": {"provider": "lmstudio",
                                     "base_url": "http://127.0.0.1:1234/v1"}})
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    assert sas.enforce_provider_allowlist_at_startup(config=cfg) is None


def test_non_allowlisted_primary_blocks(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, {"model": {"provider": "openrouter",
                                     "base_url": "https://openrouter.ai/api/v1"}})
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    with pytest.raises(sas.ProviderAllowlistError, match="primary|openrouter"):
        sas.enforce_provider_allowlist_at_startup(config=cfg)


def test_non_allowlisted_fallback_blocks(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, {
        "model": {"provider": "lmstudio", "base_url": "http://127.0.0.1:1234/v1"},
        "fallback_providers": [
            {"provider": "openrouter", "model": "x", "base_url": "https://openrouter.ai"}],
    })
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    with pytest.raises(sas.ProviderAllowlistError, match="fallback"):
        sas.enforce_provider_allowlist_at_startup(config=cfg)


def test_non_allowlisted_moa_slot_blocks(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, {
        "model": {"provider": "lmstudio", "base_url": "http://127.0.0.1:1234/v1"},
        "moa": {"presets": {"default": {
            "reference_models": [{"provider": "openrouter", "model": "m",
                                   "base_url": "https://openrouter.ai"}],
            "aggregator": {"provider": "lmstudio", "model": "a",
                           "base_url": "http://127.0.0.1:1234/v1"}}}},
    })
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    with pytest.raises(sas.ProviderAllowlistError, match="moa"):
        sas.enforce_provider_allowlist_at_startup(config=cfg)


def test_non_allowlisted_delegation_blocks(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, {
        "model": {"provider": "lmstudio", "base_url": "http://127.0.0.1:1234/v1"},
        "delegation": {"provider": "zai", "model": "x", "base_url": "https://api.z.ai"},
    })
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    with pytest.raises(sas.ProviderAllowlistError, match="delegation"):
        sas.enforce_provider_allowlist_at_startup(config=cfg)


def test_advisory_when_enforce_flag_off(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, {"model": {"provider": "openrouter",
                                     "base_url": "https://openrouter.ai"}})
    cfg["security"]["provider_allowlist_enforce"] = False
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    # Non-enforcing → returns findings (advisory), does not raise.
    findings = sas.enforce_provider_allowlist_at_startup(config=cfg)
    assert findings is None or isinstance(findings, list)


def test_low_side_posture_no_block(tmp_path, monkeypatch):
    policy = tmp_path / "provider-allowlist.yaml"
    policy.write_text(_POLICY, encoding="utf-8")
    cfg = {"security": {"provider_allowlist_enforce": True,
                        "provider_allowlist_path": str(policy)},
           "model": {"provider": "openrouter", "base_url": "https://openrouter.ai"}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    assert sas.enforce_provider_allowlist_at_startup(config=cfg) is None
