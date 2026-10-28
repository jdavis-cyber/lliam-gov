"""P3.1 — Approved-provider allowlist across all 5 routing paths (LG-MP-01..04/08).

A NEW additive validator (lliam_cli/provider_allowlist.py) enforces the CUI
provider allowlist identically on every path that can egress CUI to a model —
primary, fallback, MoA, auxiliary, delegation — and FAIL-CLOSED rejects any
non-allowlisted provider slug or base_url host (no silent non-US route,
LG-MP-02). For CUI it additionally requires US/local residency + no_train +
TLS (LG-MP-03) and clamps high-sensitivity to local providers (LG-MP-04).
No-op on low-side postures (capability preserving).
"""

from __future__ import annotations

import textwrap

import pytest


_POLICY = textwrap.dedent(
    """
    metadata: {default_disposition: deny}
    enforcement:
      paths:
        primary:    {enforce: true, on_violation: deny}
        fallback:   {enforce: true, on_violation: deny}
        moa:        {enforce: true, on_violation: deny}
        auxiliary:  {enforce: true, on_violation: deny}
        delegation: {enforce: true, on_violation: deny}
      require_for_cui: {data_residency: us, no_train: true, tls_required: true}
      high_sensitivity: {local_only: true, preference: [lmstudio, ollama, vllm]}
    providers:
      - id: lmstudio
        provider_class: local
        base_url_hosts: ["127.0.0.1", "localhost"]
        data_residency: local
        no_train: true
        cui_eligible: true
        cui_only: true
      - id: bedrock
        provider_class: gov-cloud
        base_url_hosts: ["bedrock-runtime.us-gov-west-1.amazonaws.com"]
        data_residency: us
        no_train: true
        cui_eligible: true
        cui_only: false
    """
)

_PATHS = ["primary", "fallback", "moa", "auxiliary", "delegation"]


@pytest.fixture
def strict_pa(tmp_path, monkeypatch):
    policy = tmp_path / "provider-allowlist.yaml"
    policy.write_text(_POLICY, encoding="utf-8")
    cfg = {"security": {"posture": "strict",
                        "provider_allowlist_enforce": True,
                        "provider_allowlist_path": str(policy)}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import lliam_cli.provider_allowlist as pa

    pa.reset_provider_allowlist_cache()
    yield pa
    pa.reset_provider_allowlist_cache()


# ---------------------------------------------------------------------------
# 1. LG-MP-02 — approved in-boundary provider routes on ALL 5 paths
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", _PATHS)
def test_local_provider_allowed_on_every_path(strict_pa, path):
    d = strict_pa.validate_provider(
        "lmstudio", "http://127.0.0.1:1234/v1", path=path, cui=True)
    assert d.disposition == "allow"


@pytest.mark.parametrize("path", _PATHS)
def test_govcloud_provider_allowed_on_every_path(strict_pa, path):
    d = strict_pa.validate_provider(
        "bedrock", "https://bedrock-runtime.us-gov-west-1.amazonaws.com",
        path=path, cui=False)
    assert d.disposition == "allow"


# ---------------------------------------------------------------------------
# 2. LG-MP-01/02 — non-allowlisted provider/host rejected on EVERY path
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", _PATHS)
def test_non_allowlisted_provider_rejected_on_every_path(strict_pa, path):
    d = strict_pa.validate_provider(
        "openrouter", "https://openrouter.ai/api/v1", path=path, cui=True)
    assert d.disposition == "deny"


@pytest.mark.parametrize("path", _PATHS)
def test_right_slug_wrong_host_rejected_on_every_path(strict_pa, path):
    # bedrock slug but the COMMERCIAL (non-GovCloud) host — the classic bypass.
    d = strict_pa.validate_provider(
        "bedrock", "https://bedrock-runtime.us-east-1.amazonaws.com",
        path=path, cui=True)
    assert d.disposition == "deny"
    assert "host" in d.reason.lower()


# ---------------------------------------------------------------------------
# 3. LG-MP-03 — CUI requires US/local + no_train + TLS
# ---------------------------------------------------------------------------

def test_cui_rejected_over_plaintext_base_url(strict_pa):
    # bedrock GovCloud host but plaintext http:// → TLS required for CUI.
    d = strict_pa.validate_provider(
        "bedrock", "http://bedrock-runtime.us-gov-west-1.amazonaws.com",
        path="primary", cui=True)
    assert d.disposition == "deny"
    assert "tls" in d.reason.lower()


# ---------------------------------------------------------------------------
# 4. LG-MP-04 — high-sensitivity clamps to local providers
# ---------------------------------------------------------------------------

def test_high_sensitivity_clamps_cloud_to_approve(strict_pa):
    # bedrock is CUI-eligible cloud, but high_sensitivity_local_only routes a
    # non-local approved provider to HITL rather than auto-allow.
    d = strict_pa.validate_provider(
        "bedrock", "https://bedrock-runtime.us-gov-west-1.amazonaws.com",
        path="primary", cui=True, high_sensitivity=True)
    assert d.disposition == "approve"


def test_high_sensitivity_local_provider_still_allowed(strict_pa):
    d = strict_pa.validate_provider(
        "lmstudio", "http://127.0.0.1:1234/v1",
        path="primary", cui=True, high_sensitivity=True)
    assert d.disposition == "allow"


# ---------------------------------------------------------------------------
# 5. Fail-closed on blank + capability preservation
# ---------------------------------------------------------------------------

def test_blank_provider_fails_closed(strict_pa):
    d = strict_pa.validate_provider("", "", path="fallback", cui=True)
    assert d.disposition == "deny"


def test_low_side_posture_allows_all(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    import lliam_cli.provider_allowlist as pa

    pa.reset_provider_allowlist_cache()
    d = pa.validate_provider("openrouter", "https://openrouter.ai/api/v1",
                             path="primary", cui=True)
    assert d.disposition == "allow"  # complete no-op — shipped routing unchanged
    pa.reset_provider_allowlist_cache()


def test_enforce_disabled_is_noop(tmp_path, monkeypatch):
    policy = tmp_path / "provider-allowlist.yaml"
    policy.write_text(_POLICY, encoding="utf-8")
    cfg = {"security": {"posture": "strict",
                        "provider_allowlist_enforce": False,
                        "provider_allowlist_path": str(policy)}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import lliam_cli.provider_allowlist as pa

    pa.reset_provider_allowlist_cache()
    d = pa.validate_provider("openrouter", "https://openrouter.ai", path="primary", cui=True)
    assert d.disposition == "allow"
    pa.reset_provider_allowlist_cache()
