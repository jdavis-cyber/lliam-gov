"""P2.5 — Network egress boundary (deny-by-default allowlist + enclave).

LG-NE-01 (deny-by-default destination allowlist), LG-NE-02 (unconditional
SSRF/private/metadata floor — reusing url_safety.is_always_blocked_url),
LG-NE-03 (website allow/deny in allowlist mode), LG-NE-06 (air-gap/deny_all
profile). The new module tools/egress_policy.py layers allowlist semantics
OVER the existing SSRF guard; the always-blocked floor stays the runtime
authority and no allowlist entry can override it. No-op on low-side postures.
"""

from __future__ import annotations

import textwrap

import pytest


_POLICY = textwrap.dedent(
    """
    metadata:
      default_disposition: deny
    approved_destinations:
      - {host: "bedrock-runtime.us-gov-west-1.amazonaws.com", surfaces: [provider]}
      - {host: "api.github.com", surfaces: [web, mcp]}
      - {host: "*.nist.gov", surfaces: [web, browser]}
    """
)


@pytest.fixture
def strict_egress(tmp_path, monkeypatch):
    policy = tmp_path / "egress-allowlist.yaml"
    policy.write_text(_POLICY, encoding="utf-8")
    cfg = {"security": {"posture": "strict", "allow_private_urls": False,
                        "egress": {"mode": "allowlist",
                                   "policy_path": str(policy),
                                   "fail_closed": True}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import tools.egress_policy as ep

    ep.reset_egress_cache()
    yield ep
    ep.reset_egress_cache()


# ---------------------------------------------------------------------------
# 1. LG-NE-01/03 — deny-by-default allowlist
# ---------------------------------------------------------------------------

def test_allowlisted_host_is_allowed(strict_egress):
    d = strict_egress.check_egress("https://api.github.com/repos/x", surface="web")
    assert d.disposition == "allow"


def test_wildcard_parent_domain_allowed(strict_egress):
    d = strict_egress.check_egress("https://csrc.nist.gov/pubs", surface="web")
    assert d.disposition == "allow"


def test_non_allowlisted_host_denied_by_default(strict_egress):
    d = strict_egress.check_egress("https://pastebin.test/raw", surface="web")
    assert d.disposition == "deny"
    assert "allowlist" in d.reason.lower()


def test_surface_mismatch_is_not_allowed(strict_egress):
    # api.github.com is approved for web/mcp, NOT browser.
    d = strict_egress.check_egress("https://api.github.com/x", surface="browser")
    assert d.disposition != "allow"


def test_allowlisted_host_over_http_is_denied(strict_egress):
    d = strict_egress.check_egress("http://api.github.com/repos/x", surface="web")
    assert d.disposition == "deny"
    assert "scheme" in d.reason.lower()


def test_allowlisted_hostname_resolving_private_is_denied(strict_egress, monkeypatch):
    monkeypatch.setattr("tools.url_safety.is_always_blocked_url", lambda _url: False)
    monkeypatch.setattr("tools.url_safety.is_safe_url", lambda _url: False)
    d = strict_egress.check_egress("https://api.github.com/repos/x", surface="web")
    assert d.disposition == "deny"
    assert "unsafe" in d.reason.lower()


def test_public_ceiling_denies_cui_tainted_session(strict_egress, monkeypatch):
    import agent.data_protection as dp

    monkeypatch.setattr("tools.url_safety.is_safe_url", lambda _url: True)
    dp.reset_dp_state()
    dp.note_cui_exposure("read_file", "CUI\nContract data\nCUI", session_id="s1")
    d = strict_egress.check_egress(
        "https://api.github.com/repos/x", surface="web", session_id="s1"
    )
    assert d.disposition == "deny"
    assert "ceiling" in d.reason.lower()
    dp.reset_dp_state()


# ---------------------------------------------------------------------------
# 2. LG-NE-02 — unconditional SSRF/metadata floor (allowlist can't override)
# ---------------------------------------------------------------------------

def test_metadata_endpoint_always_blocked(strict_egress):
    d = strict_egress.check_egress("http://169.254.169.254/latest/meta-data/", surface="web")
    assert d.disposition == "deny"
    assert "metadata" in d.reason.lower() or "block" in d.reason.lower()


def test_private_ip_always_blocked(strict_egress):
    d = strict_egress.check_egress("http://10.0.0.5/admin", surface="web")
    assert d.disposition == "deny"


def test_metadata_block_wins_even_if_allowlisted(strict_egress, tmp_path, monkeypatch):
    # Even if someone lists a metadata host, the floor still denies it.
    policy = tmp_path / "egress-allowlist.yaml"
    policy.write_text(textwrap.dedent(
        """
        metadata: {default_disposition: deny}
        approved_destinations:
          - {host: "metadata.google.internal", surfaces: [web]}
        """
    ), encoding="utf-8")
    cfg = {"security": {"posture": "strict", "egress": {
        "mode": "allowlist", "policy_path": str(policy), "fail_closed": True}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    strict_egress.reset_egress_cache()
    d = strict_egress.check_egress("http://metadata.google.internal/x", surface="web")
    assert d.disposition == "deny"  # floor beats the allowlist entry


# ---------------------------------------------------------------------------
# 3. LG-NE-06 — air-gap / deny_all profile
# ---------------------------------------------------------------------------

def test_air_gap_mode_denies_even_allowlisted(tmp_path, monkeypatch):
    policy = tmp_path / "egress-allowlist.yaml"
    policy.write_text(_POLICY, encoding="utf-8")
    cfg = {"security": {"posture": "strict", "egress": {
        "mode": "deny_all", "policy_path": str(policy)}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import tools.egress_policy as ep

    ep.reset_egress_cache()
    d = ep.check_egress("https://api.github.com/x", surface="web")
    assert d.disposition == "deny"
    assert "air-gap" in d.reason.lower() or "deny_all" in d.reason.lower()
    ep.reset_egress_cache()


# ---------------------------------------------------------------------------
# 4. Capability preservation — low-side no-op
# ---------------------------------------------------------------------------

def test_low_side_posture_allows_all(monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    import tools.egress_policy as ep

    ep.reset_egress_cache()
    d = ep.check_egress("https://pastebin.test/raw", surface="web")
    assert d.disposition == "allow"  # PDP/website_policy unchanged on low-side
    ep.reset_egress_cache()


def test_posture_resolution_error_fails_closed(monkeypatch):
    def _broken(*_args, **_kwargs):
        raise RuntimeError("config unavailable")

    monkeypatch.setattr("lliam_cli.config.load_config", _broken)
    import tools.egress_policy as ep

    assert ep.check_egress("https://api.github.com/x").disposition == "deny"


def test_dispatch_funnel_blocks_http_before_tool_execution(strict_egress, monkeypatch):
    import json
    import model_tools
    from tools.registry import registry

    called = []
    monkeypatch.setattr(registry, "dispatch", lambda *a, **kw: called.append(a) or "{}")
    result = model_tools.handle_function_call(
        "web_extract", {"url": "http://api.github.com/x"},
        skip_pre_tool_call_hook=True,
    )
    assert not called
    assert "error" in json.loads(result)


def test_provider_request_boundary_enforces_deny_all(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from agent.chat_completion_helpers import _enforce_provider_egress

    policy = tmp_path / "egress-allowlist.yaml"
    policy.write_text(_POLICY, encoding="utf-8")
    cfg = {"security": {"posture": "strict", "egress": {
        "mode": "deny_all", "policy_path": str(policy)}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    agent = SimpleNamespace(
        base_url="https://bedrock-runtime.us-gov-west-1.amazonaws.com",
        _anthropic_base_url=None,
        client=None,
        session_id="session-a",
    )
    with pytest.raises(PermissionError, match="air-gap|deny_all"):
        _enforce_provider_egress(agent)


def test_squid_and_compose_enforce_tls_and_private_dns():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    compose = (root / "deploy/docker-compose.gov.override.yml").read_text()
    squid = (root / "deploy/config/squid-allowlist.conf").read_text()
    assert "./deploy/config/squid-allowlist.conf" in compose
    assert "http_access deny !CONNECT" in squid
    assert "acl private_dst dst" in squid
    assert "dst_as_regex" not in squid


def test_new_domain_hitl_mode(tmp_path, monkeypatch):
    policy = tmp_path / "egress-allowlist.yaml"
    policy.write_text(_POLICY, encoding="utf-8")
    cfg = {"security": {"posture": "strict", "egress": {
        "mode": "allowlist", "policy_path": str(policy),
        "new_domain_disposition": "hitl_approve"}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import tools.egress_policy as ep

    ep.reset_egress_cache()
    d = ep.check_egress("https://newvendor.test/api", surface="web")
    assert d.disposition == "hitl_approve"  # new domain routes to approver
    ep.reset_egress_cache()
