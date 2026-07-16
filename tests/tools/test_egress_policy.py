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
