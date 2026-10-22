"""P2.5 — Network egress boundary (deny-by-default allowlist + enclave).

LG-NE-01 (deny-by-default destination allowlist), LG-NE-02 (unconditional
SSRF/private/metadata floor — reusing url_safety.is_always_blocked_url),
LG-NE-03 (website allow/deny in allowlist mode), LG-NE-06 (air-gap/deny_all
profile). The new module tools/egress_policy.py layers allowlist semantics
OVER the existing SSRF guard; the always-blocked floor stays the runtime
authority and no allowlist entry can override it. No-op on low-side postures.
"""

from __future__ import annotations

import datetime
import textwrap
from pathlib import Path

import pytest
import yaml

_TODAY = datetime.date(2026, 7, 1)
_REPO = Path(__file__).resolve().parents[2]

_POLICY = textwrap.dedent(
    """
    metadata:
      default_disposition: deny
    approved_destinations:
      - {host: "bedrock-runtime.us-gov-west-1.amazonaws.com", surfaces: [provider], expires: "2026-12-31"}
      - {host: "api.github.com", surfaces: [web, mcp], expires: "2026-12-31"}
      - {host: "*.nist.gov", surfaces: [web, browser], expires: "2026-12-31"}
    """
)


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    """Regression tests exercise policy behavior, not current entry approval."""
    import tools.egress_policy as ep

    monkeypatch.setattr(ep, "_today", lambda: _TODAY)


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
          - {host: "metadata.google.internal", surfaces: [web], expires: "2026-12-31"}
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


# ---------------------------------------------------------------------------
# 5. LG-NE-01 — allowlist entries are time-boxed by ``expires``
# ---------------------------------------------------------------------------

def _strict_with_entry(tmp_path, monkeypatch, entry_yaml, **egress):
    policy = tmp_path / "egress-allowlist.yaml"
    policy.write_text(textwrap.dedent(
        f"""
        metadata: {{default_disposition: deny}}
        approved_destinations:
          - {entry_yaml}
        """
    ), encoding="utf-8")
    cfg = {"security": {"posture": "strict", "egress": {
        "mode": "allowlist", "policy_path": str(policy), "fail_closed": True,
        **egress}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    monkeypatch.setattr("tools.url_safety.is_safe_url", lambda _url: True)
    import tools.egress_policy as ep

    ep.reset_egress_cache()
    return ep


def test_unexpired_entry_is_allowed(tmp_path, monkeypatch):
    ep = _strict_with_entry(
        tmp_path, monkeypatch,
        '{host: "api.github.com", surfaces: [web], expires: "2026-07-02"}')
    assert ep.check_egress("https://api.github.com/x", surface="web").disposition == "allow"


def test_expired_entry_is_denied_with_reason(tmp_path, monkeypatch):
    ep = _strict_with_entry(
        tmp_path, monkeypatch,
        '{host: "api.github.com", surfaces: [web], expires: "2026-06-30"}')
    d = ep.check_egress("https://api.github.com/x", surface="web")
    assert d.disposition == "deny"
    assert "'api.github.com' (expired 2026-06-30)" in d.reason


@pytest.mark.parametrize("days_after_expiry, expected", [(0, "allow"), (1, "deny")])
def test_entry_valid_through_expires_day(tmp_path, monkeypatch, days_after_expiry, expected):
    ep = _strict_with_entry(
        tmp_path, monkeypatch,
        '{host: "api.github.com", surfaces: [web], expires: 2026-07-01}')  # YAML date
    monkeypatch.setattr(
        ep, "_today", lambda: _TODAY + datetime.timedelta(days=days_after_expiry))
    assert ep.check_egress("https://api.github.com/x", surface="web").disposition == expected


@pytest.mark.parametrize("expires, defect", [
    ('"2026-13-45"', "malformed expires"),
    ('"soon"', "malformed expires"),
    ("true", "malformed expires"),
    ('""', "missing expires"),
    (None, "missing expires"),
])
def test_missing_or_malformed_expires_fails_closed(tmp_path, monkeypatch, expires, defect):
    field = "" if expires is None else f", expires: {expires}"
    ep = _strict_with_entry(
        tmp_path, monkeypatch, f'{{host: "api.github.com", surfaces: [web]{field}}}')
    d = ep.check_egress("https://api.github.com/x", surface="web")
    assert d.disposition == "deny"
    assert defect in d.reason
    assert "api.github.com" in d.reason


def test_expired_entry_routes_to_hitl_when_configured(tmp_path, monkeypatch):
    ep = _strict_with_entry(
        tmp_path, monkeypatch,
        '{host: "api.github.com", surfaces: [web], expires: "2026-06-30"}',
        new_domain_disposition="hitl_approve")
    d = ep.check_egress("https://api.github.com/x", surface="web")
    assert d.disposition == "hitl_approve"
    assert "expired 2026-06-30" in d.reason


def test_expired_entry_does_not_shadow_a_valid_one(tmp_path, monkeypatch):
    policy = tmp_path / "egress-allowlist.yaml"
    policy.write_text(textwrap.dedent(
        """
        approved_destinations:
          - {host: "api.github.com", surfaces: [web], expires: "2026-06-30"}
          - {host: "github.com", surfaces: [web], expires: "2026-12-31"}
        """
    ), encoding="utf-8")
    cfg = {"security": {"posture": "strict", "egress": {
        "mode": "allowlist", "policy_path": str(policy)}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    monkeypatch.setattr("tools.url_safety.is_safe_url", lambda _url: True)
    import tools.egress_policy as ep

    ep.reset_egress_cache()
    # github.com parent rule still matches api.github.com and is in date.
    assert ep.check_egress("https://api.github.com/x", surface="web").disposition == "allow"


def test_low_side_posture_ignores_expiry(tmp_path, monkeypatch):
    policy = tmp_path / "egress-allowlist.yaml"
    policy.write_text(textwrap.dedent(
        """
        approved_destinations:
          - {host: "api.github.com", surfaces: [web], expires: "2026-06-30"}
        """
    ), encoding="utf-8")
    cfg = {"security": {"egress": {"policy_path": str(policy)}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import tools.egress_policy as ep

    ep.reset_egress_cache()
    assert ep.check_egress("https://api.github.com/x", surface="web").disposition == "allow"


@pytest.mark.parametrize("days_after_expiry", [0, 1])
def test_shipped_allowlist_expiry_boundaries(monkeypatch, days_after_expiry):
    """Every shipped entry is allowed on its expires day and denied the day
    after, under the shipped policy file and a controlled clock."""
    shipped = _REPO / "policy" / "egress-allowlist.yaml"
    entries = yaml.safe_load(shipped.read_text())["approved_destinations"]
    cfg = {"security": {"posture": "strict", "egress": {
        "mode": "allowlist", "policy_path": str(shipped)}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    monkeypatch.setattr("tools.url_safety.is_safe_url", lambda _url: True)
    import tools.egress_policy as ep

    ep.reset_egress_cache()
    assert entries
    for entry in entries:
        expires = ep._parse_expires(entry.get("expires"))
        assert expires is not None, entry
        today = expires + datetime.timedelta(days=days_after_expiry)
        monkeypatch.setattr(ep, "_today", lambda today=today: today)
        rule = entry["host"]
        host = "www." + rule[2:] if rule.startswith("*.") else rule
        d = ep.check_egress(f"https://{host}/x", surface=entry["surfaces"][0])
        assert d.disposition == ("deny" if days_after_expiry else "allow"), (entry, d)
        if days_after_expiry:
            assert f"expired {expires.isoformat()}" in d.reason
