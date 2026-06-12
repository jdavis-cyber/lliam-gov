"""Egress allowlist + TLS posture — LG-4.3 / AI-220.

WHY: SP 800-171 3.1.20/3.13.1 require controlled connections to external
systems; 3.13.8 requires CUI in transit be protected. These tests pin the
fail-closed semantics: enforcement with NO allowlist is deny-all, a
misconfigured entry never widens to allow-all, TLS verification cannot be
disabled, and every denial is audited as host:port only.
"""

import json

import httpx
import pytest

from lliam_gov.security.egress import (
    EGRESS_ALLOWLIST_ENV,
    EGRESS_ENFORCE_ENV,
    EgressDenied,
    EgressTLSViolation,
    check_egress,
    install_egress_guard,
    load_allowlist,
)


@pytest.fixture
def enforced(tmp_path, monkeypatch):
    home = tmp_path / "lliam-home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv(EGRESS_ENFORCE_ENV, "1")
    monkeypatch.delenv(EGRESS_ALLOWLIST_ENV, raising=False)
    return home


# ── allowlist parsing ───────────────────────────────────────────────────────


def test_env_allowlist_parses_hosts_and_ports(monkeypatch):
    monkeypatch.setenv(
        EGRESS_ALLOWLIST_ENV, "api.anthropic.com, slack.com:443, smtp.x.io:587"
    )
    assert load_allowlist() == frozenset(
        {("api.anthropic.com", 443), ("slack.com", 443), ("smtp.x.io", 587)}
    )


def test_file_allowlist_with_comments(enforced, monkeypatch):
    (enforced / "egress-allowlist.txt").write_text(
        "# governed endpoints\napi.anthropic.com\n*.slack.com:443\n"
    )
    assert load_allowlist() == frozenset(
        {("api.anthropic.com", 443), ("*.slack.com", 443)}
    )


# ── policy semantics ────────────────────────────────────────────────────────


def test_enforcement_off_allows_everything(monkeypatch):
    monkeypatch.delenv(EGRESS_ENFORCE_ENV, raising=False)
    check_egress("anywhere.example", 9999)


def test_missing_allowlist_is_deny_all(enforced):
    with pytest.raises(EgressDenied, match="Fail-closed"):
        check_egress("api.anthropic.com", 443)


def test_allowed_host_passes(enforced, monkeypatch):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "api.anthropic.com")
    check_egress("api.anthropic.com", 443)
    check_egress("API.ANTHROPIC.COM", None)  # case + default port


def test_unlisted_host_denied(enforced, monkeypatch):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "api.anthropic.com")
    with pytest.raises(EgressDenied):
        check_egress("exfil.example", 443)


def test_port_mismatch_denied(enforced, monkeypatch):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "api.anthropic.com:443")
    with pytest.raises(EgressDenied):
        check_egress("api.anthropic.com", 80)


def test_wildcard_matches_subdomain_not_bare_suffix(enforced, monkeypatch):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "*.slack.com")
    check_egress("hooks.slack.com", 443)
    with pytest.raises(EgressDenied):
        check_egress("slack.com", 443)  # bare suffix is its own decision
    with pytest.raises(EgressDenied):
        check_egress("notslack.com", 443)


def test_loopback_always_allowed(enforced):
    check_egress("127.0.0.1", 9119)
    check_egress("localhost", 3741)
    check_egress("::1", 8080)


# ── audit on denial ─────────────────────────────────────────────────────────


def test_denial_audited_host_port_only(enforced, monkeypatch):
    with pytest.raises(EgressDenied):
        check_egress("exfil.example", 8443)
    audit_dir = enforced / "audit"
    records = [
        json.loads(line)
        for f in audit_dir.glob("*.jsonl")
        for line in f.read_text().splitlines()
    ]
    denials = [r for r in records if r["event_type"] == "egress_denied"]
    assert denials, "denial must be audited"
    d = denials[-1]
    assert d["blocked"] is True
    assert d["block_reason"] == "exfil.example:8443"
    assert "params" not in d, "raw params never land in the chain (A.8.11)"
    assert "/upload" not in json.dumps(d), "no URL paths in audit records"


# ── httpx guard ─────────────────────────────────────────────────────────────


def test_httpx_send_blocked_for_denied_host(enforced, monkeypatch):
    install_egress_guard()
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "api.anthropic.com")
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as c:
        with pytest.raises(EgressDenied):
            c.get("https://exfil.example/upload")


def test_httpx_send_allows_listed_host(enforced, monkeypatch):
    install_egress_guard()
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "api.anthropic.com")
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as c:
        assert c.get("https://api.anthropic.com/v1/ping").status_code == 200


@pytest.mark.asyncio
async def test_async_httpx_send_blocked(enforced, monkeypatch):
    install_egress_guard()
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "api.anthropic.com")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200))
    ) as c:
        with pytest.raises(EgressDenied):
            await c.get("https://exfil.example/upload")


def test_verify_false_refused_under_enforcement(enforced):
    install_egress_guard()
    with pytest.raises(EgressTLSViolation, match="mandatory"):
        httpx.Client(verify=False)


def test_verify_false_allowed_when_not_enforced(monkeypatch):
    install_egress_guard()
    monkeypatch.delenv(EGRESS_ENFORCE_ENV, raising=False)
    httpx.Client(verify=False).close()  # dev parity preserved
