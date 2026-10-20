"""JER-75 — provider egress allowlist and provider allowlist cannot drift.

The provider allowlist (policy/provider-allowlist.yaml, mirrored by
security.allowed_providers in cli-config.gov.yaml) is the policy of record for
which inference endpoints may receive data. The provider-surface entries of
policy/egress-allowlist.yaml, and the squid dstdomain ACL that mirrors that
file, must name exactly the remote hosts of those providers — no more (an
egress entry would otherwise authorize a provider the allowlist rejects, as
api.anthropic.com did) and no less.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _load(rel: str):
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


def _egress_entries():
    return [e for e in _load("policy/egress-allowlist.yaml").get("approved_destinations") or []
            if isinstance(e, dict)]


def _provider_egress_hosts() -> set[str]:
    return {str(e["host"]).strip().lower() for e in _egress_entries()
            if "provider" in (e.get("surfaces") or [])}


def _providers():
    return _load("policy/provider-allowlist.yaml").get("providers") or []


def _remote_provider_hosts() -> dict[str, str]:
    """Remote (non-loopback) base_url host -> provider id."""
    hosts: dict[str, str] = {}
    for p in _providers():
        for h in p.get("base_url_hosts") or []:
            h = str(h).strip().lower()
            if h not in LOCAL_HOSTS:
                hosts[h] = p["id"]
    return hosts


def _squid_dstdomains() -> set[str]:
    text = (ROOT / "deploy/config/squid-allowlist.conf").read_text(encoding="utf-8")
    out = set()
    for line in text.splitlines():
        parts = line.split()
        if parts[:3] == ["acl", "allowed_dstdomains", "dstdomain"]:
            out.update(p.lower() for p in parts[3:])
    return out


def test_allowed_providers_mirror_provider_allowlist():
    cfg = _load("cli-config.gov.yaml")
    allowed = set(cfg["security"]["allowed_providers"])
    assert allowed == {p["id"] for p in _providers()}


def test_provider_egress_entries_are_exact_hosts():
    """Wildcards/parent domains would let one entry authorize hosts the
    provider allowlist never named (e.g. every *.amazonaws.com)."""
    for host in _provider_egress_hosts():
        assert "*" not in host and not host.startswith("."), host
        assert host.count(".") >= 2, f"{host} is too broad for a provider entry"


def test_every_provider_egress_host_belongs_to_an_allowlisted_provider():
    allowed = set(_load("cli-config.gov.yaml")["security"]["allowed_providers"])
    remote = _remote_provider_hosts()
    for host in _provider_egress_hosts():
        assert host in remote, (
            f"egress-allowlist authorizes provider host {host!r} that no "
            "provider-allowlist entry lists"
        )
        assert remote[host] in allowed, f"{host!r} belongs to non-allowed provider {remote[host]!r}"


def test_every_allowlisted_remote_provider_host_has_an_egress_entry():
    missing = set(_remote_provider_hosts()) - _provider_egress_hosts()
    assert not missing, f"provider-allowlist hosts with no provider egress entry: {sorted(missing)}"


def test_squid_acl_mirrors_egress_allowlist():
    declared = {str(e.get("squid_dstdomain") or "").strip().lower() for e in _egress_entries()}
    declared.discard("")
    assert _squid_dstdomains() == declared


def test_anthropic_commercial_api_cannot_authorize_provider_egress():
    assert "api.anthropic.com" not in _provider_egress_hosts()
    assert "api.anthropic.com" not in _squid_dstdomains()
