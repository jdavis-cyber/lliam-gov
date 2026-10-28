"""P3.V — Phase 3 capability-preservation corpus (the verify gate, AI-492).

Asserts the Phase 3 acceptance boundary: an authorized in-boundary provider
routes on EVERY path; an approved attested skill + an allowlisted least-privilege
MCP server still load; and the ONLY new blocks are (a) non-allowlisted
provider/base_url, (b) unsigned/unreviewed skill, (c) unsafe-serialization
(code-executing model formats) load. Composes the P3.1–P3.4 authorities.
"""

from __future__ import annotations

import textwrap

import pytest

_PATHS = ["primary", "fallback", "moa", "auxiliary", "delegation"]


@pytest.fixture
def p3_overlay(tmp_path, monkeypatch):
    prov = tmp_path / "provider-allowlist.yaml"
    prov.write_text(textwrap.dedent("""
        metadata: {default_disposition: deny}
        enforcement:
          paths: {primary: {enforce: true}, fallback: {enforce: true},
                  moa: {enforce: true}, auxiliary: {enforce: true},
                  delegation: {enforce: true}}
          require_for_cui: {data_residency: us, no_train: true, tls_required: true}
        providers:
          - {id: lmstudio, provider_class: local, base_url_hosts: ["127.0.0.1"],
             data_residency: local, no_train: true, cui_eligible: true}
          - {id: bedrock, provider_class: gov-cloud,
             base_url_hosts: ["bedrock-runtime.us-gov-west-1.amazonaws.com"],
             data_residency: us, no_train: true, cui_eligible: true}
    """), encoding="utf-8")
    mcp = tmp_path / "mcp-allowlist.yaml"
    mcp.write_text(textwrap.dedent("""
        policy: {default_action: deny, require_explicit_include: true, default_deny_write: true}
        approved_servers:
          - {name: gov-filesystem, transport: stdio, command: uvx,
             scope: {allow_write: false, include: [read_file], write_tools: []}}
    """), encoding="utf-8")
    cards = tmp_path / "model-cards.yaml"
    cards.write_text(textwrap.dedent("""
        models:
          - {id: "lmstudio/llama-3.1-8b-instruct", cui_eligible: true}
    """), encoding="utf-8")
    cfg = {"security": {
        "posture": "strict",
        "provider_allowlist_enforce": True, "provider_allowlist_path": str(prov),
        "mcp_allowlist_enforce": True, "mcp_allowlist_path": str(mcp),
        "require_signed_skills": True,
        "require_model_card": True, "model_cards_path": str(cards),
        "safe_serialization_only": True,
    }}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import agent.attestation as att
    import lliam_cli.provider_allowlist as pa
    import tools.mcp_allowlist as ma
    pa.reset_provider_allowlist_cache(); ma.reset_mcp_allowlist_cache(); att.reset_attestation_cache()
    yield pa, ma, att
    pa.reset_provider_allowlist_cache(); ma.reset_mcp_allowlist_cache(); att.reset_attestation_cache()


# --- Capability: in-boundary provider routes on EVERY path ------------------

@pytest.mark.parametrize("path", _PATHS)
def test_local_provider_routes_on_every_path(p3_overlay, path):
    pa, _ma, _att = p3_overlay
    assert pa.validate_provider("lmstudio", "http://127.0.0.1:1234/v1",
                                path=path, cui=True).disposition == "allow"


@pytest.mark.parametrize("path", _PATHS)
def test_govcloud_provider_routes_on_every_path(p3_overlay, path):
    pa, _ma, _att = p3_overlay
    assert pa.validate_provider(
        "bedrock", "https://bedrock-runtime.us-gov-west-1.amazonaws.com",
        path=path, cui=False).disposition == "allow"


# --- Capability: approved MCP + carded model still load ---------------------

def test_allowlisted_mcp_server_loads(p3_overlay):
    _pa, ma, _att = p3_overlay
    d = ma.check_mcp_server("gov-filesystem", {
        "transport": "stdio", "command": "uvx", "tools": {"include": ["read_file"]}})
    assert d.allowed is True


def test_carded_model_cui_eligible(p3_overlay):
    _pa, _ma, att = p3_overlay
    assert att.model_cui_eligible("lmstudio/llama-3.1-8b-instruct") is True


# --- Acceptance boundary: ONLY the three expected new blocks ----------------

def test_non_allowlisted_provider_blocked(p3_overlay):
    pa, _ma, _att = p3_overlay
    assert pa.validate_provider("openrouter", "https://openrouter.ai",
                                path="primary", cui=True).disposition == "deny"


def test_unvetted_skill_blocked(p3_overlay, tmp_path):
    _pa, ma, _att = p3_overlay
    sd = tmp_path / "skills" / "rogue"
    sd.mkdir(parents=True)
    (sd / "SKILL.md").write_text("---\nname: rogue\n---\n", encoding="utf-8")
    assert ma.skill_attestation_ok("rogue", sd).allowed is False


def test_unsafe_serialization_blocked(p3_overlay):
    _pa, _ma, att = p3_overlay
    assert att.check_serialization("weights.bin").allowed is False


def test_safe_serialization_allowed(p3_overlay):
    _pa, _ma, att = p3_overlay
    assert att.check_serialization("weights.safetensors").allowed is True
