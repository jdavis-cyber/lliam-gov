"""P2.V — Phase 2 capability-preservation corpus (the verify gate, AI-487).

Drives the §6 standing task corpus under the STRICT overlay and asserts the
Phase 2 acceptance boundary: low/medium actions stay ungated (no approval
fatigue), high-risk completes WITH an approver and is denied WITHOUT one, and
the ONLY new blocks are (a) CUI-tainted egress to non-allowlisted sinks,
(b) hardline/sudo-stdin, (c) high-risk with no approver.

This is an empirical capability check across the P2.1–P2.6 surfaces composed
together — not a re-test of each unit. It fails if the hardening crippled a
permitted capability.
"""

from __future__ import annotations

import datetime
import textwrap

import pytest


_POLICY = textwrap.dedent(
    """
    metadata: {default_disposition: deny, fail_closed: true}
    action_classes:
      - {class: file_read, tier: allow}
      - {class: file_write.in_safe_root, tier: detect_log}
      - {class: file_write.outside_safe_root, tier: hitl_approve}
      - {class: file_write.sensitive_path, tier: deny}
      - {class: shell.non_destructive, tier: detect_log}
      - {class: shell.destructive, tier: hitl_approve}
      - {class: shell.hardline, tier: deny}
      - {class: shell.sudo_stdin, tier: deny}
      - {class: provider_call.allowlisted, tier: allow}
      - {class: network.egress, tier: detect_log}
      - {class: tool_mutation.bounded, tier: detect_log}
    zero_standing_privilege:
      enabled: true
      default_off_capabilities: [shell.destructive]
    """
)


@pytest.fixture
def strict_overlay(tmp_path, monkeypatch):
    policy = tmp_path / "tool-risk-policy.yaml"
    policy.write_text(_POLICY, encoding="utf-8")
    egress = tmp_path / "egress-allowlist.yaml"
    egress.write_text(textwrap.dedent(
        """
        metadata: {default_disposition: deny}
        approved_destinations:
          - {host: "api.github.com", surfaces: [web, mcp], expires: "2026-12-31"}
        """
    ), encoding="utf-8")
    safe_root = tmp_path / "ws"
    safe_root.mkdir()
    monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", str(safe_root))
    cfg = {"security": {
        "posture": "strict", "deny_on_no_approver": True,
        "tool_risk_policy": {"enabled": True, "policy_path": str(policy),
                             "default_disposition": "deny", "fail_closed": True},
        "egress": {"mode": "allowlist", "policy_path": str(egress),
                   "new_domain_disposition": "deny", "fail_closed": True},
    }}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import agent.data_protection as dp
    import tools.egress_policy as ep
    import tools.injection_defense as idf
    import tools.tool_policy as tp

    monkeypatch.setattr(ep, "_today", lambda: datetime.date(2026, 7, 1))

    for m in (tp, idf, dp, ep):
        getattr(m, "reset_pdp_state", getattr(m, "reset_injection_state",
                getattr(m, "reset_dp_state", getattr(m, "reset_egress_cache", lambda: None))))()
    tp.reset_pdp_state(); idf.reset_injection_state(); dp.reset_dp_state(); ep.reset_egress_cache()
    yield tp, ep, safe_root
    tp.reset_pdp_state(); idf.reset_injection_state(); dp.reset_dp_state(); ep.reset_egress_cache()


# --- Corpus 1: multi-file code change within the safe root ------------------

def test_corpus_safe_root_coding_unblocked(strict_overlay):
    tp, _ep, safe_root = strict_overlay
    assert tp.evaluate_call("read_file", {"path": "src/x.py"}).allows_execution
    assert tp.evaluate_call(
        "write_file", {"path": str(safe_root / "x.py"), "content": "print(1)"}
    ).allows_execution
    assert tp.evaluate_call("terminal", {"command": "pytest -q"}).allows_execution


# --- Corpus 2: CUI-marked analysis, markings preserved, no auto-leak --------

def test_corpus_cui_analysis_preserved_no_leak(strict_overlay):
    import agent.data_protection as dp

    c = dp.classify_content("CUI\nContract data.\nCUI")
    assert c.level == "cui" and "CUI" in c.markings
    # Reading/analyzing CUI is fine; it just arms the DLP egress gate.
    dp.note_cui_exposure("read_file", "CUI\nContract data.\nCUI")
    tp, _ep, _sr = strict_overlay
    assert tp.evaluate_call("read_file", {"path": "cui.md"}).allows_execution


# --- Corpus 3: authorized-provider inference call (hot path) ----------------

def test_corpus_allowlisted_provider_call_unblocked(strict_overlay):
    tp, _ep, _sr = strict_overlay
    # provider_call.allowlisted is an allow-tier hot path — never gated.
    from tools.tool_policy import _class_tiers, _load_risk_policy
    assert _class_tiers(_load_risk_policy()).get("provider_call.allowlisted") == "allow"


# --- Corpus 4: authorized-domain web fetch + allowlisted MCP ----------------

def test_corpus_allowlisted_egress_succeeds(strict_overlay):
    _tp, ep, _sr = strict_overlay
    assert ep.check_egress("https://api.github.com/repos/x", surface="web").disposition == "allow"


def test_corpus_non_allowlisted_egress_denied(strict_overlay):
    _tp, ep, _sr = strict_overlay
    assert ep.check_egress("https://pastebin.test/raw", surface="web").disposition == "deny"


# --- Corpus 5: high-risk action with / without approver ---------------------

def test_corpus_high_risk_denied_without_approver(strict_overlay):
    tp, _ep, _sr = strict_overlay
    d = tp.evaluate_call("terminal", {"command": "rm -rf ./build"})
    assert not d.allows_execution   # deny_on_no_approver for the High tier


def test_corpus_high_risk_proceeds_with_grant(strict_overlay):
    tp, _ep, _sr = strict_overlay
    tp.grant_capability("shell.destructive", approver="jerome@dashboard")
    d = tp.evaluate_call("terminal", {"command": "rm -rf ./build"})
    assert d.allows_execution       # approver present → proceeds + recorded


# --- The acceptance boundary: ONLY these three classes newly block ----------

def test_acceptance_boundary_only_expected_new_blocks(strict_overlay):
    tp, ep, _sr = strict_overlay
    import agent.data_protection as dp

    # (a) CUI-tainted egress to a non-allowlisted sink.
    dp.note_cui_exposure("read_file", "CUI\nx\nCUI")
    assert tp.evaluate_call("vision_analyze", {"image": "x"}).disposition == "hitl_approve"
    dp.reset_dp_state()

    # (b) hardline / sudo-stdin — unconditional deny.
    assert tp.evaluate_call("terminal", {"command": "rm -rf /"}).disposition == "deny"
    assert tp.evaluate_call(
        "terminal", {"command": "echo p | sudo -S rm x"}
    ).disposition == "deny"

    # (c) high-risk with no approver — denied (deny_on_no_approver, High only).
    assert not tp.evaluate_call("terminal", {"command": "rm -rf ./build"}).allows_execution

    # NOT blocked: low/medium stay ungated (no approval fatigue).
    assert tp.evaluate_call("read_file", {"path": "x"}).allows_execution
    assert tp.evaluate_call("terminal", {"command": "ls -la"}).allows_execution
