"""P2.2 — Human-in-the-loop oversight gates (LG-HO-01..10).

The oversight layer binds the PDP's hitl_approve verdicts to REAL approval
outcomes: under strict posture the legacy non-interactive auto-approve branch
fails closed (LG-HO-02 — the R6 gap), every approval/denial/override lands in
the hash-chained ledger with the approver identity (LG-HO-10), JIT grants are
approval-backed (LG-HO-05), prompts carry risk rationale (LG-HO-08) and are
fatigue-tracked (LG-HO-07), and an explicit operator override channel exists
(LG-HO-09). Low/medium tiers stay ungated; hardline/sudo-stdin stay
unconditional (LG-HO-03).
"""

from __future__ import annotations

import textwrap

import pytest


_STRICT = {"security": {"posture": "strict", "deny_on_no_approver": True}}


@pytest.fixture
def clean_env(monkeypatch):
    for var in (
        "HERMES_INTERACTIVE", "LLIAM_INTERACTIVE",
        "HERMES_GATEWAY_SESSION", "LLIAM_GATEWAY_SESSION",
        "HERMES_CRON_SESSION", "LLIAM_CRON_SESSION",
        "HERMES_EXEC_ASK", "LLIAM_EXEC_ASK",
        "SUDO_PASSWORD",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def strict_cfg(monkeypatch, clean_env):
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: _STRICT)


@pytest.fixture
def gov_ledger(tmp_path, monkeypatch):
    import agent.governance_audit_hooks as gah
    from agent.governance_audit import GovernanceLedger

    led = GovernanceLedger(tmp_path / "agent-audit.log")
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: led)
    return led


def _records(led):
    from agent.governance_audit import iter_records
    return list(iter_records(led.path))


# ---------------------------------------------------------------------------
# 1. LG-HO-02 — non-interactive auto-approve becomes fail-closed deny
# ---------------------------------------------------------------------------

def test_strict_non_interactive_dangerous_command_is_denied(strict_cfg):
    from tools.approval import check_dangerous_command, clear_session

    clear_session("t-ho02")
    result = check_dangerous_command("rm -rf ./build", "local")
    assert result["approved"] is False
    assert "fail-closed" in (result.get("message") or "").lower()


def test_terminal_dispatch_guard_denies_strict_noninteractive_command(strict_cfg):
    from tools.approval import check_all_command_guards

    result = check_all_command_guards("rm -rf ./build", "local")
    assert result["approved"] is False
    assert "fail-closed" in (result.get("message") or "").lower()


def test_low_side_non_interactive_refuses_without_approver(clean_env, monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    from tools.approval import check_dangerous_command

    result = check_dangerous_command("rm -rf ./build", "local")
    # AI-1172: low side no longer auto-approves; it refuses with its own
    # message (strict keeps the LG-HO-02 fail-closed wording).
    assert result["approved"] is False
    assert "desktop app" in (result.get("message") or "")


def test_strict_cron_dangerous_command_denied_even_in_approve_mode(strict_cfg, monkeypatch):
    monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    from tools.approval import check_dangerous_command

    monkeypatch.setattr("tools.approval._get_cron_approval_mode", lambda: "approve")
    result = check_dangerous_command("rm -rf ./build", "local")
    assert result["approved"] is False  # strict floor beats cron approve mode


# ---------------------------------------------------------------------------
# 2. LG-HO-03 — hardline/sudo-stdin unconditional (above any approval state)
# ---------------------------------------------------------------------------

def test_sudo_stdin_blocked_even_in_interactive_session(strict_cfg, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    from tools.approval import _check_sudo_stdin_guard

    blocked, _ = _check_sudo_stdin_guard("echo pw | sudo -S rm x")
    assert blocked is True


# ---------------------------------------------------------------------------
# 3. LG-HO-10 — every approval/denial recorded with identity
# ---------------------------------------------------------------------------

def test_ho02_denial_emits_approval_decision_record(strict_cfg, gov_ledger):
    from tools.approval import check_dangerous_command, clear_session

    clear_session("t-ho10")
    check_dangerous_command("rm -rf ./build", "local")
    recs = [r for r in _records(gov_ledger) if r["event"] == "approval.decision"]
    assert recs and recs[-1]["decision"] == "deny"
    assert "LG-HO-02" in str(recs[-1].get("outcome", {}))


def test_jit_grant_emits_approval_decision_with_approver(strict_cfg, gov_ledger, tmp_path, monkeypatch):
    policy = tmp_path / "tool-risk-policy.yaml"
    policy.write_text(textwrap.dedent(
        """
        metadata: {default_disposition: deny, fail_closed: true}
        action_classes:
          - {class: shell.destructive, tier: hitl_approve}
        zero_standing_privilege:
          enabled: true
          default_off_capabilities: [shell.destructive]
        """
    ), encoding="utf-8")
    cfg = {"security": {"posture": "strict", "tool_risk_policy": {
        "enabled": True, "policy_path": str(policy),
        "default_disposition": "deny", "fail_closed": True}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import tools.tool_policy as tp

    tp.reset_pdp_state()
    tp.grant_capability("shell.destructive", approver="jerome@dashboard")
    recs = [r for r in _records(gov_ledger) if r["event"] == "approval.decision"]
    assert recs and recs[-1]["decision"] == "approve"
    assert "jerome@dashboard" in str(recs[-1].get("approver", {}))
    tp.reset_pdp_state()


# ---------------------------------------------------------------------------
# 4. LG-HO-08 — JIT risk rationale at the decision point
# ---------------------------------------------------------------------------

def test_ho02_denial_message_carries_risk_rationale(strict_cfg):
    from tools.approval import check_dangerous_command, clear_session

    clear_session("t-ho08")
    result = check_dangerous_command("rm -rf ./build", "local")
    msg = result.get("message") or ""
    assert "recursive delete" in msg.lower() or "dangerous" in msg.lower()
    assert "approv" in msg.lower()   # tells the operator HOW to approve


# ---------------------------------------------------------------------------
# 5. LG-HO-07 — approval-prompt fatigue tracking
# ---------------------------------------------------------------------------

def test_prompt_fatigue_counter_flags_over_threshold(strict_cfg):
    from tools import hitl_oversight as ho

    ho.reset_fatigue_state()
    for _ in range(ho.FATIGUE_PROMPT_THRESHOLD):
        assert ho.note_approval_prompt("sess-f") is False  # under threshold
    assert ho.note_approval_prompt("sess-f") is True       # flagged (logged, never auto-approves)
    ho.reset_fatigue_state()


# ---------------------------------------------------------------------------
# 6. LG-HO-09 — operator override/appeal channel (recorded)
# ---------------------------------------------------------------------------

def test_operator_override_records_and_grants(strict_cfg, gov_ledger, tmp_path, monkeypatch):
    policy = tmp_path / "tool-risk-policy.yaml"
    policy.write_text(textwrap.dedent(
        """
        metadata: {default_disposition: deny, fail_closed: true}
        action_classes:
          - {class: shell.destructive, tier: hitl_approve}
        zero_standing_privilege:
          enabled: true
          default_off_capabilities: [shell.destructive]
        """
    ), encoding="utf-8")
    cfg = {"security": {"posture": "strict", "tool_risk_policy": {
        "enabled": True, "policy_path": str(policy),
        "default_disposition": "deny", "fail_closed": True}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import tools.tool_policy as tp
    from tools import hitl_oversight as ho

    tp.reset_pdp_state()
    ho.operator_override(
        "shell.destructive", approver="jerome@dashboard",
        justification="mission-required cleanup of build artifacts",
    )
    # Override is an approval-backed grant: the capability now proceeds.
    d = tp.evaluate_call("terminal", {"command": "rm -rf ./build"})
    assert d.allows_execution
    recs = [r for r in _records(gov_ledger) if r["event"] == "approval.decision"]
    assert any("override" in str(r.get("outcome", {})).lower() for r in recs)
    tp.reset_pdp_state()


def test_operator_override_never_reenables_deny(strict_cfg, gov_ledger):
    from tools import hitl_oversight as ho

    with pytest.raises(ValueError):
        ho.operator_override(
            "shell.hardline", approver="jerome@dashboard", justification="x",
        )
