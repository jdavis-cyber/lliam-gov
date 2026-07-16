"""P2.1 — Tool-risk Policy Decision Point (graduated dispositions).

The PDP (tools/tool_policy.py, additive extension of the P0 enablement gate)
maps every concrete tool call to exactly one of the four graduated
dispositions — allow / detect_log / hitl_approve / deny — by resolving the
call against the action classes in policy/tool-risk-policy.yaml (LG-RM-08,
LG-AZ-01). Deny-by-default + fail-closed under strict posture; complete
no-op on low-side postures (capability preserving).

These tests drive the REAL backends the policy names — agent/file_safety.py
for the write split, tools/approval.py guards for the shell split — with a
hermetic policy file, not mocks.
"""

from __future__ import annotations

import textwrap

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_POLICY_YAML = textwrap.dedent(
    """
    metadata:
      policy_id: "LG-TOOL-RISK-POLICY"
      version: "test"
      default_disposition: deny
      fail_closed: true
    action_classes:
      - {class: file_read, tier: allow}
      - {class: file_write.in_safe_root, tier: detect_log}
      - {class: file_write.outside_safe_root, tier: hitl_approve}
      - {class: file_write.sensitive_path, tier: deny}
      - {class: shell.non_destructive, tier: detect_log}
      - {class: shell.destructive, tier: hitl_approve}
      - {class: shell.hardline, tier: deny}
      - {class: shell.sudo_stdin, tier: deny}
      - {class: computer_use.desktop_control, tier: deny}
    """
)


@pytest.fixture
def strict_pdp(tmp_path, monkeypatch):
    """Strict posture + hermetic policy file + tmp safe-root. Returns tool_policy."""
    policy_file = tmp_path / "tool-risk-policy.yaml"
    policy_file.write_text(_POLICY_YAML, encoding="utf-8")
    safe_root = tmp_path / "workspace"
    safe_root.mkdir()
    monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", str(safe_root))
    cfg = {
        "security": {
            "posture": "strict",
            "tool_risk_policy": {
                "enabled": True,
                "policy_path": str(policy_file),
                "default_disposition": "deny",
                "fail_closed": True,
            },
        }
    }
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import tools.tool_policy as tp

    tp.reset_pdp_state()
    yield tp
    tp.reset_pdp_state()


# ---------------------------------------------------------------------------
# 1. Tier resolution — the four-disposition ladder (LG-RM-08)
# ---------------------------------------------------------------------------

def test_file_read_resolves_to_allow(strict_pdp):
    d = strict_pdp.evaluate_call("read_file", {"path": "notes.md"})
    assert d.disposition == "allow"
    assert d.action_class == "file_read"


def test_write_inside_safe_root_is_detect_log_not_gated(strict_pdp, tmp_path):
    target = tmp_path / "workspace" / "out.txt"
    d = strict_pdp.evaluate_call("write_file", {"path": str(target), "content": "x"})
    assert d.disposition == "detect_log"
    assert d.action_class == "file_write.in_safe_root"
    assert d.allows_execution  # proceeds — anti-approval-fatigue tier


def test_write_outside_safe_root_routes_to_hitl(strict_pdp, tmp_path):
    d = strict_pdp.evaluate_call(
        "write_file", {"path": str(tmp_path / "elsewhere" / "out.txt"), "content": "x"}
    )
    assert d.disposition == "hitl_approve"
    assert d.action_class == "file_write.outside_safe_root"
    assert not d.allows_execution  # gated until an approver rules


def test_write_sensitive_path_is_deny(strict_pdp):
    d = strict_pdp.evaluate_call(
        "write_file", {"path": "~/.ssh/authorized_keys", "content": "k"}
    )
    assert d.disposition == "deny"
    assert d.action_class == "file_write.sensitive_path"
    assert not d.allows_execution


def test_non_destructive_shell_is_detect_log(strict_pdp):
    d = strict_pdp.evaluate_call("terminal", {"command": "ls -la"})
    assert d.disposition == "detect_log"
    assert d.action_class == "shell.non_destructive"
    assert d.allows_execution


def test_destructive_shell_routes_to_hitl(strict_pdp):
    d = strict_pdp.evaluate_call("terminal", {"command": "rm -rf ./build"})
    assert d.disposition == "hitl_approve"
    assert d.action_class == "shell.destructive"
    assert not d.allows_execution


def test_hardline_shell_is_deny(strict_pdp):
    d = strict_pdp.evaluate_call("terminal", {"command": "rm -rf /"})
    assert d.disposition == "deny"
    assert d.action_class == "shell.hardline"
    assert not d.allows_execution


def test_sudo_stdin_is_deny(strict_pdp):
    d = strict_pdp.evaluate_call(
        "terminal", {"command": "echo hunter2 | sudo -S systemctl stop firewalld"}
    )
    assert d.disposition == "deny"
    assert d.action_class == "shell.sudo_stdin"


def test_computer_use_is_deny_in_cui_baseline(strict_pdp):
    d = strict_pdp.evaluate_call("computer_use", {"action": "screenshot"})
    assert d.disposition == "deny"
    assert d.action_class == "computer_use.desktop_control"


# ---------------------------------------------------------------------------
# 2. Deny-by-default + fail-closed + low-side no-op
# ---------------------------------------------------------------------------

def test_unknown_mutating_tool_resolves_to_bounded_mutation_class(strict_pdp):
    # Unknown tools (incl. MCP) classify as bounded mutation — an EXPLICIT
    # policy class, not a silent hole. The hermetic policy here omits the
    # class, so it falls to default_disposition (deny) — the backstop works.
    d = strict_pdp.evaluate_call("mystery_new_tool", {"anything": 1})
    assert d.action_class == "tool_mutation.bounded"
    assert d.disposition == "deny"  # class absent from policy → default deny


def test_memory_write_resolves_to_memory_write_class(strict_pdp):
    d = strict_pdp.evaluate_call("memory", {"action": "write", "content": "x"})
    assert d.action_class == "memory_write"


def test_egress_tool_resolves_to_network_egress_class(strict_pdp):
    d = strict_pdp.evaluate_call("vision_analyze", {"image": "a.png"})
    assert d.action_class == "network.egress"


def test_browser_action_resolves_to_browser_class(strict_pdp):
    d = strict_pdp.evaluate_call("browser_navigate", {"url": "https://x.test"})
    assert d.action_class == "browser.unlisted_or_action"


def test_repo_policy_of_record_covers_every_resolvable_class(strict_pdp):
    """LG-RM-03 coverage reconciliation: every class the PDP can produce has
    an explicit tier in policy/tool-risk-policy.yaml — no unmapped classes."""
    import yaml
    from pathlib import Path

    repo_policy = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "policy" / "tool-risk-policy.yaml")
        .read_text(encoding="utf-8")
    )
    covered = {
        str(e.get("class")).strip()
        for e in repo_policy.get("action_classes") or []
        if isinstance(e, dict)
    }
    resolvable = {
        "file_read",
        "file_write.in_safe_root", "file_write.outside_safe_root",
        "file_write.sensitive_path",
        "shell.non_destructive", "shell.destructive",
        "shell.hardline", "shell.sudo_stdin",
        "computer_use.desktop_control",
        "browser.unlisted_or_action",
        "memory_write", "skill_write",
        "network.egress", "delegation", "tool_mutation.bounded",
    }
    missing = resolvable - covered
    assert not missing, f"policy of record missing classes: {sorted(missing)}"


def test_policy_parse_error_fails_closed_to_deny(strict_pdp, tmp_path):
    (tmp_path / "tool-risk-policy.yaml").write_text(
        "metadata: [broken", encoding="utf-8"
    )
    strict_pdp.reset_pdp_state()
    d = strict_pdp.evaluate_call("read_file", {"path": "notes.md"})
    assert d.disposition == "deny"
    assert "fail" in d.reason.lower() or "policy" in d.reason.lower()


# ---------------------------------------------------------------------------
# 3. Privileged-function force-up (LG-AZ-06)
# ---------------------------------------------------------------------------

_PRIVILEGED_POLICY = _POLICY_YAML + textwrap.dedent(
    """
    privileged_functions:
      members: [shell.non_destructive]
      force_disposition: hitl_approve
    """
)


def test_privileged_member_never_resolves_below_hitl(strict_pdp, tmp_path):
    (tmp_path / "tool-risk-policy.yaml").write_text(
        _PRIVILEGED_POLICY, encoding="utf-8"
    )
    strict_pdp.reset_pdp_state()
    d = strict_pdp.evaluate_call("terminal", {"command": "ls -la"})
    assert d.disposition == "hitl_approve"  # forced up from detect_log
    assert d.action_class == "shell.non_destructive"
    assert "privileged" in d.reason.lower()


# ---------------------------------------------------------------------------
# 4. Zero-standing-privilege / JIT grants (LG-AZ-07)
# ---------------------------------------------------------------------------

_JIT_POLICY = _POLICY_YAML + textwrap.dedent(
    """
    zero_standing_privilege:
      enabled: true
      default_off_capabilities: [shell.destructive]
      grant:
        ttl_seconds: 1800
    """
)


def _use_jit_policy(strict_pdp, tmp_path):
    (tmp_path / "tool-risk-policy.yaml").write_text(_JIT_POLICY, encoding="utf-8")
    strict_pdp.reset_pdp_state()


def test_default_off_capability_requires_grant(strict_pdp, tmp_path):
    _use_jit_policy(strict_pdp, tmp_path)
    d = strict_pdp.evaluate_call("terminal", {"command": "rm -rf ./build"})
    assert d.disposition == "hitl_approve"
    assert not d.allows_execution


def test_active_grant_lets_capability_proceed_with_ledger_record(strict_pdp, tmp_path):
    _use_jit_policy(strict_pdp, tmp_path)
    strict_pdp.grant_capability("shell.destructive", approver="jerome@dashboard")
    d = strict_pdp.evaluate_call("terminal", {"command": "rm -rf ./build"})
    assert d.disposition == "detect_log"  # approved → proceed + full record
    assert d.allows_execution
    assert "grant" in d.reason.lower()


def test_jit_grant_is_scoped_to_runtime_session(strict_pdp, tmp_path):
    _use_jit_policy(strict_pdp, tmp_path)
    strict_pdp.grant_capability(
        "shell.destructive", approver="jerome@dashboard", session_id="session-a"
    )
    assert strict_pdp.evaluate_call(
        "terminal", {"command": "rm -rf ./build"}, session_id="session-a"
    ).allows_execution
    assert strict_pdp.evaluate_call(
        "terminal", {"command": "rm -rf ./build"}, session_id="session-b"
    ).disposition == "hitl_approve"


def test_expired_grant_forces_reapproval(strict_pdp, tmp_path):
    _use_jit_policy(strict_pdp, tmp_path)
    strict_pdp.grant_capability(
        "shell.destructive", approver="jerome@dashboard", ttl_seconds=0
    )
    d = strict_pdp.evaluate_call("terminal", {"command": "rm -rf ./build"})
    assert d.disposition == "hitl_approve"  # grant expired → re-approval


def test_grant_never_reenables_a_deny_class(strict_pdp, tmp_path):
    _use_jit_policy(strict_pdp, tmp_path)
    strict_pdp.grant_capability("shell.hardline", approver="jerome@dashboard")
    d = strict_pdp.evaluate_call("terminal", {"command": "rm -rf /"})
    assert d.disposition == "deny"  # deny is terminal (LG-HO-03)


# ---------------------------------------------------------------------------
# 5. Mutating-call budgets + runaway caps (LG-AZ-10 / LG-AZ-12)
# ---------------------------------------------------------------------------

_BUDGET_POLICY = _POLICY_YAML + textwrap.dedent(
    """
    budgets:
      max_mutating_calls:
        per_turn: 3
        per_session: 5
        on_exceed: hitl_approve
        counts_only_mutating: true
    """
)


def _use_budget_policy(strict_pdp, tmp_path):
    (tmp_path / "tool-risk-policy.yaml").write_text(_BUDGET_POLICY, encoding="utf-8")
    strict_pdp.reset_pdp_state()


def _write_in_root(strict_pdp, tmp_path, i):
    return strict_pdp.evaluate_call(
        "write_file", {"path": str(tmp_path / "workspace" / f"f{i}.txt"), "content": "x"}
    )


def test_per_turn_budget_exceeded_routes_to_hitl(strict_pdp, tmp_path):
    _use_budget_policy(strict_pdp, tmp_path)
    for i in range(3):
        assert _write_in_root(strict_pdp, tmp_path, i).allows_execution
    d = _write_in_root(strict_pdp, tmp_path, 99)
    assert d.disposition == "hitl_approve"  # runaway throttle, not a hard halt
    assert "budget" in d.reason.lower()


def test_reads_do_not_consume_budget(strict_pdp, tmp_path):
    _use_budget_policy(strict_pdp, tmp_path)
    for _ in range(10):
        assert strict_pdp.evaluate_call("read_file", {"path": "n.md"}).allows_execution
    assert _write_in_root(strict_pdp, tmp_path, 0).allows_execution


def test_new_turn_resets_per_turn_budget_but_session_cap_holds(strict_pdp, tmp_path):
    _use_budget_policy(strict_pdp, tmp_path)
    for i in range(3):
        assert _write_in_root(strict_pdp, tmp_path, i).allows_execution
    strict_pdp.pdp_begin_turn()
    for i in range(3, 5):  # session total reaches 5
        assert _write_in_root(strict_pdp, tmp_path, i).allows_execution
    d = _write_in_root(strict_pdp, tmp_path, 99)
    assert d.disposition == "hitl_approve"  # per-session cap (LG-AZ-12)
    assert "session" in d.reason.lower()


def test_mutation_budgets_are_scoped_to_runtime_session(strict_pdp, tmp_path):
    _use_budget_policy(strict_pdp, tmp_path)
    for i in range(3):
        assert strict_pdp.evaluate_call(
            "write_file",
            {"path": str(tmp_path / "workspace" / f"a{i}.txt"), "content": "x"},
            session_id="session-a",
        ).allows_execution
    assert strict_pdp.evaluate_call(
        "write_file",
        {"path": str(tmp_path / "workspace" / "b.txt"), "content": "x"},
        session_id="session-b",
    ).allows_execution


# ---------------------------------------------------------------------------
# 7. pdp_gate — enforcement at the dispatch chokepoint (LG-AZ-01)
# ---------------------------------------------------------------------------

def test_pdp_gate_blocks_deny_fail_closed(strict_pdp):
    decision = strict_pdp.pdp_gate("terminal", {"command": "rm -rf /"})
    assert decision is not None and decision.should_halt
    assert decision.code == "pdp_deny"


def test_pdp_gate_passes_ungated_tiers(strict_pdp, tmp_path):
    assert strict_pdp.pdp_gate("read_file", {"path": "n.md"}) is None
    assert strict_pdp.pdp_gate(
        "write_file", {"path": str(tmp_path / "workspace" / "o.txt"), "content": "x"}
    ) is None


def test_pdp_gate_blocks_hitl_pending_approval(strict_pdp, tmp_path):
    decision = strict_pdp.pdp_gate(
        "write_file", {"path": str(tmp_path / "elsewhere" / "o.txt"), "content": "x"}
    )
    assert decision is not None and decision.should_halt
    assert decision.code == "pdp_approval_required"  # deny_on_no_approver (LG-HO-06)


def test_pdp_gate_delegates_marked_hitl_class_to_backend_gate(strict_pdp, tmp_path):
    delegated = _POLICY_YAML.replace(
        "- {class: shell.destructive, tier: hitl_approve}",
        "- {class: shell.destructive, tier: hitl_approve, hitl_delegated_to_backend: true}",
    )
    (tmp_path / "tool-risk-policy.yaml").write_text(delegated, encoding="utf-8")
    strict_pdp.reset_pdp_state()
    # The EXISTING tools/approval.py flow is the HITL gate for shell — the PDP
    # must not double-block it (capability preservation).
    assert strict_pdp.pdp_gate("terminal", {"command": "rm -rf ./build"}) is None


def test_pdp_gate_low_side_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    import tools.tool_policy as tp

    tp.reset_pdp_state()
    assert tp.pdp_gate("terminal", {"command": "rm -rf /"}) is None
    tp.reset_pdp_state()


def test_pdp_gate_emits_policy_violation_to_ledger(strict_pdp, tmp_path, monkeypatch):
    import agent.governance_audit_hooks as gah
    from agent.governance_audit import GovernanceLedger, iter_records

    led = GovernanceLedger(tmp_path / "agent-audit.log")
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: led)
    strict_pdp.pdp_gate("terminal", {"command": "rm -rf /"})
    records = list(iter_records(led.path))
    assert any(r["event"] == "policy.violation" for r in records)


# ---------------------------------------------------------------------------
# 8. Chokepoint wiring — funnel + executor (LG-AZ-01, exactly-once)
# ---------------------------------------------------------------------------

def test_funnel_blocks_pdp_denied_call_before_dispatch(strict_pdp, monkeypatch):
    import json

    import model_tools
    from tools.registry import registry

    dispatched = []
    monkeypatch.setattr(
        registry, "dispatch",
        lambda name, args, **kw: dispatched.append(name) or '{"output": "ok"}',
    )
    monkeypatch.setattr(model_tools, "_READ_SEARCH_TOOLS", frozenset())
    result = model_tools.handle_function_call(
        "computer_use", {"action": "screenshot"}, task_id="t1",
        skip_pre_tool_call_hook=True,
    )
    assert dispatched == []  # blocked BEFORE execution
    assert "error" in json.loads(result)


def test_funnel_skips_pdp_when_executor_already_gated(strict_pdp, monkeypatch):
    import model_tools
    from tools.registry import registry

    dispatched = []
    monkeypatch.setattr(
        registry, "dispatch",
        lambda name, args, **kw: dispatched.append(name) or '{"output": "ok"}',
    )
    monkeypatch.setattr(model_tools, "_READ_SEARCH_TOOLS", frozenset())
    model_tools.handle_function_call(
        "computer_use", {"action": "screenshot"}, task_id="t1",
        skip_governance_predispatch=True, skip_pre_tool_call_hook=True,
    )
    assert dispatched == ["computer_use"]  # executor-gated path not re-gated


def test_executor_seams_invoke_pdp_gate_and_turn_reset():
    import inspect

    import agent.tool_executor as tx

    src = inspect.getsource(tx)
    assert src.count("pdp_gate(") >= 2       # both dispatch sites gated
    assert src.count("pdp_begin_turn(") >= 2  # per-turn budget reset (LG-AZ-10)


# ---------------------------------------------------------------------------
# 9. Low-side no-op
# ---------------------------------------------------------------------------

def test_low_side_posture_is_complete_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    import tools.tool_policy as tp

    tp.reset_pdp_state()
    d = tp.evaluate_call("terminal", {"command": "rm -rf ./build"})
    assert d.disposition == "allow"
    assert d.allows_execution
    tp.reset_pdp_state()
