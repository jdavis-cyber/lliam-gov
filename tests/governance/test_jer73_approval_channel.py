"""JER-73 — the HITL approval channel requires an authenticated approver.

``security.require_authenticated_approver: true`` (cli-config.gov.yaml) must
be enforced, not just declared:

  * an approval resolved with no authenticated dashboard_auth principal bound
    is REFUSED (gateway queue, CLI/ACP prompt, smart-approval LLM, MCP bridge,
    JIT grants / operator override) and the refusal is recorded;
  * the same approval with an authenticated principal bound is ACCEPTED and
    the ``approval.decision`` record names that principal;
  * denials are never refused;
  * the MCP ``permissions_respond`` tool is withheld under strict posture;
  * low-side configs (key unset) behave exactly as before;
  * the control-effectiveness CI gate fails when either invariant regresses.
"""

from __future__ import annotations

import sys
import textwrap
import threading
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import control_effectiveness as ce  # noqa: E402

_GOV = {
    "security": {
        "posture": "strict",
        "deny_on_no_approver": True,
        "require_authenticated_approver": True,
    }
}
_LOW = {"security": {}}


@pytest.fixture
def clean_env(monkeypatch):
    for var in (
        "HERMES_INTERACTIVE", "LLIAM_INTERACTIVE",
        "HERMES_GATEWAY_SESSION", "LLIAM_GATEWAY_SESSION",
        "HERMES_CRON_SESSION", "LLIAM_CRON_SESSION",
        "HERMES_EXEC_ASK", "LLIAM_EXEC_ASK",
        "HERMES_YOLO_MODE", "LLIAM_YOLO_MODE",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _no_subject():
    import agent.governance_audit_hooks as gah

    gah.set_operator_subject(None)
    yield
    gah.set_operator_subject(None)


@pytest.fixture
def gov_cfg(monkeypatch, clean_env):
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: _GOV)


@pytest.fixture
def low_cfg(monkeypatch, clean_env):
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: _LOW)


@pytest.fixture
def gov_ledger(tmp_path, monkeypatch):
    import agent.governance_audit_hooks as gah
    from agent.governance_audit import GovernanceLedger

    led = GovernanceLedger(tmp_path / "agent-audit.log")
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: led)
    return led


def _decisions(led):
    from agent.governance_audit import iter_records

    return [r for r in iter_records(led.path) if r["event"] == "approval.decision"]


def _authenticate(principal="alice@agency.mil"):
    import agent.governance_audit_hooks as gah

    gah.set_operator_subject(principal, auth="dashboard_auth:oauth")


def _queue_entry(session_key, command="rm -rf ./build"):
    from tools.approval import _ApprovalEntry, _gateway_queues

    entry = _ApprovalEntry({"command": command, "description": "recursive delete"})
    _gateway_queues.setdefault(session_key, []).append(entry)
    return entry


@pytest.fixture
def clean_queues():
    from tools.approval import _gateway_queues

    _gateway_queues.clear()
    yield
    _gateway_queues.clear()


# ---------------------------------------------------------------------------
# Gateway resolution (TUI approval.respond, messaging /approve, API server)
# ---------------------------------------------------------------------------

def test_unauthenticated_gateway_approval_is_refused(gov_cfg, gov_ledger, clean_queues):
    from tools.approval import ApprovalRefused, _gateway_queues, resolve_gateway_approval

    entry = _queue_entry("s-anon")
    assert resolve_gateway_approval("s-anon", "once") == 0
    assert not entry.event.is_set()                     # still pending
    assert _gateway_queues["s-anon"] == [entry]
    with pytest.raises(ApprovalRefused, match="LG-GV-05"):
        resolve_gateway_approval("s-anon", "always", raise_on_refusal=True)

    recs = _decisions(gov_ledger)
    assert recs and all(r["decision"] == "deny" for r in recs)
    assert "unauthenticated_approver_refused" in str(recs[-1].get("outcome"))


def test_authenticated_gateway_approval_is_accepted_and_attributed(
    gov_cfg, gov_ledger, clean_queues
):
    from tools.approval import resolve_gateway_approval

    entry = _queue_entry("s-auth")
    _authenticate("alice@agency.mil")
    assert resolve_gateway_approval("s-auth", "once") == 1
    assert entry.event.is_set() and entry.result == "once"
    assert entry.approver == "alice@agency.mil"


def test_denial_is_never_refused(gov_cfg, clean_queues):
    from tools.approval import resolve_gateway_approval

    entry = _queue_entry("s-deny")
    assert resolve_gateway_approval("s-deny", "deny") == 1
    assert entry.result == "deny"


def test_connection_only_identity_is_not_an_approver(gov_cfg, clean_queues):
    """The dashboard's server-internal WS identity authenticates a socket,
    not a human — it cannot approve."""
    from tools.approval import resolve_gateway_approval

    _queue_entry("s-internal")
    _authenticate("server-internal")
    assert resolve_gateway_approval("s-internal", "once") == 0


def test_low_side_anonymous_gateway_approval_unchanged(low_cfg, clean_queues):
    from tools.approval import resolve_gateway_approval

    entry = _queue_entry("s-low")
    assert resolve_gateway_approval("s-low", "once") == 1
    assert entry.result == "once" and entry.approver is None


def test_gateway_wait_records_the_resolving_principal(gov_cfg, gov_ledger, clean_queues):
    """End to end: the agent thread blocks in _await_gateway_decision, an
    authenticated resolver approves from another context, and the ledger's
    approval.decision names the resolver."""
    import contextvars

    from tools import approval as ap

    def notify(_data):
        def resolver():
            _authenticate("bob@agency.mil")
            ap.resolve_gateway_approval("s-e2e", "once")

        # Fresh context: the resolver's principal is ITS OWN, not the agent's.
        threading.Thread(target=lambda: contextvars.Context().run(resolver)).start()

    decision = ap._await_gateway_decision(
        "s-e2e", notify, {"command": "rm -rf ./build", "description": "recursive delete"},
    )
    assert decision == {"resolved": True, "choice": "once"}
    recs = [r for r in _decisions(gov_ledger) if r.get("outcome", {}).get("origin") == "gateway"]
    assert recs[-1]["decision"] == "approve"
    assert recs[-1]["approver"] == {"id": "bob@agency.mil", "authenticated": True}


# ---------------------------------------------------------------------------
# TUI JSON-RPC approval.respond
# ---------------------------------------------------------------------------

def test_tui_approval_respond_reports_refusal(gov_cfg, clean_queues, monkeypatch):
    from tui_gateway import server

    _queue_entry("tui-key")
    monkeypatch.setitem(server._sessions, "sid-1", {"session_key": "tui-key"})
    resp = server.handle_request({
        "jsonrpc": "2.0", "id": "r1", "method": "approval.respond",
        "params": {"session_id": "sid-1", "choice": "once"},
    })
    assert resp["error"]["code"] == 4033
    assert "LG-GV-05" in resp["error"]["message"]

    _authenticate()
    resp = server.handle_request({
        "jsonrpc": "2.0", "id": "r2", "method": "approval.respond",
        "params": {"session_id": "sid-1", "choice": "once"},
    })
    assert resp["result"] == {"resolved": 1}


# ---------------------------------------------------------------------------
# CLI / ACP prompt path and smart approval
# ---------------------------------------------------------------------------

def test_cli_prompt_not_shown_without_authenticated_approver(gov_cfg, monkeypatch):
    from tools import approval as ap

    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    ap.clear_session("default")
    prompted = []
    result = ap.check_dangerous_command(
        "rm -rf ./build", "local",
        approval_callback=lambda *a, **kw: prompted.append(a) or "once",
    )
    assert result["approved"] is False
    assert "LG-GV-05" in result["message"]
    assert prompted == []
    assert ap.prompt_dangerous_approval(
        "rm -rf ./build", "recursive delete",
        approval_callback=lambda *a, **kw: "once",
    ) == "deny"


def test_cli_prompt_with_authenticated_approver_still_prompts(gov_cfg, gov_ledger, monkeypatch):
    from tools import approval as ap

    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    ap.clear_session("default")
    _authenticate("carol@agency.mil")
    result = ap.check_dangerous_command(
        "rm -rf ./build", "local", approval_callback=lambda *a, **kw: "once",
    )
    assert result["approved"] is True
    rec = _decisions(gov_ledger)[-1]
    assert rec["decision"] == "approve"
    assert rec["approver"] == {"id": "carol@agency.mil", "authenticated": True}


def test_low_side_cli_prompt_unchanged(low_cfg, monkeypatch):
    from tools import approval as ap

    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    ap.clear_session("default")
    result = ap.check_dangerous_command(
        "rm -rf ./build", "local", approval_callback=lambda *a, **kw: "once",
    )
    assert result["approved"] is True


def test_smart_approval_escalates_when_authenticated_approver_required(gov_cfg, monkeypatch):
    from types import SimpleNamespace

    from tools import approval as ap

    reply = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="APPROVE"))])
    monkeypatch.setattr("agent.auxiliary_client.call_llm", lambda *a, **kw: reply)
    assert ap._smart_approve("python -c 'print(1)'", "script execution") == "escalate"


def test_low_side_smart_approval_unchanged(low_cfg, monkeypatch):
    from types import SimpleNamespace

    from tools import approval as ap

    reply = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="APPROVE"))])
    monkeypatch.setattr("agent.auxiliary_client.call_llm", lambda *a, **kw: reply)
    assert ap._smart_approve("python -c 'print(1)'", "script execution") == "approve"


# ---------------------------------------------------------------------------
# JIT grants / operator override
# ---------------------------------------------------------------------------

@pytest.fixture
def risk_policy(tmp_path, monkeypatch):
    policy = tmp_path / "tool-risk-policy.yaml"
    policy.write_text(textwrap.dedent(
        """
        metadata: {default_disposition: deny, fail_closed: true}
        action_classes:
          - {class: shell.destructive, tier: hitl_approve}
        zero_standing_privilege:
          enabled: true
          default_off_capabilities: [shell.destructive]
          grant: {ttl_seconds: 1800}
        """
    ))
    from tools import tool_policy as tp

    monkeypatch.setattr(tp, "_load_risk_policy", lambda: yaml.safe_load(policy.read_text()))
    tp.reset_pdp_state()
    yield tp
    tp.reset_pdp_state()


def test_operator_override_requires_bound_principal(gov_cfg, risk_policy):
    from tools.hitl_oversight import operator_override

    with pytest.raises(PermissionError, match="LG-GV-05"):
        operator_override("shell.destructive", approver="mallory", justification="x")
    with pytest.raises(PermissionError):
        risk_policy.grant_capability("shell.destructive", approver="mallory")

    _authenticate("alice@agency.mil")
    with pytest.raises(PermissionError, match="not the authenticated principal"):
        operator_override("shell.destructive", approver="mallory", justification="x")
    operator_override("shell.destructive", approver="alice@agency.mil", justification="incident 42")
    assert risk_policy._active_grant("shell.destructive") is not None


def test_low_side_grant_unchanged(low_cfg, risk_policy):
    risk_policy.grant_capability("shell.destructive", approver="jerome@dashboard")
    assert risk_policy._active_grant("shell.destructive") is not None


# ---------------------------------------------------------------------------
# MCP surface (mcp_serve)
# ---------------------------------------------------------------------------

def test_permissions_respond_withheld_under_strict(monkeypatch):
    import mcp_serve

    assert "permissions_respond" not in mcp_serve.tool_surface(strict=True)
    assert "permissions_respond" in mcp_serve.tool_surface(strict=False)

    registered = []

    class _FakeMCP:
        def __init__(self, *a, **kw):
            pass

        def tool(self):
            def deco(fn):
                registered.append(fn.__name__)
                return fn
            return deco

    monkeypatch.setattr(mcp_serve, "_MCP_SERVER_AVAILABLE", True)
    monkeypatch.setattr(mcp_serve, "FastMCP", _FakeMCP)
    mcp_serve.create_mcp_server(event_bridge=mcp_serve.EventBridge(), strict=True)
    assert registered == mcp_serve.tool_surface(strict=True)
    registered.clear()
    mcp_serve.create_mcp_server(event_bridge=mcp_serve.EventBridge(), strict=False)
    assert "permissions_respond" in registered


def test_mcp_strict_default_follows_live_posture(gov_cfg):
    import mcp_serve

    assert "permissions_respond" not in mcp_serve.tool_surface()


def test_mcp_bridge_refuses_unauthenticated_approval(gov_cfg):
    import mcp_serve

    bridge = mcp_serve.EventBridge()
    bridge._pending_approvals["a1"] = {"id": "a1", "description": "sudo rm"}
    out = bridge.respond_to_approval("a1", "allow-once")
    assert "LG-GV-05" in out["error"]
    assert "a1" in bridge._pending_approvals               # still pending
    assert bridge.respond_to_approval("a1", "deny")["resolved"] is True


# ---------------------------------------------------------------------------
# CI invariant (control_effectiveness)
# ---------------------------------------------------------------------------

def test_control_effectiveness_reports_approval_channel_invariants():
    r = ce.effectiveness_report(repo_root=_REPO)
    assert r["authenticated_approver_required"] is True
    assert r["authenticated_approver_enforced"] is True
    assert r["mcp_permissions_respond_withheld"] is True


def test_control_effectiveness_fails_without_authenticated_approver(tmp_path):
    data = yaml.safe_load((_REPO / "cli-config.gov.yaml").read_text())
    data["security"]["require_authenticated_approver"] = False
    p = tmp_path / "cli-config.gov.yaml"
    p.write_text(yaml.safe_dump(data))
    failures = ce.check_effectiveness(repo_root=_REPO, overlay_path=p)
    assert any("require_authenticated_approver" in f for f in failures)
    assert any("unauthenticated HITL approval" in f for f in failures)


def test_control_effectiveness_fails_when_permissions_respond_exposed(monkeypatch):
    import mcp_serve

    monkeypatch.setattr(mcp_serve, "STRICT_EXCLUDED_TOOLS", frozenset())
    failures = ce.check_effectiveness(repo_root=_REPO)
    assert any("permissions_respond" in f for f in failures)
