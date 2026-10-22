"""P1 capability-preservation corpus: accountable, and not in the way.

Phase 1 adds the hash-chained audit ledger (P1.1), the dispatch chokepoint
plus outcome accountability (P1.2), chain verification at startup and in CI
(P1.3), agent identity binding (P1.4), and the control-plane auth gate
(P1.5). Under the SHIPPED overlay this corpus runs a realistic session through
the public dispatch funnel and checks the Phase 1 acceptance boundary:

  * the work still happens: every call reaches its handler with its real
    arguments and returns the handler's result unchanged, and the startup
    gates (identity bind, chain verify, control-plane auth) pass on a clean
    home;
  * every call is recorded and attributable: one ``tool.dispatch`` plus one
    terminal record, a contiguous verified chain, and one NPE instance bound to
    the same code and governed config as the startup identity. Secrets are
    masked in the record but never in the call;
  * the ONLY new block is LG-AU-09: a mutating/high-risk call whose audit
    record cannot be written is refused, while a low-risk read still runs.
"""

from __future__ import annotations

import json
import sys

import pytest

from tests.governance._governed_profile import (
    REPO,
    call_tool,
    enter_governed_profile,
    stub_tool_handlers,
)

sys.path.insert(0, str(REPO / "ci" / "governance-ci-gates"))

import audit_chain_gate as acg  # noqa: E402

_TOKEN = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"


def _session(ws):
    return [
        ("read_file", {"path": "src/app.py"}),
        ("search_files", {"pattern": "def handler", "path": "src"}),
        ("write_file", {"path": str(ws / "app.py"), "content": "x = 1\n"}),
        ("patch", {"path": str(ws / "app.py"), "old_string": "1", "new_string": "2"}),
        ("terminal", {"command": "pytest -q"}),
        ("terminal", {"command": f"curl -H 'Authorization: token {_TOKEN}' https://api.github.com/user"}),
    ]


@pytest.fixture
def p1(tmp_path, monkeypatch):
    gp = enter_governed_profile(tmp_path, monkeypatch)
    import lliam_cli.security_audit_startup as sas

    for latch in ("_CHAIN_VERIFIED", "_CONTROL_PLANE_CHECKED"):
        monkeypatch.setattr(sas, latch, False, raising=False)
    return gp


def _records(gp):
    from agent.governance_audit import iter_records

    return list(iter_records(gp.ledger_path))


def test_ledger_is_on_and_contained_under_home_logs(p1):
    from agent import governance_audit as ga

    assert ga.ledger_enabled()
    assert ga.resolve_ledger_path() == p1.ledger_path


def test_startup_gates_pass_on_a_clean_home(p1):
    import lliam_cli.security_audit_startup as sas

    identity = sas.emit_agent_identity_at_startup()
    assert str(identity["instance_id"]).startswith("sha256:")
    verdict = sas.verify_audit_chain_at_startup(force=True)
    assert verdict["ok"] is True
    assert sas.enforce_control_plane_auth_at_startup(force=True) is None


def test_session_runs_unchanged_and_every_call_is_recorded(p1, monkeypatch):
    import lliam_cli.security_audit_startup as sas
    from agent.governance_audit import verify_chain

    identity = sas.emit_agent_identity_at_startup()
    handled = stub_tool_handlers(monkeypatch, result='{"output": "handler-result"}')
    session = _session(p1.safe_root)
    for name, args in session:
        assert call_tool(name, args, task_id="p1") == {"output": "handler-result"}
    # Handlers got the REAL arguments (incl. the secret), nothing was dropped.
    assert handled == [(n, a) for n, a in session]

    recs = [r for r in _records(p1) if r["correlation_id"] == "task-p1"]
    dispatch = [r for r in recs if r["event"] == "tool.dispatch"]
    outcome = [r for r in recs if r["event"] == "tool.result"]
    assert [r["action"] for r in dispatch] == [f"tool.{n}" for n, _ in session]
    assert [r["action"] for r in outcome] == [f"tool.{n}" for n, _ in session]
    assert all(r["outcome"]["status"] == "success" for r in outcome)
    assert all(r["decision"] != "deny" for r in recs)
    # Attributable: every dispatch names one NPE instance, bound to the same
    # code and effective (governed) config as the startup identity record.
    assert len({r["actor"]["instance_id"] for r in dispatch}) == 1
    for r in dispatch:
        assert str(r["actor"]["instance_id"]).startswith("sha256:")
        assert r["actor"]["code_hash"] == identity["code_hash"]
        assert r["actor"]["config_hash"] == identity["config_hash"]

    result = verify_chain(p1.ledger_path)
    assert result.ok and result.checked == len(_records(p1))
    assert acg.main(["--ledger", str(p1.ledger_path), "--require-strict"]) == 0


def test_secret_masked_in_record_not_in_call(p1, monkeypatch):
    handled = stub_tool_handlers(monkeypatch)
    args = _session(p1.safe_root)[-1][1]
    call_tool("terminal", args, task_id="p1")
    assert _TOKEN in handled[0][1]["command"]
    raw = p1.ledger_path.read_text(encoding="utf-8")
    assert _TOKEN not in raw
    disp = [r for r in _records(p1) if r["event"] == "tool.dispatch"][-1]
    assert disp["parameters"]["content_hash"].startswith("sha256:")


# --- the one new block: no record, no high-risk action (LG-AU-09) ----------

def test_unrecordable_high_risk_call_refused_low_risk_still_runs(p1, monkeypatch):
    from agent.governance_audit import GovernanceLedger

    handled = stub_tool_handlers(monkeypatch)

    def _disk_full(self, f, fields):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(GovernanceLedger, "_append_locked", _disk_full)

    out = call_tool("write_file", {"path": str(p1.safe_root / "a.py"), "content": "x"})
    assert "LG-AU-09" in json.dumps(out)
    assert handled == []                               # never executed

    assert call_tool("read_file", {"path": "src/app.py"}) == {"output": "ok"}
    assert handled == [("read_file", {"path": "src/app.py"})]
