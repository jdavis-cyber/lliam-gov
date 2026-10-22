"""P5 capability-preservation corpus: monitored, continuously authorized, capable.

Phase 5 adds continuous monitoring (P5.1 ISCM sink + runtime monitors fed from
every sealed ledger record), scheduled assurance (P5.2 control-effectiveness
and governance metrics), the kill-switch (P5.3), and the cATO loop that
auto-suspends on a real posture break (P5.4). Under the SHIPPED overlay this
corpus runs a realistic session through the public dispatch funnel and checks
the Phase 5 acceptance boundary:

  * the monitoring and cATO functions really run in the governed profile:
    the monitor hub is live, control effectiveness holds on the repo, and the
    governance metrics are computed from the live ledger;
  * steady-state work raises no alert and no notification, the live cATO
    cycle does not suspend, and work continues after it;
  * a kill-switch drill halts dispatch and a verified recovery restores it
    fully;
  * the ONLY new signal on a real denial is a warning alert plus a
    notification to the configured staff. A warning does not suspend.
"""

from __future__ import annotations

import sys

import pytest

from tests.governance._governed_profile import (
    REPO,
    call_tool,
    enter_governed_profile,
    stub_tool_handlers,
)

sys.path.insert(0, str(REPO / "ci" / "governance-ci-gates"))

import control_effectiveness as ce  # noqa: E402
import governance_metrics as gm  # noqa: E402

_SESSION_ID = "task-p5"


def _session(ws):
    # A realistic edit/test loop. It interleaves tools on purpose: LG-MO-01
    # keys runaway on (action, outcome.target), and dispatch records carry no
    # target, so 8+ consecutive calls to one tool alert even on distinct
    # files. That false-positive is reported separately and is not baked in.
    loop = []
    for i in range(4):
        loop += [
            ("read_file", {"path": f"src/mod{i}.py"}),
            ("search_files", {"pattern": f"def f{i}", "path": "src"}),
            ("patch", {"path": str(ws / f"mod{i}.py"), "old_string": "a", "new_string": "b"}),
            ("terminal", {"command": f"pytest -q tests/test_mod{i}.py"}),
        ]
    return loop + [("write_file", {"path": str(ws / "CHANGELOG.md"), "content": "fix\n"})]


@pytest.fixture
def p5(tmp_path, monkeypatch):
    gp = enter_governed_profile(tmp_path, monkeypatch)
    handled = stub_tool_handlers(monkeypatch)
    return gp, handled


def _hub():
    import agent.governance_audit as ga

    return ga.get_monitor_hub()


def _run(session):
    return [call_tool(name, args, task_id="p5") for name, args in session]


def test_monitoring_is_live_in_governed_profile(p5):
    hub = _hub()
    assert hub is not None and hub.enabled
    assert hub.notify_recipients                      # named staff configured
    assert ce.check_effectiveness(repo_root=REPO) == []


def test_steady_state_no_alert_no_suspension_work_continues(p5):
    from agent import cato_loop as cato
    from agent import killswitch as ks

    gp, handled = p5
    session = _session(gp.safe_root)
    assert all(r == {"output": "ok"} for r in _run(session))
    assert len(handled) == len(session)

    hub = _hub()
    assert hub.session_timeline(_SESSION_ID) == []
    assert hub.drain_notifications() == []

    # Live cATO cycle: real control-effectiveness run + the observed alerts.
    verdict = cato.run_cato_cycle(alerts=hub.session_timeline(_SESSION_ID),
                                  actor="isso@agency.mil", repo_root=REPO)
    assert verdict.suspend is False
    assert ks.is_engaged() is False
    assert call_tool("read_file", {"path": "src/after.py"}, task_id="p5") == {"output": "ok"}


def test_metrics_computed_from_live_ledger(p5):
    gp, _handled = p5
    session = _session(gp.safe_root)
    _run(session)
    m = gm.compute_metrics(ledger_path=gp.ledger_path)
    assert m["by_event"]["tool.dispatch"] == len(session)
    assert m["by_event"]["tool.result"] == len(session)
    assert m["deny_count"] == 0 and m["critical_count"] == 0


def test_killswitch_drill_halts_then_verified_recovery_restores(p5):
    from agent import killswitch as ks
    from agent.governance_audit import verify_chain

    gp, handled = p5
    assert call_tool("read_file", {"path": "a.py"}, task_id="p5") == {"output": "ok"}
    ks.engage(reason="scheduled drill", actor="isso@agency.mil")
    out = call_tool("read_file", {"path": "b.py"}, task_id="p5")
    assert "kill-switch" in out.get("error", "").lower(), out
    assert [n for n, _ in handled] == ["read_file"]   # halted call never ran

    check = verify_chain(gp.ledger_path)
    assert ks.recover_and_reenable(baseline_tag="gov-P0-good", actor="isso@agency.mil",
                                   verify_ok=check.ok, verify_reason=str(check.reason))
    assert ks.is_engaged() is False
    session = _session(gp.safe_root)
    assert all(r == {"output": "ok"} for r in _run(session))
    assert len(handled) == 1 + len(session)


def test_real_denial_alerts_staff_without_suspending(p5):
    from agent import cato_loop as cato
    from agent import killswitch as ks

    _gp, handled = p5
    out = call_tool("computer_use", {"action": "screenshot"}, task_id="p5")
    assert "Blocked" in out.get("error", "")
    assert handled == []

    hub = _hub()
    alerts = hub.session_timeline(_SESSION_ID)
    assert [(a.control, a.severity) for a in alerts] == [("LG-MO-04", "warning")]
    notes = hub.drain_notifications()
    assert [n.session for n in notes if n.session == _SESSION_ID] == [_SESSION_ID]
    assert all(n.recipients == hub.notify_recipients for n in notes)
    assert all(n.severity == "warning" for n in notes)

    verdict = cato.run_cato_cycle(alerts=alerts, actor="isso@agency.mil", repo_root=REPO)
    assert verdict.suspend is False and ks.is_engaged() is False
    assert call_tool("read_file", {"path": "src/app.py"}, task_id="p5") == {"output": "ok"}
