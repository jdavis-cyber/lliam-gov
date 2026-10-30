"""P5.V — FINAL verify gate over the entire standing corpus (AI-503).

The final assertions:
  * the scheduled kill-switch test HALTS then CLEANLY RESTORES full capability
    (no residue) and is fail-closed on a broken chain;
  * NO false auto-suspensions on steady state — the cATO loop does not suspend
    on benign activity and DOES suspend on real injected drift;
  * every Phase 4/5 control-effectiveness invariant holds (godmode disabled,
    allowlists enforced, encryption/audit/monitoring on).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import control_effectiveness as ce
from agent import cato_loop as cato
from agent import killswitch as ks

@pytest.fixture
def _iso_ks(tmp_path, monkeypatch):
    monkeypatch.setattr(ks, "_state_path", lambda: tmp_path / "killswitch.state")
    ks.reset_for_tests()
    yield
    ks.reset_for_tests()


# ---------------------------------------------------------------------------
# The scheduled kill-switch test: HALT → CLEAN RESTORE (the FINAL requirement)
# ---------------------------------------------------------------------------

def test_scheduled_killswitch_halts_then_cleanly_restores(_iso_ks, live_ledger,
                                                         baseline_repo):
    # steady state: fully capable
    assert ks.is_engaged() is False
    assert ks.guard_tool_dispatch("shell.destructive") is None
    ks.assert_inference_live()

    # HALT
    ks.engage(reason="scheduled kill-switch drill", actor="isso@agency.mil")
    assert ks.guard_tool_dispatch("file_read") is not None      # tools halted
    with pytest.raises(ks.KillSwitchEngaged):
        ks.assert_inference_live()                              # inference halted

    # broken chain → recovery REFUSED (fail-closed), still halted
    good = live_ledger.path.read_bytes()
    live_ledger.path.write_bytes(good.replace(b'"session.start"',
                                              b'"session.stop"', 1))
    assert ks.recover_and_reenable(actor="isso@agency.mil",
                                   reason="scheduled drill",
                                   repo_root=baseline_repo.root) is False
    assert ks.is_engaged() is True

    # verified chain → CLEAN RESTORE of full capability, no residue
    live_ledger.path.write_bytes(good)
    assert ks.recover_and_reenable(actor="isso@agency.mil",
                                   reason="scheduled drill",
                                   repo_root=baseline_repo.root) is True
    assert ks.is_engaged() is False
    assert ks.guard_tool_dispatch("shell.destructive") is None
    ks.assert_inference_live()
    assert ks.class_contained("shell.destructive") is False


# ---------------------------------------------------------------------------
# NO false auto-suspensions on steady state; suspend ONLY on real drift
# ---------------------------------------------------------------------------

def test_no_false_auto_suspension_on_steady_state(_iso_ks):
    verdict = cato.run_cato_cycle(alerts=[], actor="isso@agency.mil",
                                  repo_root=_REPO)
    assert verdict.suspend is False
    assert ks.is_engaged() is False


def test_cato_suspends_only_on_real_injected_drift(_iso_ks):
    # benign activity: warning/notice alerts do NOT suspend
    benign = [cato.AlertView("LG-MO-02", "warning"),
              cato.AlertView("LG-MO-04", "notice")]
    v1 = cato.run_cato_cycle(alerts=benign, effectiveness_failures=[],
                             actor="isso@agency.mil")
    assert v1.suspend is False
    assert ks.is_engaged() is False

    # injected drift: a control-effectiveness break DOES suspend
    v2 = cato.run_cato_cycle(
        alerts=[],
        effectiveness_failures=["[INEFFECTIVE] godmode is not disabled"],
        actor="isso@agency.mil")
    assert v2.suspend is True
    assert ks.is_engaged() is True


# ---------------------------------------------------------------------------
# Control-effectiveness invariants hold on the standing baseline
# ---------------------------------------------------------------------------

def test_control_effectiveness_invariants_hold():
    assert ce.check_effectiveness(repo_root=_REPO) == []
    r = ce.effectiveness_report(repo_root=_REPO)
    for key in ("posture_strict", "godmode_disabled", "obliteratus_disabled",
                "provider_allowlist_enforced", "mcp_allowlist_enforced",
                "at_rest_encryption", "audit_ledger_enabled",
                "audit_verify_on_startup", "monitoring_enabled"):
        assert r[key] is True, f"invariant {key} broken"
