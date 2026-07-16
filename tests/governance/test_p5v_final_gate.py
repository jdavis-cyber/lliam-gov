"""P5.V — FINAL verify gate over the entire standing corpus (AI-503).

The assessor-ready final assertions:
  * control-by-control status for ALL 188 controls — every control is
    Implemented (0 Partial · 0 Planned), the SoA reconciles to the catalog,
    and every implemented control's evidence file exists;
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

import yaml
import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import control_effectiveness as ce
from agent import cato_loop as cato
from agent import killswitch as ks

_GOV = _REPO / "docs" / "governance"


def _load(rel):
    return yaml.safe_load((_GOV / rel).read_text(encoding="utf-8"))


@pytest.fixture
def _iso_ks(tmp_path, monkeypatch):
    monkeypatch.setattr(ks, "_state_path", lambda: tmp_path / "killswitch.state")
    ks.reset_for_tests()
    yield
    ks.reset_for_tests()


# ---------------------------------------------------------------------------
# Control-by-control status — ALL 188 implemented
# ---------------------------------------------------------------------------

def test_all_188_controls_implemented():
    controls = _load("control-catalog.yaml")["controls"]
    assert len(controls) == 188
    by_status = {}
    for c in controls:
        by_status.setdefault(c["status"], []).append(c["id"])
    assert set(by_status) == {"implemented"}, \
        f"non-implemented controls remain: " \
        f"{ {k: v for k, v in by_status.items() if k != 'implemented'} }"


def test_every_control_has_existing_evidence():
    missing = []
    for c in _load("control-catalog.yaml")["controls"]:
        ev = c.get("evidence")
        if not ev:
            missing.append(f"{c['id']}: no evidence")
        elif ev.endswith((".md", ".yaml", ".py", ".sh")) and \
                not (_REPO / ev).exists():
            missing.append(f"{c['id']}: {ev} missing")
    assert missing == [], "\n".join(missing)


def test_soa_reconciles_all_188():
    import soa_gate
    assert soa_gate.check_soa(repo_root=_REPO) == []


# ---------------------------------------------------------------------------
# The scheduled kill-switch test: HALT → CLEAN RESTORE (the FINAL requirement)
# ---------------------------------------------------------------------------

def test_scheduled_killswitch_halts_then_cleanly_restores(_iso_ks):
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
    assert ks.recover_and_reenable(baseline_tag="gov-P5-good",
                                   actor="isso@agency.mil",
                                   verify_ok=False) is False
    assert ks.is_engaged() is True

    # verified chain → CLEAN RESTORE of full capability, no residue
    assert ks.recover_and_reenable(baseline_tag="gov-P5-good",
                                   actor="isso@agency.mil",
                                   verify_ok=True) is True
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


# ---------------------------------------------------------------------------
# Outstanding POA&M is deployment-tier only (no eval-scope gaps)
# ---------------------------------------------------------------------------

def test_only_deployment_tier_poam_open():
    poam = _load("poam.yaml")["items"]
    open_items = [i["id"] for i in poam if i.get("status") == "open"]
    assert set(open_items) <= {"POAM-FIPS", "POAM-EGRESS-ENCLAVE"}, \
        f"unexpected open POA&M: {open_items}"
