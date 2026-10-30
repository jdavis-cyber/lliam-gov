"""P5.4 cATO loop + reciprocity export tests (LG-GV-07/08, LG-TP-07, AI-502).

The AI-502 VERIFY criteria, machine-checked:
  * a posture-break (injected drift) triggers auto-suspend via the kill-switch
    (LG-GV-07) — and steady state does NOT (no false auto-suspension, the
    FINAL-gate requirement);
  * the portable posture/attestation export is produced with provenance and
    the audit-chain hash, and carries a content signature (LG-TP-07).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

from agent import cato_loop as cato
from agent import killswitch as ks
import attestation_export as ax


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(ks, "_state_path", lambda: tmp_path / "killswitch.state")
    ks.reset_for_tests()
    yield
    ks.reset_for_tests()


# ---------------------------------------------------------------------------
# LG-GV-07 — cATO auto-suspend on real posture-break, not steady state
# ---------------------------------------------------------------------------

def test_steady_state_does_not_suspend():
    v = cato.evaluate(alerts=[], effectiveness_failures=[])
    assert v.suspend is False
    # a couple of low-severity alerts are steady-state noise, not a break
    v2 = cato.evaluate(
        alerts=[cato.AlertView("LG-MO-02", "info"),
                cato.AlertView("LG-MO-04", "notice")],
        effectiveness_failures=[])
    assert v2.suspend is False


def test_effectiveness_break_suspends():
    v = cato.evaluate(
        alerts=[],
        effectiveness_failures=["[INEFFECTIVE] godmode is not disabled (LG-MO-08)"])
    assert v.suspend is True
    assert "godmode" in v.reason


def test_critical_alert_suspends():
    v = cato.evaluate(
        alerts=[cato.AlertView("LG-MO-04", "critical")],
        effectiveness_failures=[])
    assert v.suspend is True


def test_run_cato_cycle_injected_drift_engages_killswitch():
    assert ks.is_engaged() is False
    verdict = cato.run_cato_cycle(
        alerts=[cato.AlertView("LG-MO-04", "critical")],
        effectiveness_failures=["[INEFFECTIVE] provider allowlist not enforced"],
        actor="isso@agency.mil")
    assert verdict.suspend is True
    assert verdict.reauthorization_required is True
    # the kill-switch is now engaged (auto-suspend, LG-GV-07)
    assert ks.is_engaged() is True


def test_run_cato_cycle_steady_state_leaves_capability():
    verdict = cato.run_cato_cycle(alerts=[], effectiveness_failures=[],
                                  actor="isso@agency.mil")
    assert verdict.suspend is False
    assert verdict.reauthorization_required is False
    assert ks.is_engaged() is False  # NO false auto-suspension


# ---------------------------------------------------------------------------
# LG-TP-07 — portable posture/attestation export
# ---------------------------------------------------------------------------

def test_attestation_export_produced_and_signed():
    att = ax.build_attestation(repo_root=_REPO, stamp="2026-07-16T00:00:00Z",
                               attested_by="jdavis@agency.mil")
    assert att["provenance"]["baseline_tag"]
    assert "audit_chain" in att
    assert att["attested_by"] == "jdavis@agency.mil"
    signed = ax.sign_attestation(att)
    assert signed["content_sha256"]
    # the signature verifies against the content (not a shipped secret)
    assert ax.verify_attestation(signed) is True


def test_attestation_tamper_detected():
    att = ax.build_attestation(repo_root=_REPO, stamp="2026-07-16T00:00:00Z",
                               attested_by="jdavis@agency.mil")
    signed = ax.sign_attestation(att)
    signed["provenance"]["baseline_commit"] = "0" * 40  # tamper
    assert ax.verify_attestation(signed) is False


# ---------------------------------------------------------------------------
# Live wiring + rollup
# ---------------------------------------------------------------------------

def test_cato_reads_effectiveness_checker():
    # the cato loop's helper composes the real control-effectiveness gate
    failures = cato.current_effectiveness_failures(repo_root=_REPO)
    assert failures == []  # repo posture is effective

