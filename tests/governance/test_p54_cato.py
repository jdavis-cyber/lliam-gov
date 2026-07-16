"""P5.4 cATO loop + autonomy classification + reciprocity export tests
(LG-GV-07/08, LG-TP-05/06/07, AI-502).

The AI-502 VERIFY criteria, machine-checked:
  * a posture-break (injected drift) triggers auto-suspend via the kill-switch
    (LG-GV-07) — and steady state does NOT (no false auto-suspension, the
    FINAL-gate requirement);
  * the portable posture/attestation export is produced with control coverage,
    provenance, and the audit-chain hash, and carries a content signature
    (LG-TP-07);
  * the autonomy (L0–L5) + intervention-tier classification and third-party
    contingency docs are present (LG-TP-05/06).
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
    assert att["control_coverage"]["total"] == 188
    assert att["control_coverage"]["implemented"] >= 180
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
    signed["control_coverage"]["implemented"] = 999  # tamper
    assert ax.verify_attestation(signed) is False


# ---------------------------------------------------------------------------
# LG-TP-05 / LG-TP-06 — autonomy classification + contingency docs
# ---------------------------------------------------------------------------

def test_autonomy_classification_doc_present():
    text = (_REPO / "docs" / "governance"
            / "autonomy-classification.md").read_text(encoding="utf-8")
    for level in ("L0", "L1", "L2", "L3", "L4", "L5"):
        assert level in text, f"autonomy doc missing {level}"
    for tier in ("T1", "T5"):
        assert tier in text
    assert "kill-switch" in text.lower()


def test_contingency_doc_present():
    text = (_REPO / "docs" / "governance"
            / "third-party-contingency.md").read_text(encoding="utf-8")
    assert len(text) > 1500
    assert "on-prem" in text.lower() or "on-premise" in text.lower()
    assert "fallback" in text.lower()


# ---------------------------------------------------------------------------
# Live wiring + rollup
# ---------------------------------------------------------------------------

def test_cato_reads_effectiveness_checker():
    # the cato loop's helper composes the real control-effectiveness gate
    failures = cato.current_effectiveness_failures(repo_root=_REPO)
    assert failures == []  # repo posture is effective


def _load(rel):
    import yaml
    return yaml.safe_load((_REPO / "docs" / "governance" / rel).read_text())


def test_gv_tp_controls_now_implemented():
    cat = {c["id"]: c for c in _load("control-catalog.yaml")["controls"]}
    for cid in ("LG-GV-07", "LG-GV-08", "LG-TP-05", "LG-TP-06", "LG-TP-07"):
        assert cat[cid]["status"] == "implemented", \
            f"{cid}: {cat[cid]['status']}"


def test_poam_p5_cato_closed():
    poam = {i["id"]: i for i in _load("poam.yaml")["items"]}
    assert poam["POAM-P5-CATO"]["status"] == "closed"
