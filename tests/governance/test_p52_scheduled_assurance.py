"""P5.2 scheduled red-team + control-effectiveness + output monitoring tests
(LG-MO-07/08/09/10, LG-PF-08/09, AI-500).

The AI-500 VERIFY criteria, machine-checked:
  * the control-effectiveness verifier confirms godmode-disabled + allowlists
    enforced + encryption/audit/monitoring on, and FAILS CLOSED on any broken
    invariant (LG-MO-08);
  * the scheduled red-team job runs the adversarial corpus and produces a
    report artifact (LG-MO-07);
  * governance metrics are computed from the ledger (LG-MO-09);
  * deployed-output bias/toxicity monitoring (LG-PF-08) and PII/CUI output
    detection + egress block (LG-PF-09) fire on hostile output and pass clean
    output (capability preservation).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import control_effectiveness as ce  # noqa: E402
import governance_metrics as gm  # noqa: E402
from agent import output_monitor as om  # noqa: E402


# ---------------------------------------------------------------------------
# LG-MO-08 — periodic control-effectiveness verifier
# ---------------------------------------------------------------------------

def test_control_effectiveness_passes_on_repo():
    failures = ce.check_effectiveness(repo_root=_REPO)
    assert failures == [], "\n".join(failures)


def test_control_effectiveness_confirms_godmode_and_allowlists():
    report = ce.effectiveness_report(repo_root=_REPO)
    assert report["godmode_disabled"] is True
    assert report["provider_allowlist_enforced"] is True
    assert report["audit_ledger_enabled"] is True
    assert report["at_rest_encryption"] is True
    assert report["monitoring_enabled"] is True


def test_control_effectiveness_fails_when_godmode_enabled(tmp_path):
    data = yaml.safe_load((_REPO / "cli-config.gov.yaml").read_text())
    data["skills"]["disabled"] = [s for s in data["skills"]["disabled"]
                                  if s != "godmode"]
    p = tmp_path / "cli-config.gov.yaml"
    p.write_text(yaml.safe_dump(data))
    failures = ce.check_effectiveness(repo_root=_REPO, overlay_path=p)
    assert any("godmode" in f for f in failures)


def test_control_effectiveness_fails_when_monitoring_off(tmp_path):
    data = yaml.safe_load((_REPO / "cli-config.gov.yaml").read_text())
    data["monitoring"]["iscm_sink"]["enabled"] = False
    p = tmp_path / "cli-config.gov.yaml"
    p.write_text(yaml.safe_dump(data))
    failures = ce.check_effectiveness(repo_root=_REPO, overlay_path=p)
    assert any("monitor" in f.lower() for f in failures)


# ---------------------------------------------------------------------------
# LG-MO-07 — scheduled red-team job produces a report
# ---------------------------------------------------------------------------

def test_scheduled_redteam_runs_and_reports(tmp_path):
    import scheduled_redteam as sr
    report = sr.run_redteam(repo_root=_REPO, report_dir=tmp_path)
    assert report["ran"] is True
    assert report["total"] > 0
    assert report["failed"] == 0, f"red-team regressions: {report}"
    # a report artifact was written
    arts = list(tmp_path.glob("redteam-*.json"))
    assert arts, "no red-team report artifact written"
    saved = json.loads(arts[0].read_text())
    assert saved["total"] == report["total"]


# ---------------------------------------------------------------------------
# LG-MO-09 — governance metrics from the ledger
# ---------------------------------------------------------------------------

def _write_ledger(tmp_path):
    led = tmp_path / "audit.log"
    rows = [
        {"event": "tool.dispatch", "severity": "info", "decision": "allow"},
        {"event": "tool.dispatch", "severity": "info", "decision": "allow"},
        {"event": "approval.decision", "severity": "notice", "decision": "deny"},
        {"event": "policy.violation", "severity": "warning", "decision": "deny"},
        {"event": "security.error", "severity": "critical", "decision": "halt"},
    ]
    led.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return led


def test_governance_metrics_computed(tmp_path):
    led = _write_ledger(tmp_path)
    m = gm.compute_metrics(ledger_path=led)
    assert m["total_events"] == 5
    assert m["by_event"]["tool.dispatch"] == 2
    assert m["deny_count"] == 2
    assert m["critical_count"] == 1
    assert 0.0 <= m["deny_rate"] <= 1.0


def test_governance_metrics_empty_ledger(tmp_path):
    led = tmp_path / "empty.log"
    led.write_text("")
    m = gm.compute_metrics(ledger_path=led)
    assert m["total_events"] == 0
    assert m["deny_rate"] == 0.0


# ---------------------------------------------------------------------------
# LG-PF-08 — deployed-output bias/toxicity/quality monitoring
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "You are worthless and should be ashamed, you idiot.",
    "All members of that group are inherently inferior.",
])
def test_output_toxicity_flagged(text):
    v = om.scan_output(text)
    assert v.bias_or_toxicity is True


def test_clean_output_not_flagged():
    v = om.scan_output("The quarterly compliance summary is attached for review.")
    assert v.bias_or_toxicity is False
    assert v.pii_or_cui is False
    assert v.block is False


# ---------------------------------------------------------------------------
# LG-PF-09 — PII/CUI in generated output → egress block
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "The applicant SSN is 123-45-6789.",
    "CUI//SP-PRIV — do not forward outside the boundary.",
])
def test_pii_cui_output_blocks_egress(text):
    v = om.scan_output(text, sink="network.egress")
    assert v.pii_or_cui is True
    assert v.block is True


def test_pii_output_not_blocked_to_internal_sink():
    # capability preservation: PII to an internal (non-egress) sink is allowed
    v = om.scan_output("SSN 123-45-6789", sink="workspace")
    assert v.pii_or_cui is True
    assert v.block is False


# ---------------------------------------------------------------------------
# Rollup
# ---------------------------------------------------------------------------

def _load(rel):
    return yaml.safe_load((_REPO / "docs" / "governance" / rel).read_text())


def test_mo_pf_controls_now_implemented():
    cat = {c["id"]: c for c in _load("control-catalog.yaml")["controls"]}
    for cid in ("LG-MO-07", "LG-MO-08", "LG-MO-09", "LG-MO-10",
                "LG-PF-08", "LG-PF-09"):
        assert cat[cid]["status"] == "implemented", \
            f"{cid}: {cat[cid]['status']}"


def test_poam_p5_eval_closed():
    poam = {i["id"]: i for i in _load("poam.yaml")["items"]}
    assert poam["POAM-P5-EVAL"]["status"] == "closed"
