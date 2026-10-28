"""P4.4 QMS + privacy/bias tests (LG-QT-*, LG-PF-01..06, AI-496).

The AI-496 VERIFY criteria, machine-checked:
  * the AI-disclosure / privacy notice is present (LG-PF-04);
  * the bias risk register covers the SP 1270 bias classes with named
    accountability (LG-PF-06);
  * the QMS layer defines process maps with measured indicators, quality
    objectives, and nonconforming-output control (LG-QT-01/02/04);
  * governance work products are under real configuration management
    (LG-QT-09) and the docs cite only real paths.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[2]

_GOV = _REPO / "docs" / "governance"


def _load(rel: str):
    with open(_GOV / rel, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# LG-PF-06 — bias risk register (SP 1270 classes, named accountability)
# ---------------------------------------------------------------------------

def test_bias_register_covers_sp1270_classes():
    reg = _load("bias-risk-register.yaml")
    classes = {r["bias_class"] for r in reg["risks"]}
    assert {"systemic", "statistical", "human"} <= classes, classes


def test_bias_register_rows_complete():
    reg = _load("bias-risk-register.yaml")
    cat_ids = {c["id"] for c in _load("control-catalog.yaml")["controls"]}
    for r in reg["risks"]:
        assert r.get("owner_role"), f"{r['id']}: no owner"
        assert r.get("mitigation"), f"{r['id']}: no mitigation"
        bad = [c for c in (r.get("controls") or []) if c not in cat_ids]
        assert bad == [], f"{r['id']}: unknown controls {bad}"


# ---------------------------------------------------------------------------
# LG-PF-01/02/04/05 — privacy policy + AI-disclosure notice
# ---------------------------------------------------------------------------

def test_privacy_policy_covers_pf_controls():
    text = (_GOV / "privacy-policy.md").read_text(encoding="utf-8")
    assert len(text) > 2500
    for needle in ("LG-PF-01", "LG-PF-02", "LG-PF-03", "LG-PF-05"):
        assert needle in text, f"privacy-policy.md missing {needle}"
    for concept in ("minimization", "retention", "lawful", "purpose"):
        assert concept in text.lower(), f"privacy policy missing '{concept}'"


def test_ai_disclosure_notice_present():
    text = (_GOV / "ai-disclosure-notice.md").read_text(encoding="utf-8")
    lowered = text.lower()
    assert "ai" in lowered and "disclos" in lowered
    assert "privacy" in lowered
    assert "appeal" in lowered or "recourse" in lowered or "handoff" in lowered


# ---------------------------------------------------------------------------
# LG-QT-01/02/04/09 — QMS process maps, objectives, nonconforming output
# ---------------------------------------------------------------------------

def test_qms_process_maps_cover_core_capabilities():
    text = (_GOV / "qms-process-maps.md").read_text(encoding="utf-8")
    for capability in ("file", "shell", "web", "provider", "mcp", "memory"):
        assert re.search(capability, text, re.I), \
            f"qms-process-maps.md missing '{capability}' process"


def test_qms_quality_objectives_named():
    text = (_GOV / "qms-process-maps.md").read_text(encoding="utf-8").lower()
    for metric in ("false-block", "redaction recall", "jailbreak-block",
                   "audit completeness", "task success"):
        assert metric in text, f"quality objective '{metric}' missing"


def test_qms_nonconforming_output_control_documented():
    text = (_GOV / "qms-process-maps.md").read_text(encoding="utf-8")
    assert "nonconforming" in text.lower()
    assert "quarantine" in text.lower() or "block" in text.lower()


def test_qms_configuration_management_cites_real_gates():
    text = (_GOV / "qms-process-maps.md").read_text(encoding="utf-8")
    for gate in ("baseline_drift_gate.py", "path_freeze_gate.py",
                 "soa_gate.py"):
        assert gate in text, f"QT-09 section missing {gate}"


_PATHLIKE = re.compile(r"`([A-Za-z0-9_./-]+/[A-Za-z0-9_./-]+\."
                       r"(?:py|yaml|yml|md|json|csv|conf|toml|lock|sh))`")


def test_p44_docs_cite_only_real_paths():
    missing = []
    for rel in ("qms-process-maps.md", "privacy-policy.md",
                "ai-disclosure-notice.md"):
        text = (_GOV / rel).read_text(encoding="utf-8")
        for m in _PATHLIKE.finditer(text):
            if not (_REPO / m.group(1)).exists():
                missing.append(f"{rel}: {m.group(1)}")
    assert missing == [], "\n".join(missing)


# ---------------------------------------------------------------------------
# Rollup — catalog flips + POA&M closure
# ---------------------------------------------------------------------------

def test_qt_pf_controls_now_implemented_in_catalog():
    cat = {c["id"]: c for c in _load("control-catalog.yaml")["controls"]}
    done = [f"LG-QT-{i:02d}" for i in (1, 2, 4, 5, 6, 7, 8, 9)]
    done += [f"LG-PF-{i:02d}" for i in range(1, 8)]
    for cid in done:
        assert cat[cid]["status"] == "implemented", \
            f"{cid}: {cat[cid]['status']}"
    # PF-08/09 were planned at P4.4; they land at P5.2 (accept either state so
    # this P4.4 test does not regress once P5.2 flips them).
    for cid in ("LG-PF-08", "LG-PF-09"):
        assert cat[cid]["status"] in ("planned", "implemented")


def test_poam_p4_qms_closed():
    poam = {i["id"]: i for i in _load("poam.yaml")["items"]}
    assert poam["POAM-P4-QMS"]["status"] == "closed"
