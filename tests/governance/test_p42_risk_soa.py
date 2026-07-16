"""P4.2 risk / SoA / POA&M artifact tests (LG-RM-01..07,09, AI-494).

Verifies the AI-494 acceptance criteria machine-checkably:
  * the SoA lists all 188 controls with applicability + status, statuses
    reconcile to the control catalog, and godmode is excluded with a
    recorded justification;
  * the capability×impact tiering matrix cited by the risk docs IS the one
    the P2.1 PDP consumes (policy/tool-risk-policy.yaml, loaded by
    tools/tool_policy.py);
  * the M-25-21 high-impact determinations carry a SIGNED (non-placeholder)
    risk acceptance and independent reviewer;
  * every pending control and 'partial' obligation resolves to a POA&M item
    with an owner and milestone (LG-RM-07);
  * the living threat register carries the six mandatory agent-threat
    classes with owner, residual rating, and control linkage (LG-RM-02).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import soa_gate  # noqa: E402

_GOV = _REPO / "docs" / "governance"

_MANDATORY_THREAT_CLASSES = {
    "prompt_injection", "excessive_agency", "tool_mcp_abuse",
    "memory_poisoning", "provider_exfiltration", "supply_chain",
}

_PLACEHOLDER = re.compile(
    r"^\s*$|\$\{|replace|placeholder|example|changeme|pending|tbd|fixme|"
    r"\[name\]|to be completed", re.I)


def _load(rel: str):
    with open(_GOV / rel, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# Control catalog (the SoA's machine source of truth)
# ---------------------------------------------------------------------------

def test_catalog_has_188_unique_controls_across_21_domains():
    cat = _load("control-catalog.yaml")
    controls = cat["controls"]
    ids = [c["id"] for c in controls]
    assert len(ids) == 188
    assert len(set(ids)) == 188
    domains = {c["domain"] for c in controls}
    assert len(domains) == 21


def test_catalog_statuses_valid_and_pending_have_poam_ref():
    cat = _load("control-catalog.yaml")
    valid = {"implemented", "partial", "planned", "inherited"}
    for c in cat["controls"]:
        assert c["status"] in valid, f"{c['id']}: bad status {c['status']}"
        if c["status"] in ("partial", "planned"):
            assert c.get("poam_ref"), f"{c['id']}: {c['status']} without poam_ref"
        if c["status"] == "implemented":
            assert c.get("evidence"), f"{c['id']}: implemented without evidence"


def test_catalog_implemented_evidence_files_exist():
    cat = _load("control-catalog.yaml")
    missing = []
    for c in cat["controls"]:
        ev = c.get("evidence")
        if c["status"] == "implemented" and ev and ev.endswith(".md"):
            if not (_REPO / ev).exists():
                missing.append(f"{c['id']}: {ev}")
    assert missing == [], "\n".join(missing)


# ---------------------------------------------------------------------------
# SoA — all 188, statuses reconcile, godmode excluded with justification
# ---------------------------------------------------------------------------

def test_soa_gate_passes_on_repo():
    failures = soa_gate.check_soa(repo_root=_REPO)
    assert failures == [], "\n".join(failures)


def test_soa_lists_all_188_controls_with_status():
    soa = (_GOV / "SoA.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\| (LG-[A-Z]{2}-\d{2}) \|.*\| *(Implemented|"
                      r"Partially Implemented|Planned|Inherited) *\|",
                      soa, re.M)
    assert len(rows) == 188, f"SoA rows found: {len(rows)}"


def test_soa_records_godmode_exclusion_with_justification():
    soa = (_GOV / "SoA.md").read_text(encoding="utf-8")
    assert "godmode" in soa
    m = re.search(r"##.*[Ee]xclu", soa)
    assert m, "SoA has no exclusions section"
    tail = soa[m.start():]
    assert "godmode" in tail and "never waivable" in tail.lower()


# ---------------------------------------------------------------------------
# POA&M — every pending control / partial obligation resolves (LG-RM-07)
# ---------------------------------------------------------------------------

def test_poam_items_have_owner_milestone_and_valid_status():
    poam = _load("poam.yaml")
    assert poam["items"], "empty POA&M"
    for item in poam["items"]:
        assert item.get("id") and item.get("owner_role")
        assert item.get("milestone"), f"{item.get('id')}: no milestone"
        assert item.get("scheduled_step"), f"{item.get('id')}: no scheduled_step"
        assert item.get("status") in {"open", "closed"}


def test_all_catalog_poam_refs_resolve():
    cat = _load("control-catalog.yaml")
    poam = _load("poam.yaml")
    ids = {i["id"] for i in poam["items"]}
    dangling = [f"{c['id']} -> {c['poam_ref']}" for c in cat["controls"]
                if c.get("poam_ref") and c["poam_ref"] not in ids]
    assert dangling == [], "\n".join(dangling)


def test_regulatory_register_poam_refs_resolve():
    reg = _load("regulatory-register.yaml")
    poam = _load("poam.yaml")
    ids = {i["id"] for i in poam["items"]}
    for ob in reg["obligations"]:
        ref = ob.get("poam_ref", "")
        if ob.get("status") == "partial":
            token = ref.split(" ")[0].strip()
            assert token in ids, f"{ob['id']}: poam_ref '{token}' not in poam.yaml"


# ---------------------------------------------------------------------------
# Threat register — six mandatory classes, owners, residuals (LG-RM-02)
# ---------------------------------------------------------------------------

def test_threat_register_covers_mandatory_classes():
    reg = _load("threat-risk-register.yaml")
    classes = set()
    for r in reg["risks"]:
        classes.update(r.get("threat_classes") or [])
    missing = _MANDATORY_THREAT_CLASSES - classes
    assert not missing, f"missing mandatory threat classes: {missing}"


def test_threat_register_rows_complete_and_controls_resolve():
    reg = _load("threat-risk-register.yaml")
    cat_ids = {c["id"] for c in _load("control-catalog.yaml")["controls"]}
    for r in reg["risks"]:
        assert r.get("owner_role"), f"{r['id']}: no owner"
        assert r.get("inherent") and r.get("residual"), f"{r['id']}: ratings"
        assert r.get("controls"), f"{r['id']}: no control linkage"
        bad = [c for c in r["controls"] if c not in cat_ids]
        assert bad == [], f"{r['id']}: unknown controls {bad}"
        assert r.get("status") in {"open", "in_treatment", "monitored",
                                   "accepted_poam"}


# ---------------------------------------------------------------------------
# Tiering matrix — the risk docs bind to the SAME file the PDP loads
# ---------------------------------------------------------------------------

def test_tiering_matrix_is_the_pdp_policy_file():
    matrix = yaml.safe_load(
        (_REPO / "policy" / "tool-risk-policy.yaml").read_text())
    assert matrix["metadata"]["pdp_module"] == "tools/tool_policy.py"
    pdp_src = (_REPO / "tools" / "tool_policy.py").read_text()
    assert "tool-risk-policy.yaml" in pdp_src, \
        "PDP does not load policy/tool-risk-policy.yaml"


def test_risk_docs_reference_the_pdp_matrix_not_a_fork():
    for rel in ("risk-assessment-process.md", "ai-impact-assessment.md",
                "SoA.md"):
        text = (_GOV / rel).read_text(encoding="utf-8")
        assert "policy/tool-risk-policy.yaml" in text, \
            f"{rel} does not cite the PDP tiering matrix"
        assert "capability_risk_policy.yaml" not in text, \
            f"{rel} cites the retired capability_risk_policy.yaml name"


def test_determination_capabilities_consistent_with_matrix():
    det = _load("high-impact-determinations.yaml")
    matrix = yaml.safe_load(
        (_REPO / "policy" / "tool-risk-policy.yaml").read_text())
    classes = {a["class"]: a["tier"] for a in matrix["action_classes"]}
    for d in det["determinations"]:
        for cap in d.get("action_classes") or []:
            assert cap in classes, \
                f"{d['id']}: action class '{cap}' not in tool-risk-policy.yaml"


# ---------------------------------------------------------------------------
# High-impact determinations — SIGNED risk acceptance (LG-RM-05/06)
# ---------------------------------------------------------------------------

def test_determinations_signed_and_reviewed():
    det = _load("high-impact-determinations.yaml")
    assert det["determinations"], "no determinations recorded"
    for d in det["determinations"]:
        assert isinstance(d.get("high_impact"), bool), f"{d['id']}: high_impact"
        assert d.get("determination_rationale"), f"{d['id']}: rationale"
        acc = d.get("signed_acceptance") or {}
        for field in ("signed_by", "role", "date"):
            val = str(acc.get(field, ""))
            assert val and not _PLACEHOLDER.search(val), \
                f"{d['id']}: signed_acceptance.{field} missing/placeholder"
        reviewer = d.get("independent_reviewer") or {}
        for field in ("principal", "disposition", "date"):
            val = str(reviewer.get(field, ""))
            assert val and not _PLACEHOLDER.search(val), \
                f"{d['id']}: independent_reviewer.{field} missing/placeholder"


def test_impact_assessment_signature_block_executed():
    text = (_GOV / "ai-impact-assessment.md").read_text(encoding="utf-8")
    assert "_[name]_" not in text and "_[named authority]_" not in text, \
        "impact assessment signature block still has placeholders"
    assert "jdavis@agency.mil" in text


# ---------------------------------------------------------------------------
# Process + runbook docs exist and are substantive (LG-RM-01, LG-RM-09)
# ---------------------------------------------------------------------------

def test_risk_process_and_runbook_exist():
    for rel, needle in (
            ("risk-assessment-process.md", "OWASP"),
            ("halt-rollback-runbook.md", "tools/interrupt.py")):
        p = _GOV / rel
        assert p.exists(), f"{rel} missing"
        text = p.read_text(encoding="utf-8")
        assert len(text) > 1500, f"{rel} not substantive"
        assert needle in text, f"{rel} missing '{needle}'"


# ---------------------------------------------------------------------------
# soa_gate negatives — the gate actually fails closed
# ---------------------------------------------------------------------------

def _mini_repo(tmp_path, *, soa_rows, catalog_controls):
    gov = tmp_path / "docs" / "governance"
    gov.mkdir(parents=True)
    (gov / "control-catalog.yaml").write_text(yaml.safe_dump(
        {"controls": catalog_controls}))
    header = ("| Control ID | Domain | Title | Applicable | Justification "
              "| Enforcement | Status | Evidence |\n|---|---|---|---|---|---|---|---|\n")
    (gov / "SoA.md").write_text("# SoA\n\n## Exclusions\ngodmode — never "
                                "waivable\n\n" + header + soa_rows)
    (gov / "poam.yaml").write_text(yaml.safe_dump({"items": [
        {"id": "POAM-X", "owner_role": "isso", "milestone": "2026-12-01",
         "scheduled_step": "P5.1", "status": "open"}]}))
    return tmp_path


def test_soa_gate_flags_missing_control(tmp_path):
    ctl = [{"id": "LG-AU-01", "domain": "AU", "title": "t",
            "status": "implemented", "evidence": "x"},
           {"id": "LG-AU-02", "domain": "AU", "title": "t",
            "status": "planned", "poam_ref": "POAM-X"}]
    rows = "| LG-AU-01 | AU | t | Yes | j | Preventive | Implemented | x |\n"
    root = _mini_repo(tmp_path, soa_rows=rows, catalog_controls=ctl)
    failures = soa_gate.check_soa(repo_root=root, expected_total=2)
    assert any("LG-AU-02" in f for f in failures)


def test_soa_gate_flags_status_mismatch(tmp_path):
    ctl = [{"id": "LG-AU-01", "domain": "AU", "title": "t",
            "status": "planned", "poam_ref": "POAM-X"}]
    rows = "| LG-AU-01 | AU | t | Yes | j | Preventive | Implemented | x |\n"
    root = _mini_repo(tmp_path, soa_rows=rows, catalog_controls=ctl)
    failures = soa_gate.check_soa(repo_root=root, expected_total=1)
    assert any("LG-AU-01" in f and "mismatch" in f.lower() for f in failures)
