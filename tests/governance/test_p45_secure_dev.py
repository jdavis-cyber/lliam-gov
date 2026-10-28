"""P4.5 secure-dev governance + personnel/supplier tests (LG-SD-*, LG-TP-*, AI-497).

Two machine-checked acceptance criteria:
  * the go/no-go release gate (LG-SD-06) fails closed when any release
    precondition is not met — godmode enabled, allowlist off, audit off,
    encryption off, SoA/authorization unsigned/expired;
  * the evidence register (LG-TP-08) indexes every governance artifact to a
    real file, and the SD-02 requirements traceability + TP-04 shared-
    responsibility + TP-01/02 registers are present and complete.

The prompt-injection red-team corpus (LG-SD-05) lives in
tests/governance/test_p45_redteam_corpus.py and exercises the real defenses.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import go_no_go_gate as gng  # noqa: E402

_GOV = _REPO / "docs" / "governance"


def _load(rel: str):
    with open(_GOV / rel, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# LG-SD-06 — go/no-go release gate, fail-closed
# ---------------------------------------------------------------------------

def test_go_no_go_passes_on_repo():
    failures = gng.check_go_no_go(repo_root=_REPO)
    assert failures == [], "\n".join(failures)


def test_go_no_go_blocks_when_godmode_enabled(tmp_path, monkeypatch):
    overlay = _REPO / "cli-config.gov.yaml"
    data = yaml.safe_load(overlay.read_text())
    data["skills"]["disabled"] = [s for s in data["skills"]["disabled"]
                                  if s != "godmode"]
    p = tmp_path / "cli-config.gov.yaml"
    p.write_text(yaml.safe_dump(data))
    failures = gng.check_go_no_go(overlay_path=p, repo_root=_REPO)
    assert any("godmode" in f for f in failures)


def test_go_no_go_blocks_when_allowlist_off(tmp_path):
    overlay = _REPO / "cli-config.gov.yaml"
    data = yaml.safe_load(overlay.read_text())
    data["security"]["provider_allowlist_enforce"] = False
    p = tmp_path / "cli-config.gov.yaml"
    p.write_text(yaml.safe_dump(data))
    failures = gng.check_go_no_go(overlay_path=p, repo_root=_REPO)
    assert any("allowlist" in f.lower() for f in failures)


def test_go_no_go_blocks_when_audit_off(tmp_path):
    overlay = _REPO / "cli-config.gov.yaml"
    data = yaml.safe_load(overlay.read_text())
    data["audit"]["ledger_enabled"] = False
    p = tmp_path / "cli-config.gov.yaml"
    p.write_text(yaml.safe_dump(data))
    failures = gng.check_go_no_go(overlay_path=p, repo_root=_REPO)
    assert any("audit" in f.lower() for f in failures)


def test_go_no_go_blocks_when_posture_not_strict(tmp_path):
    overlay = _REPO / "cli-config.gov.yaml"
    data = yaml.safe_load(overlay.read_text())
    data["security"]["posture"] = "permissive"
    p = tmp_path / "cli-config.gov.yaml"
    p.write_text(yaml.safe_dump(data))
    failures = gng.check_go_no_go(overlay_path=p, repo_root=_REPO)
    assert any("posture" in f.lower() for f in failures)


def test_go_no_go_blocks_on_expired_authorization(tmp_path):
    # point the overlay's authorization at an expired record
    auth = {"schema": "lg-gv/1", "authorization_id": "LG-ATO-2026-001",
            "decision": "authorized",
            "authorizing_official": {"principal": "jdavis@agency.mil"},
            "expires": "2020-01-01"}
    gov = tmp_path / "docs" / "governance"
    gov.mkdir(parents=True)
    (gov / "authorization-record.yaml").write_text(yaml.safe_dump(auth))
    failures = gng.check_go_no_go(repo_root=tmp_path,
                                  overlay_path=_REPO / "cli-config.gov.yaml")
    assert any("expire" in f.lower() or "authorization" in f.lower()
               for f in failures)


# ---------------------------------------------------------------------------
# LG-TP-08 — evidence register indexes every artifact to a real file
# ---------------------------------------------------------------------------

def test_evidence_register_indexes_real_files():
    reg = _load("evidence-register.yaml")
    layers = reg["layers"]
    assert set(layers) >= {"governance", "technical", "operational",
                           "assessment", "attestation"}
    missing = []
    for layer, entries in layers.items():
        for e in entries:
            for art in (e.get("artifacts") or []):
                if not (_REPO / art).exists():
                    missing.append(f"{layer}/{e.get('control')}: {art}")
    assert missing == [], "\n".join(missing)


def test_evidence_register_maps_controls_to_artifacts():
    reg = _load("evidence-register.yaml")
    cat_ids = {c["id"] for c in _load("control-catalog.yaml")["controls"]}
    for layer, entries in reg["layers"].items():
        for e in entries:
            ctrl = e.get("control")
            assert ctrl, f"{layer}: entry without control"
            for c in (ctrl if isinstance(ctrl, list) else [ctrl]):
                assert c in cat_ids, f"{layer}: unknown control {c}"
            assert e.get("artifacts"), f"{layer}/{ctrl}: no artifacts"


# ---------------------------------------------------------------------------
# LG-SD-02 — requirements-to-control traceability
# ---------------------------------------------------------------------------

def test_requirements_traceability_complete():
    trc = _load("requirements-traceability.yaml")
    cat_ids = {c["id"] for c in _load("control-catalog.yaml")["controls"]}
    assert trc["requirements"], "no requirements captured"
    for req in trc["requirements"]:
        assert req.get("id") and req.get("statement")
        assert req.get("verification"), f"{req['id']}: no verification method"
        bad = [c for c in (req.get("controls") or []) if c not in cat_ids]
        assert bad == [], f"{req['id']}: unknown controls {bad}"


# ---------------------------------------------------------------------------
# LG-TP-04 — five-layer shared-responsibility matrix, one accountable party
# ---------------------------------------------------------------------------

def test_shared_responsibility_one_accountable_each():
    srm = _load("shared-responsibility-matrix.yaml")
    assert srm["components"], "no components"
    for comp in srm["components"]:
        acc = comp.get("accountable")
        assert acc and not isinstance(acc, list), \
            f"{comp.get('component')}: must have exactly one accountable party"
        assert comp.get("layer"), f"{comp.get('component')}: no layer"


def test_shared_responsibility_covers_five_layers():
    srm = _load("shared-responsibility-matrix.yaml")
    layers = {c["layer"] for c in srm["components"]}
    assert len(layers) >= 5, f"only {len(layers)} layers: {layers}"


# ---------------------------------------------------------------------------
# LG-SD-04 — CODEOWNERS peer review on governance-sensitive paths
# ---------------------------------------------------------------------------

def test_codeowners_covers_governance_paths():
    co = _REPO / ".github" / "CODEOWNERS"
    assert co.exists(), "CODEOWNERS missing"
    text = co.read_text(encoding="utf-8")
    for path in ("cli-config.gov.yaml", "docs/governance/", "policy/",
                 "ci/governance-ci-gates/", "lliam_cli/security_audit_startup.py"):
        assert path in text, f"CODEOWNERS does not cover {path}"


# ---------------------------------------------------------------------------
# LG-TP-01/02 — training + rules-of-behavior registers
# ---------------------------------------------------------------------------

def test_training_register_present():
    reg = _load("training-register.yaml")
    assert reg.get("required_training")
    for role in ("caio", "isso", "approver", "auditor", "killswitch_owner"):
        assert any(role in (t.get("roles") or [])
                   for t in reg["required_training"]), \
            f"no training assigned to {role}"


def test_rules_of_behavior_present():
    text = (_GOV / "rules-of-behavior.md").read_text(encoding="utf-8")
    assert len(text) > 1500
    assert "godmode" in text.lower()
    assert "kill" in text.lower()


# ---------------------------------------------------------------------------
# Rollup
# ---------------------------------------------------------------------------

def test_sd_tp_controls_now_implemented():
    cat = {c["id"]: c for c in _load("control-catalog.yaml")["controls"]}
    done = [f"LG-SD-{i:02d}" for i in range(2, 9)]
    done += ["LG-TP-01", "LG-TP-02", "LG-TP-04", "LG-TP-08"]
    for cid in done:
        assert cat[cid]["status"] == "implemented", \
            f"{cid}: {cat[cid]['status']}"


def test_poam_p4_sdlc_closed():
    poam = {i["id"]: i for i in _load("poam.yaml")["items"]}
    assert poam["POAM-P4-SDLC"]["status"] == "closed"
