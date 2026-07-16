"""P4.3 boundary/inventory + SSP tests (LG-IN-01/04/05/06/07, AI-495).

The AI-495 acceptance criterion, machine-checked: every 800-171 r3 family in
the SSP cites a REAL, enforced config point, reconciled to what P0-P3 (and
P4.1/P4.2) actually enforce. The machine layer is
docs/governance/traceability-171r3.yaml (family -> controls -> config points),
validated by ci/governance-ci-gates/ssp_reconciliation_gate.py with the same
resolver the regulatory register uses. A second depth check: every repo path
cited in backticks by SSP.md / boundary-scope.md must exist — the SSP can
never cite a module or file that is not really there.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import ssp_reconciliation_gate as srg  # noqa: E402

_GOV = _REPO / "docs" / "governance"

_FAMILIES = [f"03.{i:02d}" for i in range(1, 18)]


def _load(rel: str):
    with open(_GOV / rel, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# Traceability matrix — all 17 families, resolving config points
# ---------------------------------------------------------------------------

def test_traceability_covers_all_17_families():
    trc = _load("traceability-171r3.yaml")
    ids = [f["family"] for f in trc["families"]]
    assert ids == _FAMILIES, f"families found: {ids}"


def test_traceability_families_complete():
    trc = _load("traceability-171r3.yaml")
    cat_ids = {c["id"] for c in _load("control-catalog.yaml")["controls"]}
    for fam in trc["families"]:
        fid = fam["family"]
        assert fam.get("title"), f"{fid}: no title"
        assert fam.get("status") in {"implemented", "inherited"}, \
            f"{fid}: bad status"
        assert fam.get("controls"), f"{fid}: no implementing controls"
        bad = [c for c in fam["controls"] if c not in cat_ids]
        assert bad == [], f"{fid}: unknown controls {bad}"
        assert fam.get("config_points"), f"{fid}: no config points"


def test_ssp_gate_passes_on_repo():
    failures = srg.check_ssp(repo_root=_REPO)
    assert failures == [], "\n".join(failures)


def test_ssp_gate_flags_dangling_config_point(tmp_path):
    gov = tmp_path / "docs" / "governance"
    gov.mkdir(parents=True)
    (gov / "traceability-171r3.yaml").write_text(yaml.safe_dump({
        "families": [{"family": "03.01", "title": "AC",
                      "status": "implemented", "controls": ["LG-AZ-01"],
                      "config_points": [{"kind": "config_key",
                                         "key": "security.nope"}]}]}))
    (gov / "SSP.md").write_text("# SSP\n### 03.01 — AC\n")
    (tmp_path / "cli-config.gov.yaml").write_text(
        "security:\n  posture: strict\n")
    failures = srg.check_ssp(repo_root=tmp_path, expected_families=["03.01"])
    assert any("03.01" in f and "nope" in f for f in failures)


def test_ssp_gate_flags_family_missing_from_ssp_md(tmp_path):
    gov = tmp_path / "docs" / "governance"
    gov.mkdir(parents=True)
    (gov / "traceability-171r3.yaml").write_text(yaml.safe_dump({
        "families": [{"family": "03.01", "title": "AC",
                      "status": "implemented", "controls": ["LG-AZ-01"],
                      "config_points": [{"kind": "config_key",
                                         "key": "security.posture"}]}]}))
    (gov / "SSP.md").write_text("# SSP\n(no family sections)\n")
    (tmp_path / "cli-config.gov.yaml").write_text(
        "security:\n  posture: strict\n")
    failures = srg.check_ssp(repo_root=tmp_path, expected_families=["03.01"])
    assert any("03.01" in f and "SSP.md" in f for f in failures)


# ---------------------------------------------------------------------------
# SSP.md — every family section present; cited repo paths actually exist
# ---------------------------------------------------------------------------

def test_ssp_md_has_all_family_sections():
    ssp = (_GOV / "SSP.md").read_text(encoding="utf-8")
    for fam in _FAMILIES:
        assert re.search(rf"^### {re.escape(fam)} ", ssp, re.M), \
            f"SSP.md missing section for {fam}"


_PATHLIKE = re.compile(r"`([A-Za-z0-9_./-]+/[A-Za-z0-9_./-]+\."
                       r"(?:py|yaml|yml|md|json|csv|conf|toml|lock))`")


def _cited_paths_exist(rel: str) -> list[str]:
    text = (_GOV / rel).read_text(encoding="utf-8")
    missing = []
    for m in _PATHLIKE.finditer(text):
        p = m.group(1)
        if p.startswith("$"):
            continue
        if not (_REPO / p).exists():
            missing.append(p)
    return sorted(set(missing))


def test_ssp_cites_only_real_paths():
    assert _cited_paths_exist("SSP.md") == []


def test_boundary_scope_cites_only_real_paths():
    assert _cited_paths_exist("boundary-scope.md") == []


# ---------------------------------------------------------------------------
# boundary-scope.md — LG-IN-01/04/05/06 content
# ---------------------------------------------------------------------------

def test_boundary_scope_covers_in_controls():
    text = (_GOV / "boundary-scope.md").read_text(encoding="utf-8")
    assert len(text) > 3000, "boundary-scope.md not substantive"
    for needle in ("LG-IN-01", "LG-IN-04", "LG-IN-05", "LG-IN-06"):
        assert needle in text, f"boundary-scope.md missing {needle}"
    # the asset/CUI map and host inventory are present as sections
    for section in ("boundary", "classification", "location", "host"):
        assert re.search(rf"^##.*{section}", text, re.M | re.I), \
            f"boundary-scope.md has no '{section}' section"


# ---------------------------------------------------------------------------
# Catalog / POA&M rollup after P4.3
# ---------------------------------------------------------------------------

def test_in_controls_now_implemented_in_catalog():
    cat = {c["id"]: c for c in _load("control-catalog.yaml")["controls"]}
    for cid in ("LG-IN-01", "LG-IN-04", "LG-IN-05", "LG-IN-06", "LG-IN-07"):
        assert cat[cid]["status"] == "implemented", \
            f"{cid}: {cat[cid]['status']}"


def test_poam_p4_docs_closed():
    poam = {i["id"]: i for i in _load("poam.yaml")["items"]}
    assert poam["POAM-P4-DOCS"]["status"] == "closed"
