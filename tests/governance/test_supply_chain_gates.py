"""P3.4 — supply-chain CI gates + SBOM/AI-BOM (LG-SS-02/03/04/05/06, IN-02/03).

Locally-runnable, deterministic gates under ci/governance-ci-gates/ (the CI-
credits-independent enforcement surface):
  * supply_chain_gate.py — block .pth / base64-exec / install-hook shapes
    (LG-SS-04); exit non-zero on a hit.
  * osv_gate.py — fail on an OSV finding at/above a severity threshold
    (LG-SS-02); evaluates a results file (no network in the test).
  * generate_bom.py — produce an SBOM + a machine-readable AI-BOM
    (LG-SS-05, IN-02/03).
"""

from __future__ import annotations

import importlib.util
import textwrap
from pathlib import Path

import pytest

_GATES = Path(__file__).resolve().parents[2] / "ci" / "governance-ci-gates"


def _load(module_name: str):
    path = _GATES / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(f"_gate_{module_name}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# 1. LG-SS-04 — block .pth / base64-exec / install-hook shapes
# ---------------------------------------------------------------------------

def test_pth_file_flagged(tmp_path):
    gate = _load("supply_chain_gate")
    # A .pth artifact is flagged by extension (it auto-runs at interpreter start).
    (tmp_path / "evil.pth").write_text("import site  # placeholder", encoding="utf-8")
    findings = gate.scan_tree(tmp_path)
    assert any(f["kind"] == "pth_file" for f in findings)


def test_base64_exec_combo_flagged(tmp_path):
    gate = _load("supply_chain_gate")
    # base64-decode fed straight into a dynamic executor — the litellm attack shape.
    payload = "import base64\n" + "ex" + "ec(base64.b64decode('cA=='))\n"
    (tmp_path / "mod.py").write_text(payload, encoding="utf-8")
    findings = gate.scan_tree(tmp_path)
    assert any(f["kind"] == "base64_exec" for f in findings)


def test_multiline_base64_exec_combo_flagged(tmp_path):
    gate = _load("supply_chain_gate")
    payload = "import base64\n" + "ex" + "ec(\n base64.b64decode('cA==')\n)\n"
    (tmp_path / "mod.py").write_text(payload, encoding="utf-8")
    assert any(f["kind"] == "base64_exec" for f in gate.scan_tree(tmp_path))


def test_install_hook_flagged(tmp_path):
    gate = _load("supply_chain_gate")
    (tmp_path / "sitecustomize.py").write_text("VALUE = 1\n", encoding="utf-8")
    findings = gate.scan_tree(tmp_path)
    assert any(f["kind"] == "install_hook" for f in findings)


def test_setup_py_dynamic_execution_flagged(tmp_path):
    gate = _load("supply_chain_gate")
    (tmp_path / "setup.py").write_text("eval('1 + 1')\n", encoding="utf-8")
    assert any(f["kind"] == "install_hook" for f in gate.scan_tree(tmp_path))


def test_release_artifacts_are_scanned(tmp_path):
    gate = _load("supply_chain_gate")
    release = tmp_path / "release"
    release.mkdir()
    (release / "evil.pth").write_text("import evil\n", encoding="utf-8")
    assert any(f["kind"] == "pth_file" for f in gate.scan_tree(tmp_path))


def test_missing_scan_root_fails_closed(tmp_path):
    gate = _load("supply_chain_gate")
    assert gate.run_gate(tmp_path / "missing") != 0


def test_clean_tree_no_findings(tmp_path):
    gate = _load("supply_chain_gate")
    (tmp_path / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert gate.scan_tree(tmp_path) == []


def test_gate_exit_code_nonzero_on_finding(tmp_path):
    gate = _load("supply_chain_gate")
    (tmp_path / "evil.pth").write_text("x", encoding="utf-8")
    assert gate.run_gate(tmp_path) != 0


def test_gate_exit_code_zero_on_clean(tmp_path):
    gate = _load("supply_chain_gate")
    (tmp_path / "ok.py").write_text("y = 1\n", encoding="utf-8")
    assert gate.run_gate(tmp_path) == 0


# ---------------------------------------------------------------------------
# 2. LG-SS-02 — OSV severity gate
# ---------------------------------------------------------------------------

def test_osv_gate_fails_on_high_severity(tmp_path):
    gate = _load("osv_gate")
    results = tmp_path / "osv.json"
    results.write_text(textwrap.dedent("""
    {"results": [{"packages": [{"package": {"name": "evil-dep"},
      "vulnerabilities": [{"id": "GHSA-xxxx", "database_specific": {"severity": "HIGH"}}]}]}]}
    """), encoding="utf-8")
    rc, findings = gate.evaluate(results, fail_on="high")
    assert rc != 0
    assert any("evil-dep" in f for f in findings)


def test_osv_gate_passes_when_below_threshold(tmp_path):
    gate = _load("osv_gate")
    results = tmp_path / "osv.json"
    results.write_text(textwrap.dedent("""
    {"results": [{"packages": [{"package": {"name": "minor-dep"},
      "vulnerabilities": [{"id": "GHSA-yyyy", "database_specific": {"severity": "LOW"}}]}]}]}
    """), encoding="utf-8")
    rc, _ = gate.evaluate(results, fail_on="high")
    assert rc == 0


def test_osv_gate_passes_on_clean(tmp_path):
    gate = _load("osv_gate")
    results = tmp_path / "osv.json"
    results.write_text('{"results": []}', encoding="utf-8")
    rc, findings = gate.evaluate(results, fail_on="high")
    assert rc == 0 and findings == []


def test_osv_gate_rejects_invalid_threshold(tmp_path):
    gate = _load("osv_gate")
    results = tmp_path / "osv.json"
    results.write_text('{"results": []}', encoding="utf-8")
    rc, findings = gate.evaluate(results, fail_on="hihg")
    assert rc != 0 and "invalid" in findings[0]


def test_osv_gate_parses_critical_cvss_vector(tmp_path):
    gate = _load("osv_gate")
    results = tmp_path / "osv.json"
    results.write_text(textwrap.dedent("""
    {"results": [{"packages": [{"package": {"name": "critical-dep"},
      "vulnerabilities": [{"id": "GHSA-critical", "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
      ]}]}]}]}
    """), encoding="utf-8")
    rc, findings = gate.evaluate(results, fail_on="critical")
    assert rc != 0 and any("critical" in f.lower() for f in findings)


def test_osv_gate_does_not_promote_low_cvss_to_high(tmp_path):
    gate = _load("osv_gate")
    results = tmp_path / "osv.json"
    results.write_text(textwrap.dedent("""
    {"results": [{"packages": [{"package": {"name": "low-dep"},
      "vulnerabilities": [{"id": "GHSA-low", "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}
      ]}]}]}]}
    """), encoding="utf-8")
    rc, _ = gate.evaluate(results, fail_on="high")
    assert rc == 0


# ---------------------------------------------------------------------------
# 3. LG-SS-05 / IN-02 / IN-03 — SBOM + AI-BOM generation
# ---------------------------------------------------------------------------

def test_generate_sbom_has_components(tmp_path):
    gen = _load("generate_bom")
    repo = Path(__file__).resolve().parents[2]
    sbom = gen.build_sbom(repo)
    assert sbom.get("bomFormat") == "CycloneDX"
    assert isinstance(sbom.get("components"), list) and len(sbom["components"]) >= 1


def test_generate_ai_bom_indexes_providers_models_mcp(tmp_path):
    gen = _load("generate_bom")
    repo = Path(__file__).resolve().parents[2]
    ai_bom = gen.build_ai_bom(repo)
    # AI-BOM reconciles the P3 policy artifacts.
    assert "providers" in ai_bom and "models" in ai_bom and "mcp_servers" in ai_bom
    provider_ids = {p.get("id") for p in ai_bom["providers"]}
    assert "lmstudio" in provider_ids and "bedrock" in provider_ids
    model_ids = {m.get("id") for m in ai_bom["models"]}
    assert any("llama" in (mid or "") for mid in model_ids)
    assert {s.get("name") for s in ai_bom["skills"]} >= {"pdf", "xlsx", "docx"}


def test_generate_boms_fail_closed_on_missing_inputs(tmp_path):
    gen = _load("generate_bom")
    with pytest.raises(FileNotFoundError):
        gen.build_sbom(tmp_path)
    with pytest.raises(FileNotFoundError):
        gen.build_ai_bom(tmp_path)


def test_bom_artifacts_written(tmp_path):
    gen = _load("generate_bom")
    repo = Path(__file__).resolve().parents[2]
    sbom_path, ai_bom_path = gen.write_boms(repo, tmp_path)
    assert Path(sbom_path).is_file()
    assert Path(ai_bom_path).is_file()
