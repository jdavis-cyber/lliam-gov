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
import re
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


# ---------------------------------------------------------------------------
# 4. JER-78 — the AI-BOM never carries a hash-shaped placeholder
# ---------------------------------------------------------------------------


_REPO = Path(__file__).resolve().parents[2]
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _assert_attestable_or_marked(gen, value):
    assert gen.is_unprovisioned_marker(value) or _SHA256.match(str(value)), value
    assert "PLACEHOLDER" not in str(value).upper() or gen.is_unprovisioned_marker(value)


def test_ai_bom_marks_absent_skills_and_template_values_unprovisioned():
    gen = _load("generate_bom")
    ai_bom = gen.build_ai_bom(_REPO)
    skills = {s["name"]: s for s in ai_bom["skills"]}
    for name in ("pdf", "xlsx", "docx"):   # allowlisted but not shipped in this repo
        assert gen.is_unprovisioned_marker(skills[name]["content_hash"])
        assert "no skill directory named" in skills[name]["content_hash"]
        # model_manifest.yaml still carries the shipped template hashes.
        assert gen.is_unprovisioned_marker(skills[name]["signed_hash"])
    assert gen.is_unprovisioned_marker(ai_bom["attestations"]["manifest_signature"])
    for skill in ai_bom["skills"]:
        _assert_attestable_or_marked(gen, skill["content_hash"])
        _assert_attestable_or_marked(gen, skill["signed_hash"])


def test_committed_ai_bom_carries_no_placeholder_hashes():
    import yaml

    gen = _load("generate_bom")
    committed = yaml.safe_load((_REPO / "evidence" / "bom" / "ai-bom.yaml").read_text(encoding="utf-8"))
    for skill in committed["skills"]:
        _assert_attestable_or_marked(gen, skill["content_hash"])
        _assert_attestable_or_marked(gen, skill["signed_hash"])
    signature = committed["attestations"]["manifest_signature"]
    assert gen.is_unprovisioned_marker(signature) or "REPLACE" not in signature.upper()


def _mini_repo(tmp_path, *, skill_hash, signature):
    import yaml

    (tmp_path / "policy").mkdir()
    (tmp_path / "docs" / "governance" / "model-cards").mkdir(parents=True)
    (tmp_path / "policy" / "provider-allowlist.yaml").write_text(yaml.safe_dump({
        "providers": [{"id": "lmstudio", "provider_class": "local",
                       "data_residency": "local", "cui_eligible": True}]}), encoding="utf-8")
    (tmp_path / "docs" / "governance" / "model-cards" / "model-cards.yaml").write_text(
        yaml.safe_dump({"models": [{"id": "lmstudio/m", "provider": "lmstudio"}]}), encoding="utf-8")
    (tmp_path / "policy" / "mcp-allowlist.yaml").write_text("approved_servers: []\n", encoding="utf-8")
    (tmp_path / "policy" / "skills-allowlist.yaml").write_text(yaml.safe_dump({
        "security": {"skill_allowlist": [{"name": "notes"}, {"name": "ghost"}]}}), encoding="utf-8")
    (tmp_path / "model_manifest.yaml").write_text(yaml.safe_dump({
        "signer": "s", "signature": signature, "models": {"primary": "lmstudio/m"},
        "skill_hashes": {"notes": skill_hash, "ghost": skill_hash}}), encoding="utf-8")
    skill = tmp_path / "skills" / "productivity" / "notes"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: notes\n---\nTake notes.\n", encoding="utf-8")
    (skill / "scripts").mkdir()
    (skill / "scripts" / "run.py").write_text("print('ok')\n", encoding="utf-8")
    return skill


def test_ai_bom_computes_real_sha256_for_present_skills(tmp_path):
    gen = _load("generate_bom")
    provisioned = "sha256:" + "cd" * 32
    skill = _mini_repo(tmp_path, skill_hash=provisioned, signature="a" * 64)
    skills = {s["name"]: s for s in gen.build_ai_bom(tmp_path)["skills"]}

    computed = skills["notes"]["content_hash"]
    assert _SHA256.match(computed)
    assert computed == gen.skill_content_sha256(skill)
    (skill / "SKILL.md").write_text("---\nname: notes\n---\nTampered.\n", encoding="utf-8")
    assert gen.skill_content_sha256(skill) != computed   # content-bound
    assert skills["notes"]["signed_hash"] == provisioned  # provisioned value carried as-is
    assert gen.is_unprovisioned_marker(skills["ghost"]["content_hash"])


def test_ai_bom_marks_template_manifest_values_unprovisioned(tmp_path):
    gen = _load("generate_bom")
    _mini_repo(tmp_path, skill_hash="sha256:PLACEHOLDER-recompute-at-build",
               signature="REPLACE-WITH-PROVISIONED-SIGNATURE")
    ai_bom = gen.build_ai_bom(tmp_path)
    skills = {s["name"]: s for s in ai_bom["skills"]}
    assert gen.is_unprovisioned_marker(skills["notes"]["signed_hash"])
    assert _SHA256.match(skills["notes"]["content_hash"])   # still computed from disk
    assert gen.is_unprovisioned_marker(ai_bom["attestations"]["manifest_signature"])
