"""P4.1 governance-artifacts gate tests (LG-GV-01/03/06/10, AI-493).

Exercises enforce_governance_artifacts_at_startup — the top-management
mandatory-artifacts check: AI policy identity, go/no-go authorization record,
CAIO waiver register, and regulatory register, fail-closed under strict
posture and a complete no-op on the low-side posture. Also reconciles the
REAL repo regulatory register: every obligation's control bindings must
resolve to real enforced config points (the AI-493 acceptance criterion).
"""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

import pytest
import yaml

import lliam_cli.security_audit_startup as sas

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import regulatory_reconciliation_gate as rrg  # noqa: E402


def _future() -> str:
    return (datetime.date.today() + datetime.timedelta(days=365)).isoformat()


def _past() -> str:
    return (datetime.date.today() - datetime.timedelta(days=1)).isoformat()


# ---------------------------------------------------------------------------
# Synthetic-artifact helpers (tmp_path repo layout)
# ---------------------------------------------------------------------------

def _write_artifacts(root: Path, *, auth_overrides: dict | None = None,
                     waivers: list | None = None,
                     never_waivable: list | None = None,
                     baseline_denied: list | None = None) -> None:
    gov = root / "docs" / "governance"
    gov.mkdir(parents=True, exist_ok=True)
    (gov / "ai-policy.md").write_text("# AI Policy (test)\n")

    auth = {
        "schema": "lg-gv/1",
        "authorization_id": "LG-ATO-2026-001",
        "decision": "authorized",
        "authorizing_official": {"role": "approver",
                                 "principal": "jdavis@agency.mil"},
        "risk_acceptance": {"signed_by": "jdavis@agency.mil",
                            "date": "2026-07-16"},
        "baseline": {"git_tag": "gov-P3-good", "git_commit": "e92b6f35"},
        "issued": "2026-07-16",
        "expires": _future(),
    }
    auth.update(auth_overrides or {})
    (gov / "authorization-record.yaml").write_text(yaml.safe_dump(auth))

    reg = {"schema": "lg-gv/1", "obligations": [
        {"id": "REG-TEST-1", "source": "DFARS 252.204-7012(b)",
         "obligation": "test", "controls": ["LG-CH-01"], "status": "implemented",
         "config_points": [{"kind": "config_key", "key": "security.posture"}]},
    ]}
    (gov / "regulatory-register.yaml").write_text(yaml.safe_dump(reg))

    wav = {
        "schema": "lg-gv/1",
        "never_waivable": (never_waivable if never_waivable is not None
                           else ["godmode", "obliteratus"]),
        "baseline_denied_skills": (baseline_denied if baseline_denied is not None
                                   else ["godmode", "obliteratus",
                                         "web-pentest", "sherlock"]),
        "waivers": waivers or [],
    }
    (gov / "waiver-register.yaml").write_text(yaml.safe_dump(wav))


def _cfg(**gov_overrides) -> dict:
    governance = {
        "policy_id": "LG-POL-001",
        "policy_version": "1.0",
        "policy_approved_by": "jdavis@agency.mil",
        "policy_review_date": _future(),
        "policy_path": "docs/governance/ai-policy.md",
        "authorization_id": "LG-ATO-2026-001",
        "registers": {
            "regulatory": "docs/governance/regulatory-register.yaml",
            "authorization": "docs/governance/authorization-record.yaml",
            "waiver": "docs/governance/waiver-register.yaml",
        },
    }
    governance.update(gov_overrides)
    return {
        "security": {"posture": "strict"},
        "skills": {"disabled": ["godmode", "obliteratus",
                                "web-pentest", "sherlock"]},
        "governance": governance,
    }


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    # Each test drives strictness through its own config; the merged-config
    # fallback must not see the developer's real home config. Reset the
    # once-per-process latch so every test exercises the gate.
    monkeypatch.setattr("lliam_cli.config.load_config",
                        lambda: {"security": {"posture": "strict"}})
    monkeypatch.setattr(sas, "_GOVERNANCE_ARTIFACTS_CHECKED", False,
                        raising=False)
    yield


# ---------------------------------------------------------------------------
# Low-side: complete no-op
# ---------------------------------------------------------------------------

def test_non_strict_is_complete_noop(tmp_path, monkeypatch):
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: {})
    cfg = {"security": {"posture": "permissive"}}  # nothing else present
    assert sas.enforce_governance_artifacts_at_startup(
        config=cfg, repo_root=tmp_path) is None


# ---------------------------------------------------------------------------
# Strict + valid artifacts: passes (capability preserved)
# ---------------------------------------------------------------------------

def test_strict_with_valid_artifacts_passes(tmp_path):
    _write_artifacts(tmp_path)
    assert sas.enforce_governance_artifacts_at_startup(
        config=_cfg(), repo_root=tmp_path) is None


# ---------------------------------------------------------------------------
# LG-GV-01 — policy identity, fail-closed on absent/placeholder/past-due
# ---------------------------------------------------------------------------

def test_missing_governance_block_blocks(tmp_path):
    _write_artifacts(tmp_path)
    cfg = _cfg()
    del cfg["governance"]
    with pytest.raises(sas.GovernanceArtifactError, match="governance"):
        sas.enforce_governance_artifacts_at_startup(config=cfg,
                                                    repo_root=tmp_path)


@pytest.mark.parametrize("field,value", [
    ("policy_id", ""),
    ("policy_id", None),
    ("policy_approved_by", "PENDING"),
    ("policy_approved_by", "REPLACE_ME"),
    ("policy_version", "${POLICY_VERSION}"),
])
def test_placeholder_policy_identity_blocks(tmp_path, field, value):
    _write_artifacts(tmp_path)
    with pytest.raises(sas.GovernanceArtifactError, match=field):
        sas.enforce_governance_artifacts_at_startup(
            config=_cfg(**{field: value}), repo_root=tmp_path)


def test_past_due_policy_review_date_blocks(tmp_path):
    _write_artifacts(tmp_path)
    with pytest.raises(sas.GovernanceArtifactError, match="review"):
        sas.enforce_governance_artifacts_at_startup(
            config=_cfg(policy_review_date=_past()), repo_root=tmp_path)


def test_missing_policy_file_blocks(tmp_path):
    _write_artifacts(tmp_path)
    (tmp_path / "docs/governance/ai-policy.md").unlink()
    with pytest.raises(sas.GovernanceArtifactError, match="ai-policy"):
        sas.enforce_governance_artifacts_at_startup(
            config=_cfg(), repo_root=tmp_path)


# ---------------------------------------------------------------------------
# LG-GV-06 — authorization record, fail-closed
# ---------------------------------------------------------------------------

def test_missing_authorization_record_blocks(tmp_path):
    _write_artifacts(tmp_path)
    (tmp_path / "docs/governance/authorization-record.yaml").unlink()
    with pytest.raises(sas.GovernanceArtifactError, match="authorization"):
        sas.enforce_governance_artifacts_at_startup(
            config=_cfg(), repo_root=tmp_path)


def test_expired_authorization_blocks(tmp_path):
    _write_artifacts(tmp_path, auth_overrides={"expires": _past()})
    with pytest.raises(sas.GovernanceArtifactError, match="expire"):
        sas.enforce_governance_artifacts_at_startup(
            config=_cfg(), repo_root=tmp_path)


def test_authorization_id_mismatch_blocks(tmp_path):
    _write_artifacts(tmp_path, auth_overrides={"authorization_id": "OTHER-9"})
    with pytest.raises(sas.GovernanceArtifactError, match="authorization_id"):
        sas.enforce_governance_artifacts_at_startup(
            config=_cfg(), repo_root=tmp_path)


def test_non_authorized_decision_blocks(tmp_path):
    _write_artifacts(tmp_path, auth_overrides={"decision": "denied"})
    with pytest.raises(sas.GovernanceArtifactError, match="decision"):
        sas.enforce_governance_artifacts_at_startup(
            config=_cfg(), repo_root=tmp_path)


# ---------------------------------------------------------------------------
# LG-GV-10 — waiver gate: high-risk enablement needs a valid CAIO waiver
# ---------------------------------------------------------------------------

def _enable(cfg: dict, skill: str) -> dict:
    cfg["skills"]["disabled"] = [s for s in cfg["skills"]["disabled"]
                                 if s != skill]
    return cfg


def test_missing_waiver_register_blocks(tmp_path):
    _write_artifacts(tmp_path)
    (tmp_path / "docs/governance/waiver-register.yaml").unlink()
    with pytest.raises(sas.GovernanceArtifactError, match="waiver"):
        sas.enforce_governance_artifacts_at_startup(
            config=_cfg(), repo_root=tmp_path)


def test_high_risk_enablement_without_waiver_blocks(tmp_path):
    _write_artifacts(tmp_path)
    with pytest.raises(sas.GovernanceArtifactError, match="web-pentest"):
        sas.enforce_governance_artifacts_at_startup(
            config=_enable(_cfg(), "web-pentest"), repo_root=tmp_path)


def test_high_risk_enablement_with_valid_waiver_passes(tmp_path):
    _write_artifacts(tmp_path, waivers=[{
        "waiver_id": "LG-WVR-2026-001", "capability": "web-pentest",
        "justification": "authorized red-team mission",
        "compensating_controls": ["scoped egress allowlist"],
        "signed_by": "jdavis@agency.mil", "granted": "2026-07-16",
        "expires": _future()}])
    assert sas.enforce_governance_artifacts_at_startup(
        config=_enable(_cfg(), "web-pentest"), repo_root=tmp_path) is None


def test_expired_waiver_blocks(tmp_path):
    _write_artifacts(tmp_path, waivers=[{
        "waiver_id": "LG-WVR-2026-001", "capability": "web-pentest",
        "justification": "expired mission",
        "signed_by": "jdavis@agency.mil", "granted": "2026-01-01",
        "expires": _past()}])
    with pytest.raises(sas.GovernanceArtifactError, match="web-pentest"):
        sas.enforce_governance_artifacts_at_startup(
            config=_enable(_cfg(), "web-pentest"), repo_root=tmp_path)


def test_unsigned_waiver_blocks(tmp_path):
    _write_artifacts(tmp_path, waivers=[{
        "waiver_id": "LG-WVR-2026-001", "capability": "web-pentest",
        "justification": "no signer", "signed_by": "PENDING",
        "granted": "2026-07-16", "expires": _future()}])
    with pytest.raises(sas.GovernanceArtifactError, match="web-pentest"):
        sas.enforce_governance_artifacts_at_startup(
            config=_enable(_cfg(), "web-pentest"), repo_root=tmp_path)


def test_godmode_is_never_waivable(tmp_path):
    """Even a signed, unexpired waiver cannot re-enable godmode (LG-SC-01)."""
    _write_artifacts(tmp_path, waivers=[{
        "waiver_id": "LG-WVR-2026-666", "capability": "godmode",
        "justification": "attempted jailbreak waiver",
        "signed_by": "jdavis@agency.mil", "granted": "2026-07-16",
        "expires": _future()}])
    with pytest.raises(sas.GovernanceArtifactError, match="godmode"):
        sas.enforce_governance_artifacts_at_startup(
            config=_enable(_cfg(), "godmode"), repo_root=tmp_path)


# ---------------------------------------------------------------------------
# LG-GV-03 — the REAL repo regulatory register reconciles to enforcement
# ---------------------------------------------------------------------------

def test_repo_regulatory_register_fully_resolves():
    failures = rrg.check_register(repo_root=_REPO)
    assert failures == [], "\n".join(failures)


def test_repo_governance_block_binds_real_artifacts():
    failures = rrg.check_governance_bindings(repo_root=_REPO)
    assert failures == [], "\n".join(failures)


def test_reconciliation_gate_flags_unbound_obligation(tmp_path):
    gov = tmp_path / "docs" / "governance"
    gov.mkdir(parents=True)
    (gov / "regulatory-register.yaml").write_text(yaml.safe_dump(
        {"schema": "lg-gv/1", "obligations": [
            {"id": "REG-X", "source": "s", "obligation": "o",
             "controls": [], "status": "implemented",
             "config_points": []}]}))
    (tmp_path / "cli-config.gov.yaml").write_text("security:\n  posture: strict\n")
    failures = rrg.check_register(repo_root=tmp_path)
    assert any("REG-X" in f for f in failures)


def test_reconciliation_gate_flags_dangling_config_key(tmp_path):
    gov = tmp_path / "docs" / "governance"
    gov.mkdir(parents=True)
    (gov / "regulatory-register.yaml").write_text(yaml.safe_dump(
        {"schema": "lg-gv/1", "obligations": [
            {"id": "REG-Y", "source": "s", "obligation": "o",
             "controls": ["LG-CH-01"], "status": "implemented",
             "config_points": [{"kind": "config_key",
                                "key": "security.nonexistent_key"}]}]}))
    (tmp_path / "cli-config.gov.yaml").write_text("security:\n  posture: strict\n")
    failures = rrg.check_register(repo_root=tmp_path)
    assert any("REG-Y" in f and "nonexistent_key" in f for f in failures)


def test_partial_obligation_requires_poam_ref(tmp_path):
    gov = tmp_path / "docs" / "governance"
    gov.mkdir(parents=True)
    (gov / "regulatory-register.yaml").write_text(yaml.safe_dump(
        {"schema": "lg-gv/1", "obligations": [
            {"id": "REG-Z", "source": "s", "obligation": "o",
             "controls": ["LG-IR-01"], "status": "partial",
             "config_points": [{"kind": "config_key",
                                "key": "security.posture"}]}]}))
    (tmp_path / "cli-config.gov.yaml").write_text("security:\n  posture: strict\n")
    failures = rrg.check_register(repo_root=tmp_path)
    assert any("REG-Z" in f and "poam" in f.lower() for f in failures)


# ---------------------------------------------------------------------------
# Live wiring — the gate is invoked on the production startup path
# ---------------------------------------------------------------------------

def test_gateway_startup_wires_governance_artifacts_gate():
    src = (_REPO / "gateway" / "run.py").read_text()
    assert "enforce_governance_artifacts_at_startup" in src
    assert "GovernanceArtifactError" in src
