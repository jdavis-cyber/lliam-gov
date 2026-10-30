"""P4.5 secure-dev governance tests (LG-SD-04/06, AI-497).

The go/no-go release gate (LG-SD-06) fails closed when any release
precondition is not met — godmode enabled, allowlist off, audit off,
posture not strict, authorization unsigned/expired — and CODEOWNERS covers
the governance-sensitive paths (LG-SD-04).

The prompt-injection red-team corpus (LG-SD-05) lives in
tests/governance/test_p45_redteam_corpus.py and exercises the real defenses.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import go_no_go_gate as gng  # noqa: E402

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
    gov = tmp_path / "policy" / "governed"
    gov.mkdir(parents=True)
    (gov / "authorization-record.yaml").write_text(yaml.safe_dump(auth))
    failures = gng.check_go_no_go(repo_root=tmp_path,
                                  overlay_path=_REPO / "cli-config.gov.yaml")
    assert any("expire" in f.lower() or "authorization" in f.lower()
               for f in failures)


# ---------------------------------------------------------------------------
# LG-SD-04 — CODEOWNERS peer review on governance-sensitive paths
# ---------------------------------------------------------------------------

def test_codeowners_covers_governance_paths():
    co = _REPO / ".github" / "CODEOWNERS"
    assert co.exists(), "CODEOWNERS missing"
    text = co.read_text(encoding="utf-8")
    for path in ("cli-config.gov.yaml", "policy/",
                 "ci/governance-ci-gates/", "lliam_cli/security_audit_startup.py"):
        assert path in text, f"CODEOWNERS does not cover {path}"
