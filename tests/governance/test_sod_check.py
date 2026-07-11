"""Separation-of-Duties gate tests (LG-GV-04/05, P1.6)."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import sod_check  # noqa: E402


_ROLES = {
    "separation_of_duties": [
        {"role": "approver", "not_also": ["engineer"], "waivable": False,
         "rationale": "AC-5"},
        {"role": "auditor", "not_also": ["approver", "engineer", "ai_risk_owner"],
         "waivable": False, "rationale": "independence"},
        {"role": "caio", "not_also": ["ai_risk_owner"], "waivable": True,
         "rationale": "self-acceptance"},
    ],
    "required_bindings": ["approver", "auditor", "killswitch_owner"],
    "sod_deviations": [
        {"conflict": ["caio", "ai_risk_owner"], "principal": "jdavis@x",
         "justification": "eval", "owner": "jdavis@x", "review_by": "2026-10-11"},
    ],
}


def test_clean_bindings_have_no_conflicts():
    bindings = {
        "approver": "jdavis@x", "engineer": "npe:lliam-gov",
        "auditor": "auditor@independent", "killswitch_owner": "jdavis@x",
    }
    assert sod_check.check_sod(_ROLES, bindings) == []


def test_approver_equals_engineer_is_nonwaivable_conflict():
    bindings = {"approver": "jdavis@x", "engineer": "jdavis@x",
                "auditor": "a@y", "killswitch_owner": "k@z"}
    conflicts = sod_check.check_sod(_ROLES, bindings)
    assert any("approver" in c and "engineer" in c and "NON-WAIVABLE" in c
               for c in conflicts)


def test_nonwaivable_conflict_cannot_be_deviated():
    """Even with a sod_deviations entry, a NON-WAIVABLE rule stays blocking."""
    roles = {
        "separation_of_duties": [
            {"role": "approver", "not_also": ["engineer"], "waivable": False,
             "rationale": "AC-5"},
        ],
        "required_bindings": [],
        "sod_deviations": [
            {"conflict": ["approver", "engineer"], "principal": "jdavis@x",
             "justification": "nice try", "owner": "jdavis@x"},
        ],
    }
    bindings = {"approver": "jdavis@x", "engineer": "jdavis@x"}
    assert sod_check.check_sod(roles, bindings)  # still blocking


def test_waivable_conflict_with_deviation_is_accepted():
    bindings = {"approver": "a@y", "engineer": "npe", "auditor": "au@z",
                "killswitch_owner": "k@z",
                "caio": "jdavis@x", "ai_risk_owner": "jdavis@x"}
    blocking, accepted = sod_check.classify_sod(_ROLES, bindings)
    assert blocking == []
    assert any("caio" in a and "ai_risk_owner" in a for a in accepted)


def test_waivable_conflict_without_deviation_blocks():
    roles = dict(_ROLES)
    roles = {**_ROLES, "sod_deviations": []}  # remove the accepted deviation
    bindings = {"approver": "a@y", "engineer": "npe", "auditor": "au@z",
                "killswitch_owner": "k@z",
                "caio": "jdavis@x", "ai_risk_owner": "jdavis@x"}
    conflicts = sod_check.check_sod(roles, bindings)
    assert any("caio" in c and "ai_risk_owner" in c and "NO tracked" in c
               for c in conflicts)


def test_unbound_required_role_is_conflict():
    bindings = {"approver": "jdavis@x", "engineer": "npe:lliam",
                "auditor": "a@y"}  # killswitch_owner missing
    conflicts = sod_check.check_sod(_ROLES, bindings)
    assert any("killswitch_owner" in c for c in conflicts)


def test_missing_sod_rules_fails_closed():
    """A renamed/emptied separation_of_duties must NOT read as 'clean'."""
    assert sod_check.check_sod({"required_bindings": []}, {})
    assert sod_check.check_sod({"separation_of_duties": [], "required_bindings": []}, {})


def test_case_insensitive_conflict_detection():
    bindings = {"approver": "JDavis@X", "engineer": "jdavis@x",
                "auditor": "a@y", "killswitch_owner": "k@z"}
    conflicts = sod_check.check_sod(_ROLES, bindings)
    assert any("approver" in c and "engineer" in c for c in conflicts)


# ---- shipped-file assertions (the recurring test-shape ≠ shipped-shape guard) --

def test_shipped_roles_declare_the_security_critical_rules():
    """Regression guard: the real roles.yaml must CONTAIN the non-waivable
    Approver≠Engineer and Auditor-independence rules — weakening the rule set
    must fail a test, not pass silently."""
    roles = yaml.safe_load((_REPO / "docs/governance/roles.yaml").read_text())
    rules = roles["separation_of_duties"]
    approver_eng = next(r for r in rules
                        if r["role"] == "approver" and "engineer" in r["not_also"])
    assert approver_eng.get("waivable") is False
    auditor = next(r for r in rules if r["role"] == "auditor")
    assert auditor.get("waivable") is False
    for indep in ("approver", "engineer"):
        assert indep in auditor["not_also"]


def test_shipped_roles_and_bindings_are_clean():
    """The committed roles.yaml + role_bindings must have zero BLOCKING
    conflicts (accepted deviations are allowed and tracked)."""
    roles = yaml.safe_load((_REPO / "docs/governance/roles.yaml").read_text())
    overlay = yaml.safe_load((_REPO / "cli-config.gov.yaml").read_text())
    bindings = (overlay.get("governance") or {}).get("role_bindings") or {}
    blocking, accepted = sod_check.classify_sod(roles, bindings)
    assert blocking == []
    assert len(accepted) == 2  # the two tracked single-operator deviations


def test_gate_exit_code_clean():
    assert sod_check.main([
        "--roles", str(_REPO / "docs/governance/roles.yaml"),
        "--overlay", str(_REPO / "cli-config.gov.yaml"),
    ]) == 0
