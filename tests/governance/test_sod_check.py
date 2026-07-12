"""Separation-of-Duties gate tests (LG-GV-04/05, P1.6)."""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import sod_check  # noqa: E402


def _future_iso() -> str:
    return (datetime.date.today() + datetime.timedelta(days=365)).isoformat()


def _past_iso() -> str:
    return (datetime.date.today() - datetime.timedelta(days=1)).isoformat()


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
         "justification": "eval", "owner": "jdavis@x", "review_by": _future_iso()},
    ],
}

# A binding set that triggers ONLY the waivable caio/ai_risk_owner conflict.
_CAIO_CONFLICT_BINDINGS = {
    "approver": "app@x", "engineer": "eng@y", "auditor": "a@y",
    "killswitch_owner": "k@z", "caio": "jdavis@x", "ai_risk_owner": "jdavis@x",
}


def _roles_with_deviation(**overrides):
    dev = {"conflict": ["caio", "ai_risk_owner"], "principal": "jdavis@x",
           "justification": "eval", "owner": "jdavis@x",
           "review_by": _future_iso()}
    dev.update(overrides)
    return {**_ROLES, "sod_deviations": [dev]}


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


def test_shipped_deviations_are_complete_and_owned():
    """Time-ROBUST structural guard on the shipped deviations.

    The clean-gate tests below are date-DEPENDENT because a deviation expires at
    its review_by. This guard is not: it asserts every shipped sod_deviations
    entry carries a conflict pair, a bound principal, a nonempty owner, a
    nonempty justification, and a well-formed review_by. Diagnostic: if a
    clean-gate test fails while THIS one still passes, the cause is almost
    certainly an EXPIRED deviation (review_by has passed) — re-review it and
    renew the date in roles.yaml. That is the control working, not a code
    regression.
    """
    roles = yaml.safe_load((_REPO / "docs/governance/roles.yaml").read_text())
    devs = roles.get("sod_deviations") or []
    assert devs, "expected tracked single-operator deviations in roles.yaml"
    for d in devs:
        assert len(d.get("conflict") or []) == 2, d
        assert str(d.get("principal") or "").strip(), d
        assert str(d.get("owner") or "").strip(), d
        assert str(d.get("justification") or "").strip(), d
        assert sod_check._parse_review_by(d.get("review_by")) is not None, d


def test_shipped_roles_and_bindings_are_clean():
    """The committed roles.yaml + role_bindings must have zero BLOCKING
    conflicts (accepted deviations are allowed and tracked).

    NOTE (date-dependent): deviations expire at their review_by, so this and
    test_gate_exit_code_clean go RED once the shipped deviations expire. That is
    intended expiry enforcement — see test_shipped_deviations_are_complete_and_owned
    for the diagnostic. Renew the review_by in roles.yaml as a deliberate,
    reviewed governance action (never a rubber-stamp bump)."""
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


# ---- deviation validity: a waiver must be complete AND unexpired (LG-GV-05) --

def test_valid_unexpired_deviation_with_all_metadata_accepted():
    roles = _roles_with_deviation()  # future review_by + owner + justification
    blocking, accepted = sod_check.classify_sod(roles, _CAIO_CONFLICT_BINDINGS)
    assert any("caio" in a and "ai_risk_owner" in a for a in accepted)
    assert not any("caio" in c and "ai_risk_owner" in c for c in blocking)


def test_expired_deviation_blocks():
    roles = _roles_with_deviation(review_by=_past_iso())
    blocking, accepted = sod_check.classify_sod(roles, _CAIO_CONFLICT_BINDINGS)
    assert not any("caio" in a for a in accepted)
    assert any("caio" in c and "ai_risk_owner" in c and "expired" in c.lower()
               for c in blocking)


def test_deviation_missing_owner_blocks():
    roles = _roles_with_deviation(owner="")
    blocking, accepted = sod_check.classify_sod(roles, _CAIO_CONFLICT_BINDINGS)
    assert not any("caio" in a for a in accepted)
    assert any("caio" in c and "ai_risk_owner" in c for c in blocking)


def test_deviation_missing_justification_blocks():
    roles = _roles_with_deviation(justification="")
    blocking, accepted = sod_check.classify_sod(roles, _CAIO_CONFLICT_BINDINGS)
    assert not any("caio" in a for a in accepted)
    assert any("caio" in c and "ai_risk_owner" in c for c in blocking)


def test_deviation_missing_review_by_blocks():
    dev = {"conflict": ["caio", "ai_risk_owner"], "principal": "jdavis@x",
           "justification": "eval", "owner": "jdavis@x"}  # no review_by
    roles = {**_ROLES, "sod_deviations": [dev]}
    blocking, accepted = sod_check.classify_sod(roles, _CAIO_CONFLICT_BINDINGS)
    assert not any("caio" in a for a in accepted)
    assert any("caio" in c and "ai_risk_owner" in c for c in blocking)


def test_deviation_malformed_review_by_blocks():
    roles = _roles_with_deviation(review_by="not-a-date")
    blocking, accepted = sod_check.classify_sod(roles, _CAIO_CONFLICT_BINDINGS)
    assert not any("caio" in a for a in accepted)
    assert any("caio" in c and "ai_risk_owner" in c for c in blocking)


def test_deviation_review_by_as_yaml_date_object_accepted():
    """PyYAML parses an unquoted ISO date (review_by: 2026-10-11) as a
    datetime.date, not a str — the checker must accept a date object too."""
    future = datetime.date.today() + datetime.timedelta(days=365)
    roles = _roles_with_deviation(review_by=future)
    _, accepted = sod_check.classify_sod(roles, _CAIO_CONFLICT_BINDINGS)
    assert any("caio" in a and "ai_risk_owner" in a for a in accepted)


def test_deviation_expired_date_object_blocks():
    past = datetime.date.today() - datetime.timedelta(days=1)
    roles = _roles_with_deviation(review_by=past)
    _, accepted = sod_check.classify_sod(roles, _CAIO_CONFLICT_BINDINGS)
    assert not any("caio" in a for a in accepted)
