"""Separation-of-Duties gate tests (LG-GV-04/05, P1.6)."""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import sod_check  # noqa: E402

_TODAY = datetime.date(2026, 7, 1)


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    """Regression tests exercise policy behavior, not current operator approval."""
    monkeypatch.setattr(sod_check, "_today", lambda: _TODAY)


def _future_iso() -> str:
    return (_TODAY + datetime.timedelta(days=365)).isoformat()


def _past_iso() -> str:
    return (_TODAY - datetime.timedelta(days=1)).isoformat()


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
    roles = yaml.safe_load((_REPO / "policy/governed/roles.yaml").read_text())
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

    Each shipped example has a conflict pair, principal, owner, justification
    and well-formed review date. The boundary tests below verify acceptance
    and expiry with a controlled clock; example dates need not be renewed to
    keep ordinary repository development working.
    """
    roles = yaml.safe_load((_REPO / "policy/governed/roles.yaml").read_text())
    devs = roles.get("sod_deviations") or []
    assert devs, "expected tracked single-operator deviations in roles.yaml"
    for d in devs:
        assert len(d.get("conflict") or []) == 2, d
        assert str(d.get("principal") or "").strip(), d
        assert str(d.get("owner") or "").strip(), d
        assert str(d.get("justification") or "").strip(), d
        assert sod_check._parse_review_by(d.get("review_by")) is not None, d


@pytest.mark.parametrize("days_after_review", [0, 1])
def test_shipped_example_expiry_boundaries(monkeypatch, days_after_review):
    """Real example files pass on review day and block after expiry, including
    the CLI exit status. No live approval is inferred from either fixture."""
    roles = yaml.safe_load((_REPO / "policy/governed/roles.yaml").read_text())
    overlay = yaml.safe_load((_REPO / "cli-config.gov.yaml").read_text())
    bindings = (overlay.get("governance") or {}).get("role_bindings") or {}
    review_dates = [sod_check._parse_review_by(d["review_by"])
                    for d in roles["sod_deviations"]]
    for review_date in sorted(set(review_dates)):
        today = review_date + datetime.timedelta(days=days_after_review)
        monkeypatch.setattr(sod_check, "_today", lambda today=today: today)
        blocking, accepted = sod_check.classify_sod(roles, bindings)
        expired = sum(date < today for date in review_dates)
        assert len(blocking) == expired
        assert all("expired review_by" in conflict for conflict in blocking)
        assert len(accepted) == len(review_dates) - expired
        assert sod_check.main([
            "--roles", str(_REPO / "policy/governed/roles.yaml"),
            "--overlay", str(_REPO / "cli-config.gov.yaml"),
        ]) == (1 if expired else 0)


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
    future = _TODAY + datetime.timedelta(days=365)
    roles = _roles_with_deviation(review_by=future)
    _, accepted = sod_check.classify_sod(roles, _CAIO_CONFLICT_BINDINGS)
    assert any("caio" in a and "ai_risk_owner" in a for a in accepted)


def test_deviation_expired_date_object_blocks():
    past = _TODAY - datetime.timedelta(days=1)
    roles = _roles_with_deviation(review_by=past)
    _, accepted = sod_check.classify_sod(roles, _CAIO_CONFLICT_BINDINGS)
    assert not any("caio" in a for a in accepted)
