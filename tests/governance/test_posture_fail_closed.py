"""JER-77: a configuration-read fault must enforce, never disable, controls.

Each safety module's strict-posture predicate is exercised with an unreadable
configuration. Low-side (readable, non-strict) behaviour is unchanged.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import control_effectiveness as ce  # noqa: E402

MODULES = ce._FAIL_CLOSED_POSTURE_MODULES


def _unreadable():
    raise OSError("synthetic configuration read fault")


@pytest.fixture
def unreadable_config(monkeypatch):
    monkeypatch.setattr("lliam_cli.config.load_config", _unreadable)


@pytest.fixture
def low_side_config(monkeypatch):
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: {})


@pytest.mark.parametrize("module_name", MODULES)
def test_config_fault_enforces_strict_controls(unreadable_config, module_name):
    module = importlib.import_module(module_name)
    assert module._is_strict() is True


@pytest.mark.parametrize("module_name", MODULES)
def test_readable_low_side_config_stays_permissive(low_side_config, module_name):
    module = importlib.import_module(module_name)
    assert module._is_strict() is False


def test_strict_status_reports_fault_separately(unreadable_config):
    from lliam_cli import posture_resolver as pr
    assert pr.strict_status() == (False, True)


def test_pdp_denies_on_config_fault(unreadable_config):
    from tools import tool_policy as tp
    tp.reset_pdp_state()
    decision = tp.evaluate_call("terminal", {"command": "ls"})
    assert decision.disposition == "deny"


def test_injection_defense_gate_active_on_config_fault(unreadable_config):
    from tools import injection_defense as inj
    # With posture unknown the defense must run rather than short-circuit to
    # the low-side no-op path.
    assert inj._is_strict()


def test_dlp_classification_active_on_config_fault(unreadable_config):
    from agent import data_protection as dp
    dp.reset_dp_state()
    assert dp._is_strict()


def test_control_effectiveness_reports_fail_closed_posture():
    assert ce.posture_fault_fails_closed() is True
    assert ce.effectiveness_report()["posture_fault_fails_closed"] is True


def test_control_effectiveness_flags_fail_open_module(monkeypatch):
    from tools import injection_defense as inj
    monkeypatch.setattr(inj, "_is_strict", lambda: False)
    assert ce.posture_fault_fails_closed() is False
