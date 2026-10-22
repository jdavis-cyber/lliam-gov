"""JER-190 — governance circuit-breaker trips the kill-switch on repeated denials."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import agent.governance_audit_hooks as gah
from agent import governance_breaker as gb


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture(autouse=True)
def _reset_breaker():
    gb.reset_for_tests()
    yield
    gb.reset_for_tests()


def _breaker(clock, threshold=5, window=60.0):
    return gb.GovernanceBreaker(threshold=threshold, window_seconds=window, clock=clock)


def test_trips_at_threshold_and_not_below(ks_home):
    clock = Clock()
    b = _breaker(clock)
    for _ in range(4):
        assert b.observe(blocked=True, session_id="s1", tool="terminal") is False
        clock.t += 1
    assert ks_home.is_engaged() is False
    assert b.observe(blocked=True, session_id="s1", tool="terminal",
                     detail="denied by PDP") is True
    st = ks_home.state()
    assert st["engaged"] is True
    assert st["actor"] == gb.ACTOR
    assert "5 consecutive blocked" in st["reason"]
    assert ks_home.guard_tool_dispatch("read_file") is not None


def test_allowed_call_resets_the_run(ks_home):
    clock = Clock()
    b = _breaker(clock)
    for _ in range(4):
        b.observe(blocked=True, session_id="s1")
    b.observe(blocked=False, session_id="s1")
    for _ in range(4):
        assert b.observe(blocked=True, session_id="s1") is False
    assert ks_home.is_engaged() is False


def test_denials_outside_the_window_do_not_count(ks_home):
    clock = Clock()
    b = _breaker(clock, threshold=5, window=60.0)
    for _ in range(4):
        b.observe(blocked=True, session_id="s1")
        clock.t += 30          # spread over 120s: never 5 inside 60s
    assert b.observe(blocked=True, session_id="s1") is False
    assert ks_home.is_engaged() is False


def test_runs_are_per_session(ks_home):
    clock = Clock()
    b = _breaker(clock)
    for _ in range(4):
        b.observe(blocked=True, session_id="a")
        b.observe(blocked=True, session_id="b")
    assert ks_home.is_engaged() is False


def test_no_double_engage_while_engaged(ks_home):
    calls = []
    b = gb.GovernanceBreaker(threshold=1, window_seconds=10, clock=Clock(),
                             engage=lambda **kw: calls.append(kw))
    ks_home.engage(reason="already", actor="isso")
    assert b.observe(blocked=True, session_id="s") is False
    assert calls == []


def test_invalid_parameters_rejected():
    with pytest.raises(ValueError):
        gb.GovernanceBreaker(threshold=0, window_seconds=10)
    with pytest.raises(ValueError):
        gb.GovernanceBreaker(threshold=3, window_seconds=0)


def test_disabled_without_config(monkeypatch):
    import lliam_cli.config as cfg
    monkeypatch.setattr(cfg, "load_config", lambda: {"security": {}})
    assert gb.get_breaker() is None
    assert gb.observe_outcome(blocked=True, session_id="s") is False


def test_built_from_the_gov_overlay(monkeypatch):
    overlay = Path(__file__).resolve().parents[2] / "cli-config.gov.yaml"
    data = yaml.safe_load(overlay.read_text(encoding="utf-8"))
    section = data["incident_response"]["circuit_breaker"]["policy_denials"]
    assert section["enabled"] is True
    import lliam_cli.config as cfg
    monkeypatch.setattr(cfg, "load_config", lambda: data)
    b = gb.get_breaker()
    assert b is not None
    assert b.threshold == section["threshold"]
    assert b.window_seconds == float(section["window_seconds"])


def test_record_outcome_feeds_the_breaker(ks_home, monkeypatch):
    clock = Clock()
    gb.set_breaker_for_tests(_breaker(clock, threshold=3))
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: None)
    for _ in range(2):
        gah.record_outcome(function_name="terminal", function_args={},
                           status="blocked", error_type="guardrail_block",
                           error_message="denied", session_id="s1")
    assert ks_home.is_engaged() is False
    gah.record_outcome(function_name="terminal", function_args={},
                       status="blocked", error_type="guardrail_block",
                       error_message="denied", session_id="s1")
    assert ks_home.is_engaged() is True


def test_record_outcome_success_resets(ks_home, monkeypatch):
    gb.set_breaker_for_tests(_breaker(Clock(), threshold=3))
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: None)
    for status in ("blocked", "blocked", "ok", "blocked", "blocked"):
        gah.record_outcome(function_name="terminal", function_args={},
                           status=status, session_id="s1")
    assert ks_home.is_engaged() is False
