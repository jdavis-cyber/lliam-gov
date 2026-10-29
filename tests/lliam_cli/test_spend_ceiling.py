"""Inference spend ceiling (security.spend_ceiling) — lliam_cli/model_cost_guard.py.

Breach routes to HITL approval; approval buys one more increment; denial,
timeout, a subagent thread or a missing approver stops further calls.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from lliam_cli import model_cost_guard as mcg


@pytest.fixture(autouse=True)
def _reset():
    mcg.reset_spend_state()
    yield
    mcg.reset_spend_state()


def _cfg(**kw):
    block = {"enabled": True, "per_session_tokens": 1000}
    block.update(kw)
    return {"security": {"spend_ceiling": block}}


def _use(monkeypatch, cfg_dict):
    cfg = mcg.load_spend_ceiling(cfg_dict)
    monkeypatch.setattr(mcg, "load_spend_ceiling", lambda config=None: cfg)
    return cfg


def _agent(depth=0, db=None):
    agent = MagicMock()
    agent._delegate_depth = depth
    agent._session_db = db
    agent._spend_tracker = None
    return agent


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

def test_absent_or_disabled_is_off():
    assert mcg.load_spend_ceiling({}).enabled is False
    assert mcg.load_spend_ceiling({"security": {"spend_ceiling": {"enabled": False}}}).enabled is False


def test_shipped_overlay_values_load():
    cfg = mcg.load_spend_ceiling(_cfg(per_day_tokens=20_000_000, per_session_cost_usd=10,
                                      per_day_cost_usd=100))
    assert cfg.enabled and cfg.on_breach == "hitl_approve"
    assert cfg.per_session_tokens == 1000 and cfg.per_day_cost_usd == 100.0


@pytest.mark.parametrize(
    "block",
    [
        {"enabled": True},
        {"enabled": True, "per_session_tokens": 0},
        {"enabled": True, "per_session_tokens": "lots"},
        {"enabled": True, "per_session_tokens": 1.5},
        {"enabled": True, "per_session_tokens": True},
        {"enabled": True, "per_session_tokens": 10, "on_breach": "allow"},
    ],
)
def test_malformed_config_raises(block):
    with pytest.raises(mcg.SpendCeilingConfigError):
        mcg.load_spend_ceiling({"security": {"spend_ceiling": block}})


def test_malformed_config_fails_closed_under_strict(monkeypatch):
    def _bad(config=None):
        raise mcg.SpendCeilingConfigError("bad")

    monkeypatch.setattr(mcg, "load_spend_ceiling", _bad)
    monkeypatch.setattr("lliam_cli.config.load_config_readonly",
                        lambda: {"security": {"posture": "strict"}})
    assert "Failing closed" in mcg.check_spend_before_call(_agent())


def test_malformed_config_is_advisory_low_side(monkeypatch):
    def _bad(config=None):
        raise mcg.SpendCeilingConfigError("bad")

    monkeypatch.setattr(mcg, "load_spend_ceiling", _bad)
    monkeypatch.setattr("lliam_cli.config.load_config_readonly", lambda: {})
    assert mcg.check_spend_before_call(_agent()) is None


# --------------------------------------------------------------------------- #
# Breach handling
# --------------------------------------------------------------------------- #

def test_under_ceiling_proceeds_without_approval(monkeypatch):
    _use(monkeypatch, _cfg())
    monkeypatch.setattr(mcg, "request_spend_approval", lambda *a: pytest.fail("no approval expected"))
    agent = _agent()
    mcg.record_spend(agent, 999, None)
    assert mcg.check_spend_before_call(agent) is None


def test_breach_requests_approval_and_approval_extends(monkeypatch):
    _use(monkeypatch, _cfg())
    calls = []
    monkeypatch.setattr(mcg, "request_spend_approval",
                        lambda agent, summary, desc: calls.append(desc) or (True, "gateway"))
    recorded = []
    monkeypatch.setattr(mcg, "_record", lambda *a: recorded.append(a))
    agent = _agent()
    mcg.record_spend(agent, 1200, None)
    assert mcg.check_spend_before_call(agent) is None
    assert len(calls) == 1 and "session token ceiling reached" in calls[0]
    assert recorded[0][0] == "approve"
    # The approval buys one increment beyond current usage (1200 + 1000).
    mcg.record_spend(agent, 999, None)
    assert mcg.check_spend_before_call(agent) is None
    assert len(calls) == 1
    mcg.record_spend(agent, 1, None)
    assert mcg.check_spend_before_call(agent) is None
    assert len(calls) == 2


def test_denied_approval_stops_further_calls(monkeypatch):
    _use(monkeypatch, _cfg())
    monkeypatch.setattr(mcg, "request_spend_approval", lambda *a: (False, "gateway"))
    recorded = []
    monkeypatch.setattr(mcg, "_record", lambda *a: recorded.append(a))
    agent = _agent()
    mcg.record_spend(agent, 1000, None)
    msg = mcg.check_spend_before_call(agent)
    assert msg and msg.startswith("Stopped: inference spend ceiling reached")
    assert recorded[0][0] == "deny"
    # Still refused on the next attempt (no grant was made).
    assert mcg.check_spend_before_call(agent)


def test_no_approver_fails_closed(monkeypatch):
    """Non-interactive, non-gateway session: no approver -> deny."""
    _use(monkeypatch, _cfg())
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
    agent = _agent()
    mcg.record_spend(agent, 5000, None)
    msg = mcg.check_spend_before_call(agent)
    assert msg and "no approver is present" in msg


def test_subagent_cannot_self_approve(monkeypatch):
    _use(monkeypatch, _cfg())
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    child = _agent(depth=1)
    mcg.record_spend(child, 5000, None)
    msg = mcg.check_spend_before_call(child)
    assert msg and "subagents cannot obtain spend approval" in msg


def test_on_breach_deny_never_asks(monkeypatch):
    _use(monkeypatch, _cfg(on_breach="deny"))
    monkeypatch.setattr(mcg, "request_spend_approval", lambda *a: pytest.fail("must not ask"))
    agent = _agent()
    mcg.record_spend(agent, 1000, None)
    assert "on_breach is deny" in mcg.check_spend_before_call(agent)


def test_cli_prompt_approval(monkeypatch):
    """Interactive CLI: the thread's approval callback rules on the breach."""
    from tools import terminal_tool

    _use(monkeypatch, _cfg())
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
    seen = []

    def _cb(command, description, *, allow_permanent=True):
        seen.append((command, allow_permanent))
        return "once"

    terminal_tool.set_approval_callback(_cb)
    try:
        agent = _agent()
        mcg.record_spend(agent, 1000, None)
        assert mcg.check_spend_before_call(agent) is None
        assert seen and "spend ceiling" in seen[0][0] and seen[0][1] is False
        terminal_tool.set_approval_callback(lambda *a, **k: "deny")
        mcg.record_spend(agent, 1000, None)
        assert mcg.check_spend_before_call(agent)
    finally:
        terminal_tool.set_approval_callback(None)


def test_gateway_queue_approval(monkeypatch):
    """Gateway session: the breach is queued to the session's approval channel."""
    import threading

    from tools import approval as ap

    _use(monkeypatch, _cfg())
    monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")
    key = "spend-test-session"
    token = ap.set_current_session_key(key)
    notified = []

    def _notify(data):
        notified.append(data)
        threading.Timer(0.05, lambda: ap.resolve_gateway_approval(key, "once")).start()

    ap.register_gateway_notify(key, _notify)
    try:
        agent = _agent()
        mcg.record_spend(agent, 1000, None)
        assert mcg.check_spend_before_call(agent) is None
        assert notified and notified[0]["pattern_key"] == "spend_ceiling"
    finally:
        ap.unregister_gateway_notify(key)
        ap.reset_current_session_key(token)


def test_gateway_without_channel_fails_closed(monkeypatch):
    from tools import approval as ap

    _use(monkeypatch, _cfg())
    monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")
    token = ap.set_current_session_key("no-channel-session")
    try:
        agent = _agent()
        mcg.record_spend(agent, 1000, None)
        assert "no approval channel" in mcg.check_spend_before_call(agent)
    finally:
        ap.reset_current_session_key(token)


# --------------------------------------------------------------------------- #
# Cost, daily ceiling, delegation sharing
# --------------------------------------------------------------------------- #

def test_cost_ceiling(monkeypatch):
    _use(monkeypatch, {"security": {"spend_ceiling": {"enabled": True, "per_session_cost_usd": 1.0}}})
    monkeypatch.setattr(mcg, "request_spend_approval", lambda *a: (False, "no_approver"))
    agent = _agent()
    mcg.record_spend(agent, 10, None)          # unknown price: not counted toward cost
    assert mcg.check_spend_before_call(agent) is None
    mcg.record_spend(agent, 10, 1.25)
    assert "session cost ceiling reached ($1.25 of $1.00)" in mcg.check_spend_before_call(agent)


def test_daily_ceiling_reads_session_db(monkeypatch):
    _use(monkeypatch, {"security": {"spend_ceiling": {"enabled": True, "per_day_tokens": 5000}}})
    monkeypatch.setattr(mcg, "request_spend_approval", lambda *a: (False, "no_approver"))
    db = MagicMock()
    db.usage_since.return_value = {"tokens": 6000, "cost_usd": 0.0}
    msg = mcg.check_spend_before_call(_agent(db=db))
    assert msg and "daily token ceiling reached" in msg
    since = db.usage_since.call_args[0][0]
    assert since % 86400 == 0  # UTC midnight


def test_daily_ceiling_in_process_fallback(monkeypatch):
    _use(monkeypatch, {"security": {"spend_ceiling": {"enabled": True, "per_day_tokens": 5000}}})
    monkeypatch.setattr(mcg, "request_spend_approval", lambda *a: (False, "no_approver"))
    a1, a2 = _agent(), _agent()
    mcg.record_spend(a1, 3000, None)
    mcg.record_spend(a2, 3000, None)          # a different session, same day
    assert "daily token ceiling" in mcg.check_spend_before_call(_agent())


def test_session_db_usage_since(tmp_path):
    import time

    from lliam_state import SessionDB

    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session("s1", "cli")
    db.update_token_counts("s1", input_tokens=100, output_tokens=50,
                           cache_read_tokens=10, estimated_cost_usd=0.5)
    usage = db.usage_since(time.time() - 3600)
    assert usage == {"tokens": 160, "cost_usd": 0.5}
    assert db.usage_since(time.time() + 3600)["tokens"] == 0


def test_child_shares_parent_tracker():
    parent = _agent()
    tracker = mcg.ensure_spend_tracker(parent)
    assert mcg.ensure_spend_tracker(parent) is tracker
    child = _agent(depth=1)
    child._spend_tracker = tracker
    tracker.record(10, None)
    assert mcg.ensure_spend_tracker(child).tokens == 10


def test_cli_prompt_approval_reads_lliam_interactive(monkeypatch):
    """AI-1187: the renamed LLIAM_INTERACTIVE flag alone reaches the CLI prompt."""
    from tools import terminal_tool

    _use(monkeypatch, _cfg())
    for name in ("LLIAM_INTERACTIVE", "LLIAM_GATEWAY_SESSION", "LLIAM_EXEC_ASK"):
        monkeypatch.delenv(name, raising=False)
    seen = []

    def _cb(command, description, *, allow_permanent=True):
        seen.append(command)
        return "once"

    terminal_tool.set_approval_callback(_cb)
    try:
        agent = _agent()
        assert mcg.request_spend_approval(agent, "spend ceiling", "d") == (False, "no_approver")
        assert seen == []

        monkeypatch.setenv("LLIAM_INTERACTIVE", "1")
        assert mcg.request_spend_approval(agent, "spend ceiling", "d") == (True, "interactive_prompt")
        assert seen == ["spend ceiling"]
    finally:
        terminal_tool.set_approval_callback(None)
