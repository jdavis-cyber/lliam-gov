"""delegation.max_spawn_depth enforcement (in-process, cross-process, strict).

Covers agent/delegation_depth.py and the delegate_tool / run_agent / subprocess
env wiring: depth-limit refusal, inherited depth from a spawning process, the
strict-posture governed ceiling, and fail-closed behaviour when the depth (or
the governed limit) cannot be determined.
"""

from __future__ import annotations

import json
import threading
from unittest.mock import MagicMock, patch

import pytest

from agent import delegation_depth as dd
from tools import delegate_tool as dt


def _parent(depth=0):
    parent = MagicMock()
    parent.base_url = "https://openrouter.ai/api/v1"
    parent.api_key = "***"
    parent.provider = "openrouter"
    parent.api_mode = "chat_completions"
    parent.model = "anthropic/claude-sonnet-4"
    parent.platform = "cli"
    parent._session_db = None
    parent._delegate_depth = depth
    parent._active_children = []
    parent._active_children_lock = threading.Lock()
    parent._print_fn = None
    parent.tool_progress_callback = None
    parent.thinking_callback = None
    return parent


@pytest.fixture
def strict(monkeypatch):
    """Strict posture with a governed (overlay) max_spawn_depth of 3."""
    governed = {"security": {"posture": "strict"}, "delegation": {"max_spawn_depth": 3}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: governed)
    return governed


# --------------------------------------------------------------------------- #
# agent/delegation_depth.py
# --------------------------------------------------------------------------- #

def test_inherited_depth_absent_is_zero(monkeypatch):
    monkeypatch.delenv(dd.ENV_VAR, raising=False)
    assert dd.inherited_depth() == 0


@pytest.mark.parametrize("raw", ["abc", "-1", "1.5", "invalid", "99999"])
def test_inherited_depth_malformed_raises(monkeypatch, raw):
    monkeypatch.setenv(dd.ENV_VAR, raw)
    with pytest.raises(dd.DelegationDepthError):
        dd.inherited_depth()


def test_effective_depth_adds_inherited_and_local(monkeypatch):
    monkeypatch.setenv(dd.ENV_VAR, "2")
    agent = MagicMock()
    agent._delegate_depth = 1
    assert dd.effective_depth(agent) == 3


def test_subprocess_env_is_untouched_outside_an_agent_turn(monkeypatch):
    monkeypatch.delenv(dd.ENV_VAR, raising=False)
    env = {}
    dd.apply_subprocess_depth_env(env)
    assert dd.ENV_VAR not in env


def test_subprocess_env_carries_depth_plus_one_inside_a_turn(monkeypatch):
    monkeypatch.setenv(dd.ENV_VAR, "1")
    agent = MagicMock()
    agent._delegate_depth = 1
    with dd.agent_depth_scope(agent) as depth:
        assert depth == 2
        env = {}
        dd.apply_subprocess_depth_env(env)
    assert env[dd.ENV_VAR] == "3"


def test_subprocess_env_propagates_unknown_depth_as_invalid(monkeypatch):
    monkeypatch.setenv(dd.ENV_VAR, "garbage")
    agent = MagicMock()
    agent._delegate_depth = 0
    with dd.agent_depth_scope(agent) as depth:
        assert depth is None
        env = {}
        dd.apply_subprocess_depth_env(env)
    assert env[dd.ENV_VAR] == dd.INVALID_MARKER


def test_terminal_run_env_carries_depth(monkeypatch):
    """The terminal tool's env builder stamps the child depth."""
    from tools.environments.local import _make_run_env, _sanitize_subprocess_env

    monkeypatch.delenv(dd.ENV_VAR, raising=False)
    agent = MagicMock()
    agent._delegate_depth = 2
    with dd.agent_depth_scope(agent):
        assert _make_run_env({})[dd.ENV_VAR] == "3"
        assert _sanitize_subprocess_env({"PATH": "/bin"})[dd.ENV_VAR] == "3"


# --------------------------------------------------------------------------- #
# delegate_task refusal
# --------------------------------------------------------------------------- #

def test_inherited_depth_counts_toward_the_limit(monkeypatch):
    """A top-level agent in a process spawned at the floor cannot delegate."""
    monkeypatch.setenv(dd.ENV_VAR, "1")
    with patch.object(dt, "_load_config", return_value={"max_spawn_depth": 1}):
        result = json.loads(dt.delegate_task(goal="x", parent_agent=_parent(depth=0)))
    assert "depth limit reached" in result["error"].lower()
    assert "depth=1" in result["error"]


def test_strict_governed_ceiling_caps_home_config(monkeypatch, strict):
    """Under strict, a home config cannot raise the governed depth."""
    with patch.object(dt, "_load_config", return_value={"max_spawn_depth": 99}):
        assert dt._get_max_spawn_depth() == 3
        result = json.loads(dt.delegate_task(goal="x", parent_agent=_parent(depth=3)))
    assert "depth limit reached" in result["error"].lower()
    assert "max_spawn_depth=3" in result["error"]


def test_low_side_keeps_runtime_value(monkeypatch):
    with patch.object(dt, "_load_config", return_value={"max_spawn_depth": 99}):
        assert dt._get_max_spawn_depth() == 99


def test_strict_malformed_inherited_depth_fails_closed(monkeypatch, strict):
    monkeypatch.setenv(dd.ENV_VAR, "not-a-number")
    with patch.object(dt, "_load_config", return_value={"max_spawn_depth": 3}):
        result = json.loads(dt.delegate_task(goal="x", parent_agent=_parent(depth=0)))
    assert "could not be determined" in result["error"]
    assert "fail" in result["error"].lower()


def test_strict_malformed_governed_limit_fails_closed(monkeypatch):
    cfg = {"security": {"posture": "strict"}, "delegation": {"max_spawn_depth": "three"}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: cfg)
    with patch.object(dt, "_load_config", return_value={"max_spawn_depth": 3}):
        result = json.loads(dt.delegate_task(goal="x", parent_agent=_parent(depth=0)))
    assert result["error"].startswith("Delegation refused:")
    assert "max_spawn_depth" in result["error"]


def test_low_side_malformed_inherited_depth_uses_in_process_depth(monkeypatch):
    """Low-side: a malformed inherited value is logged; the limit still applies."""
    monkeypatch.setenv(dd.ENV_VAR, "not-a-number")
    with patch.object(dt, "_load_config", return_value={"max_spawn_depth": 1}):
        result = json.loads(dt.delegate_task(goal="x", parent_agent=_parent(depth=1)))
    assert "depth limit reached" in result["error"].lower()


# --------------------------------------------------------------------------- #
# Turn admission for agents started in a spawned process
# --------------------------------------------------------------------------- #

def test_turn_admission_refuses_beyond_limit_under_strict(monkeypatch, strict):
    monkeypatch.setenv(dd.ENV_VAR, "4")
    agent = MagicMock()
    agent._delegate_depth = 0
    with patch.object(dt, "_load_config", return_value={"max_spawn_depth": 3}):
        msg = dt.turn_admission_error(agent)
    assert msg and "beyond max_spawn_depth=3" in msg


def test_turn_admission_allows_the_leaf_floor(monkeypatch, strict):
    monkeypatch.setenv(dd.ENV_VAR, "3")
    agent = MagicMock()
    agent._delegate_depth = 0
    with patch.object(dt, "_load_config", return_value={"max_spawn_depth": 3}):
        assert dt.turn_admission_error(agent) is None


def test_turn_admission_fails_closed_on_unknown_depth(monkeypatch, strict):
    monkeypatch.setenv(dd.ENV_VAR, dd.INVALID_MARKER)
    agent = MagicMock()
    agent._delegate_depth = 0
    msg = dt.turn_admission_error(agent)
    assert msg and "could not be determined" in msg


def test_turn_admission_is_advisory_low_side(monkeypatch):
    monkeypatch.setenv(dd.ENV_VAR, "9")
    agent = MagicMock()
    agent._delegate_depth = 0
    with patch.object(dt, "_load_config", return_value={"max_spawn_depth": 1}):
        assert dt.turn_admission_error(agent) is None


def test_run_conversation_refuses_over_deep_agent(monkeypatch, strict):
    """AIAgent.run_conversation returns a failed result without calling the loop."""
    import run_agent

    monkeypatch.setenv(dd.ENV_VAR, "5")
    agent = MagicMock()
    agent._delegate_depth = 0
    called = []
    monkeypatch.setattr(
        "agent.conversation_loop.run_conversation",
        lambda *a, **k: called.append(1) or {"final_response": "ran"},
    )
    with patch.object(dt, "_load_config", return_value={"max_spawn_depth": 3}):
        result = run_agent.AIAgent.run_conversation(agent, "hi")
    assert called == []
    assert result["failed"] is True
    assert "max_spawn_depth=3" in result["error"]


def test_run_conversation_sets_depth_scope_for_the_turn(monkeypatch):
    import run_agent

    monkeypatch.delenv(dd.ENV_VAR, raising=False)
    agent = MagicMock()
    agent._delegate_depth = 1
    seen = {}

    def _loop(*a, **k):
        env = {}
        dd.apply_subprocess_depth_env(env)
        seen["env"] = env.get(dd.ENV_VAR)
        return {"final_response": "ok"}

    monkeypatch.setattr("agent.conversation_loop.run_conversation", _loop)
    run_agent.AIAgent.run_conversation(agent, "hi")
    assert seen["env"] == "2"
