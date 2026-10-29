"""AI-1172: a cron job's delegated children keep the cron approval policy.

The cron marker is context-local, so every executor hop between the cron job
and a subagent must carry the parent's context. Without that, a standalone
cron child refused despite approvals.cron_mode: approve, and a gateway-hosted
child queued approval (inherited exec-ask) with nobody listening.
"""

import json
import threading
from unittest.mock import MagicMock, patch

import pytest

import tools.approval as approval_module
from tools.delegate_tool import _run_single_child, delegate_task

DANGEROUS = "rm -rf ./build"


def _make_mock_parent():
    parent = MagicMock()
    parent.base_url = "https://openrouter.ai/api/v1"
    parent.api_key = "***"
    parent.provider = "openrouter"
    parent.api_mode = "chat_completions"
    parent.model = "anthropic/claude-sonnet-4"
    parent.platform = "cron"
    parent.providers_allowed = None
    parent.providers_ignored = None
    parent.providers_order = None
    parent.provider_sort = None
    parent._session_db = None
    parent._delegate_depth = 0
    parent._active_children = []
    parent._active_children_lock = threading.Lock()
    parent._print_fn = None
    parent.tool_progress_callback = None
    parent.thinking_callback = None
    return parent


@pytest.fixture(autouse=True)
def _env(monkeypatch, request):
    for name in ("LLIAM_INTERACTIVE", "LLIAM_GATEWAY_SESSION", "LLIAM_EXEC_ASK",
                 "LLIAM_CRON_SESSION", "LLIAM_SESSION_PLATFORM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: {"security": {}})
    monkeypatch.setattr(approval_module, "_get_approval_config", lambda: {})
    monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", False)
    approval_module._permanent_approved.clear()
    approval_module.clear_session("default")
    yield
    approval_module._permanent_approved.clear()
    approval_module.clear_session("default")


def _guard_in_worker():
    return approval_module.check_all_command_guards(DANGEROUS, "local")


def _assert_cron_policy(result, cron_mode):
    if cron_mode == "approve":
        assert result["approved"] is True, result
    else:
        assert result["approved"] is False
        assert "cron_mode" in result["message"]
    assert result.get("status") not in {"approval_required", "pending_approval"}


@pytest.mark.parametrize("exec_ask", [False, True])
@pytest.mark.parametrize("cron_mode", ["approve", "deny"])
def test_single_child_keeps_cron_policy(monkeypatch, cron_mode, exec_ask):
    if exec_ask:
        monkeypatch.setenv("LLIAM_EXEC_ASK", "1")  # inherited from a gateway host
    monkeypatch.setattr("tools.approval._get_cron_approval_mode", lambda: cron_mode)
    seen = {}

    child = MagicMock()
    child._credential_pool = None
    child.tool_progress_callback = None

    def _run_conversation(**_kw):
        seen["guard"] = _guard_in_worker()
        seen["thread"] = threading.current_thread()
        return {"final_response": "ok", "messages": [], "api_calls": 1, "completed": True}

    child.run_conversation.side_effect = _run_conversation
    token = approval_module.set_cron_session()
    try:
        _run_single_child(0, "goal", child=child, parent_agent=_make_mock_parent())
    finally:
        approval_module.reset_cron_session(token)

    assert seen["thread"] is not threading.current_thread()
    _assert_cron_policy(seen["guard"], cron_mode)


@pytest.mark.parametrize("exec_ask", [False, True])
@pytest.mark.parametrize("cron_mode", ["approve", "deny"])
def test_batch_children_keep_cron_policy(monkeypatch, cron_mode, exec_ask):
    if exec_ask:
        monkeypatch.setenv("LLIAM_EXEC_ASK", "1")
    monkeypatch.setattr("tools.approval._get_cron_approval_mode", lambda: cron_mode)
    guards = []
    lock = threading.Lock()

    def _fake_run_single_child(task_index, goal, child=None, parent_agent=None, **_kw):
        result = _guard_in_worker()
        with lock:
            guards.append(result)
        return {"task_index": task_index, "status": "completed", "summary": "ok",
                "api_calls": 1, "duration_seconds": 0.1}

    token = approval_module.set_cron_session()
    try:
        with patch("tools.delegate_tool._run_single_child", side_effect=_fake_run_single_child), \
             patch("tools.delegate_tool._build_child_agent", side_effect=lambda *a, **kw: MagicMock()):
            out = json.loads(delegate_task(
                tasks=[{"goal": "a"}, {"goal": "b"}], parent_agent=_make_mock_parent(),
            ))
    finally:
        approval_module.reset_cron_session(token)

    assert len(out["results"]) == 2
    assert len(guards) == 2
    for result in guards:
        _assert_cron_policy(result, cron_mode)


@pytest.fixture
def _async_pool():
    import tools.async_delegation as async_delegation

    async_delegation._reset_for_tests()
    yield async_delegation
    async_delegation._reset_for_tests()


def _wait_for_delegation(async_delegation, delegation_id, timeout=10.0):
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for record in async_delegation.list_async_delegations():
            if record.get("delegation_id") == delegation_id and record.get("status") != "running":
                return record
        time.sleep(0.01)
    raise AssertionError(f"background delegation {delegation_id} did not finish")


@pytest.mark.parametrize("exec_ask", [False, True])
@pytest.mark.parametrize("cron_mode", ["approve", "deny"])
def test_background_child_keeps_cron_policy(monkeypatch, _async_pool, cron_mode, exec_ask):
    """Codex P2 (thread 4408461122): the real top-level path is background.

    AIAgent._dispatch_delegate_task always selects background execution for a
    top-level agent, so a cron job's child runs on the async-delegation pool.
    The cron marker must survive that hop too, and be gone again afterwards.
    """
    from run_agent import AIAgent

    if exec_ask:
        monkeypatch.setenv("LLIAM_EXEC_ASK", "1")  # inherited from a gateway host
    monkeypatch.setattr("tools.approval._get_cron_approval_mode", lambda: cron_mode)
    seen = {}

    child = MagicMock()
    child._credential_pool = None
    child.tool_progress_callback = None

    def _run_conversation(**_kw):
        seen["guard"] = _guard_in_worker()
        seen["thread"] = threading.current_thread()
        return {"final_response": "ok", "messages": [], "api_calls": 1, "completed": True}

    child.run_conversation.side_effect = _run_conversation
    parent = _make_mock_parent()

    token = approval_module.set_cron_session()
    try:
        with patch("tools.delegate_tool._build_child_agent", return_value=child):
            out = json.loads(AIAgent._dispatch_delegate_task(parent, {"goal": "g"}))
    finally:
        approval_module.reset_cron_session(token)

    assert out["status"] == "dispatched", out
    assert out["mode"] == "background"
    record = _wait_for_delegation(_async_pool, out["delegation_id"])
    assert record["status"] == "completed", record

    assert seen["thread"] is not threading.current_thread()
    _assert_cron_policy(seen["guard"], cron_mode)


def test_background_worker_does_not_keep_cron_marker(monkeypatch, _async_pool):
    """The pool thread is reused: the marker must be reset after the job."""
    seen = []
    done = threading.Event()

    def _probe():
        seen.append(approval_module._is_cron_session())
        done.set()
        return {"status": "completed"}

    token = approval_module.set_cron_session()
    try:
        first = _async_pool.dispatch_async_delegation(
            goal="cron", context=None, toolsets=None, role="leaf", model=None,
            session_key="", runner=_probe, max_async_children=1,
        )
    finally:
        approval_module.reset_cron_session(token)
    _wait_for_delegation(_async_pool, first["delegation_id"])

    second = _async_pool.dispatch_async_delegation(
        goal="live", context=None, toolsets=None, role="leaf", model=None,
        session_key="", runner=_probe, max_async_children=1,
    )
    _wait_for_delegation(_async_pool, second["delegation_id"])

    assert seen == [True, False]
