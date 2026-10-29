"""Tests for ``agent.session_context`` (moved from the messaging gateway, JER-198).

Covers the contextvar store the desktop chat transport, cron, and tools use
to read per-turn session metadata without leaking across concurrent turns.
"""

import pytest

from agent.session_context import (
    _UNSET,
    _VAR_MAP,
    _SESSION_ASYNC_DELIVERY,
    async_delivery_supported,
    clear_session_vars,
    get_session_env,
    set_session_vars,
)


@pytest.fixture(autouse=True)
def _reset_contextvars():
    """Reset all session contextvars to _UNSET between tests (tests share one
    thread context, so a clear from one test would otherwise leak)."""
    yield
    for var in _VAR_MAP.values():
        var.set(_UNSET)
    _SESSION_ASYNC_DELIVERY.set(_UNSET)


def test_get_session_env_falls_back_to_os_environ(monkeypatch):
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "tui")
    assert get_session_env("HERMES_SESSION_PLATFORM") == "tui"

    tokens = set_session_vars(platform="cron")
    assert get_session_env("HERMES_SESSION_PLATFORM") == "cron"

    # After clear: "" (explicitly cleared), NOT the stale os.environ (#10304).
    clear_session_vars(tokens)
    assert get_session_env("HERMES_SESSION_PLATFORM") == ""


def test_get_session_env_reads_lliam_name_first(monkeypatch):
    monkeypatch.setenv("LLIAM_SESSION_ID", "new")
    monkeypatch.setenv("HERMES_SESSION_ID", "old")
    assert get_session_env("HERMES_SESSION_ID") == "new"


def test_get_session_env_default_when_nothing_set(monkeypatch):
    monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
    monkeypatch.delenv("LLIAM_SESSION_PLATFORM", raising=False)
    assert get_session_env("HERMES_SESSION_PLATFORM") == ""
    assert get_session_env("HERMES_SESSION_PLATFORM", "fallback") == "fallback"


def test_session_key_and_source_round_trip():
    tokens = set_session_vars(session_key="desk-1", source="tui", session_id="s1")
    try:
        assert get_session_env("HERMES_SESSION_KEY") == "desk-1"
        assert get_session_env("HERMES_SESSION_SOURCE") == "tui"
        assert get_session_env("HERMES_SESSION_ID") == "s1"
    finally:
        clear_session_vars(tokens)
    assert get_session_env("HERMES_SESSION_KEY") == ""


class TestAsyncDeliverySupported:
    def test_default_unbound_is_supported(self):
        assert async_delivery_supported() is True

    def test_set_false_is_unsupported(self):
        tokens = set_session_vars(session_key="s1", async_delivery=False)
        try:
            assert async_delivery_supported() is False
        finally:
            clear_session_vars(tokens)

    def test_omitted_arg_defaults_supported(self):
        tokens = set_session_vars(session_key="s2")
        try:
            assert async_delivery_supported() is True
        finally:
            clear_session_vars(tokens)

    def test_clear_resets_to_default_supported(self):
        tokens = set_session_vars(session_key="s1", async_delivery=False)
        assert async_delivery_supported() is False
        clear_session_vars(tokens)
        assert async_delivery_supported() is True
