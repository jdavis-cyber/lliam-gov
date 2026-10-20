"""JER-73 — caller authentication on the tui_gateway WebSocket transport.

Under strict posture a socket peer that did not authenticate with a
non-scrapeable credential must present the per-launch gateway secret
(``?gw_secret=``); otherwise the upgrade is refused before any frame is
dispatched. Low-side behaviour is unchanged. An authenticated dashboard_auth
principal passed by the mounting layer is bound as the operator subject for
that connection's dispatches only.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from lliam_cli import mcp_startup
from tui_gateway import server
from tui_gateway import transport as gw_transport
from tui_gateway import ws as ws_mod


class _QP(dict):
    def get(self, key, default=None):  # starlette QueryParams-like
        return super().get(key, default)


class FakeWS:
    def __init__(self, query=None, frames=()):
        self.query_params = _QP(query or {})
        self.accepted = False
        self.closed_with = []
        self.sent = []
        self._frames = list(frames)

    async def accept(self):
        self.accepted = True

    async def send_text(self, line):
        self.sent.append(json.loads(line))

    async def receive_text(self):
        if self._frames:
            return self._frames.pop(0)
        raise ws_mod._WebSocketDisconnect()

    async def close(self, code=1000):
        self.closed_with.append(code)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(mcp_startup, "start_background_mcp_discovery", lambda **kw: None)
    monkeypatch.setattr(server, "_WS_ORPHAN_REAP_GRACE_S", 0)
    gw_transport._reset_gateway_secret_for_tests("launch-secret")
    server._sessions.clear()
    yield
    server._sessions.clear()
    gw_transport._reset_gateway_secret_for_tests(None)


@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setattr(gw_transport, "handshake_required", lambda: True)


@pytest.fixture
def low_side(monkeypatch):
    monkeypatch.setattr(gw_transport, "handshake_required", lambda: False)


def _ready(fake):
    return [f for f in fake.sent if f.get("params", {}).get("type") == "gateway.ready"]


def test_strict_refuses_peer_without_gateway_secret(strict):
    fake = FakeWS(frames=['{"jsonrpc":"2.0","id":1,"method":"session.list","params":{}}'])
    asyncio.run(ws_mod.handle_ws(fake))
    assert fake.accepted is False
    assert fake.closed_with == [4401]
    assert fake.sent == []          # nothing dispatched, no gateway.ready


def test_strict_refuses_wrong_gateway_secret(strict):
    fake = FakeWS(query={"gw_secret": "guess"})
    asyncio.run(ws_mod.handle_ws(fake))
    assert fake.accepted is False and fake.closed_with == [4401]


def test_strict_accepts_correct_gateway_secret(strict):
    fake = FakeWS(query={"gw_secret": "launch-secret"})
    asyncio.run(ws_mod.handle_ws(fake))
    assert fake.accepted is True
    assert _ready(fake)


def test_strict_accepts_peer_authenticated_by_mounting_layer(strict):
    fake = FakeWS()
    asyncio.run(ws_mod.handle_ws(fake, authenticated=True))
    assert fake.accepted is True and _ready(fake)


def test_low_side_needs_no_gateway_secret(low_side):
    fake = FakeWS()
    asyncio.run(ws_mod.handle_ws(fake))
    assert fake.accepted is True and _ready(fake)


def test_principal_bound_for_this_connection_only(low_side, monkeypatch):
    import agent.governance_audit_hooks as gah

    seen = []

    def fake_dispatch(req, transport=None):
        seen.append(gah._current_subject())
        return {"jsonrpc": "2.0", "id": req.get("id"), "result": {}}

    monkeypatch.setattr(server, "dispatch", fake_dispatch)
    frame = '{"jsonrpc":"2.0","id":1,"method":"approval.respond","params":{}}'

    asyncio.run(ws_mod.handle_ws(
        FakeWS(frames=[frame]), authenticated=True,
        principal={"user_id": "alice@agency.mil", "provider": "oauth"},
    ))
    asyncio.run(ws_mod.handle_ws(FakeWS(frames=[frame])))
    asyncio.run(ws_mod.handle_ws(
        FakeWS(frames=[frame]), authenticated=True,
        principal={"user_id": "server-internal", "provider": "server-internal"},
    ))

    assert seen[0] == {"principal": "alice@agency.mil", "auth": "dashboard_auth:oauth"}
    assert seen[1] == {"principal": None}
    assert seen[2] == {"principal": None}
    assert gah._current_subject() == {"principal": None}


# ---------------------------------------------------------------------------
# transport-level secret primitives
# ---------------------------------------------------------------------------

def test_verify_gateway_secret_is_exact():
    assert gw_transport.verify_gateway_secret("launch-secret") is True
    assert gw_transport.verify_gateway_secret("launch-secre") is False
    assert gw_transport.verify_gateway_secret("") is False
    assert gw_transport.verify_gateway_secret(None) is False


def test_gateway_secret_minted_per_launch_when_not_pinned():
    gw_transport._reset_gateway_secret_for_tests(None)
    first = gw_transport.gateway_secret()
    assert len(first) >= 40 and gw_transport.gateway_secret() == first
    gw_transport._reset_gateway_secret_for_tests(None)
    assert gw_transport.gateway_secret() != first


def test_pinned_secret_is_adopted_and_removed_from_env(monkeypatch):
    import os

    monkeypatch.setenv("LLIAM_TUI_GATEWAY_SECRET", "pinned-by-desktop")
    monkeypatch.setenv("HERMES_TUI_GATEWAY_SECRET", "legacy")
    assert gw_transport._adopt_pinned_gateway_secret() == "pinned-by-desktop"
    assert "LLIAM_TUI_GATEWAY_SECRET" not in os.environ
    assert "HERMES_TUI_GATEWAY_SECRET" not in os.environ


def test_handshake_required_follows_strict_posture(monkeypatch):
    monkeypatch.setattr("lliam_cli.config.load_config",
                        lambda *a, **kw: {"security": {"posture": "strict"}})
    assert gw_transport.handshake_required() is True
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: {"security": {}})
    assert gw_transport.handshake_required() is False


def test_gateway_secret_never_inherited_by_tool_subprocesses():
    from tools.environments import local

    assert "LLIAM_TUI_GATEWAY_SECRET" in local._ALWAYS_STRIP_KEYS
    assert "HERMES_TUI_GATEWAY_SECRET" in local._ALWAYS_STRIP_KEYS
