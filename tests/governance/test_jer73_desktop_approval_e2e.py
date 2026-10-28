"""JER-73 — the desktop app can approve HITL requests under the gov overlay.

The Electron shell mints a per-launch gateway secret for each backend it
spawns, pins it in the backend's env (``LLIAM_TUI_GATEWAY_SECRET``) and puts
the same value in its renderer's ``/api/ws`` URL (``gw_secret=``). The
renderer's approval bar sends ``approval.respond {choice, session_id}`` over
that socket. These tests drive that path at the Python boundary, through the
real dashboard route (``/api/ws`` -> ``tui_gateway.ws.handle_ws`` ->
``server.dispatch`` -> ``approval.respond`` -> ``resolve_gateway_approval``)
while an agent thread blocks in ``_await_gateway_decision``:

  * the connection that presented the right ``gw_secret`` approves, and the
    ledger names the local operator principal;
  * the same request from a connection without it is refused: the loopback
    token alone is closed 4401 at the upgrade, and a connection that passed
    the handshake with the PTY child secret gets error 4033 and the request
    stays pending (a denial over it still goes through).
"""

from __future__ import annotations

import json
import threading
import urllib.parse

import pytest

_GOV = {
    "security": {
        "posture": "strict",
        "deny_on_no_approver": True,
        "require_authenticated_approver": True,
    }
}
_DESKTOP_SECRET = "desktop-minted-launch-secret"
_PTY_CHILD_SECRET = "dashboard-pty-child-secret"


@pytest.fixture
def desktop_backend(monkeypatch, tmp_path):
    """A loopback dashboard backend as the desktop shell spawns it (gov overlay)."""
    from starlette.testclient import TestClient

    import agent.governance_audit_hooks as gah
    import lliam_cli.web_server as web_server
    from agent.governance_audit import GovernanceLedger
    from lliam_cli import mcp_startup
    from tools import approval as ap
    from tui_gateway import server
    from tui_gateway import transport as gw

    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: _GOV)
    led = GovernanceLedger(tmp_path / "agent-audit.log")
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: led)
    monkeypatch.setattr(mcp_startup, "start_background_mcp_discovery", lambda **kw: None)
    monkeypatch.setattr(server, "_WS_ORPHAN_REAP_GRACE_S", 0)
    monkeypatch.setattr(web_server, "_DASHBOARD_EMBEDDED_CHAT_ENABLED", True)
    gw._reset_gateway_secret_for_tests(_DESKTOP_SECRET, child=_PTY_CHILD_SECRET)
    gah.set_operator_subject(None)

    state = web_server.app.state
    keys = ("bound_host", "bound_port", "auth_required")
    prev = {k: getattr(state, k, None) for k in keys}
    state.bound_host, state.bound_port, state.auth_required = "127.0.0.1", 9119, False

    server._sessions.clear()
    server._sessions["sid-desktop"] = {"session_key": "desktop-key"}
    ap._gateway_queues.clear()

    # The renderer connects from loopback to the backend's 127.0.0.1 port.
    client = TestClient(web_server.app, client=("127.0.0.1", 50000))
    yield client, web_server._SESSION_TOKEN, led

    ap._gateway_queues.clear()
    server._sessions.clear()
    for k, v in prev.items():
        setattr(state, k, v)
    gw._reset_gateway_secret_for_tests(None)
    gah.set_operator_subject(None)


def _ws_path(**params):
    # Same shape as localGatewayWsUrl() in apps/desktop/electron/main.cjs.
    return "ws://127.0.0.1:9119/api/ws?" + urllib.parse.urlencode(params)


def _pending_agent_approval(session_key="desktop-key"):
    """Start an agent thread blocked on a gateway approval; return its handle."""
    from tools import approval as ap

    queued = threading.Event()
    out: dict = {}

    def notify(_data):
        queued.set()

    def agent():
        out["decision"] = ap._await_gateway_decision(
            session_key, notify,
            {"command": "rm -rf ./build", "description": "recursive delete"},
        )

    t = threading.Thread(target=agent, daemon=True)
    t.start()
    assert queued.wait(5), "agent never queued its approval"
    return t, out


def _rpc(conn, rid, method, params):
    conn.send_text(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}))
    while True:
        frame = json.loads(conn.receive_text())
        if frame.get("id") == rid:
            return frame


def _ready(conn):
    frame = json.loads(conn.receive_text())
    assert frame["params"]["type"] == "gateway.ready"


def _gateway_decisions(led):
    from agent.governance_audit import iter_records

    return [
        r for r in iter_records(led.path)
        if r["event"] == "approval.decision"
        and r.get("outcome", {}).get("origin") == "gateway"
    ]


def test_desktop_connection_with_gateway_secret_approves(desktop_backend):
    from tui_gateway import transport as gw

    client, token, led = desktop_backend
    agent, out = _pending_agent_approval()

    with client.websocket_connect(_ws_path(token=token, gw_secret=_DESKTOP_SECRET)) as conn:
        _ready(conn)
        # What apps/desktop/src/components/assistant-ui/tool-approval.tsx sends on "Run".
        resp = _rpc(conn, "r1", "approval.respond", {"choice": "once", "session_id": "sid-desktop"})

    assert resp.get("result") == {"resolved": 1}, resp
    agent.join(5)
    assert out["decision"] == {"resolved": True, "choice": "once"}

    rec = _gateway_decisions(led)[-1]
    assert rec["decision"] == "approve"
    assert rec["approver"] == {
        "id": gw.local_operator_principal(),
        "authenticated": True,
        "method": "desktop-launch-secret",
    }
    assert rec["approver"]["id"].startswith("local-operator:")


def test_same_request_without_gateway_secret_is_refused(desktop_backend):
    from starlette.websockets import WebSocketDisconnect

    from tools import approval as ap

    client, token, led = desktop_backend
    agent, out = _pending_agent_approval()

    # A local process that only scraped the index.html token: closed at the upgrade.
    with pytest.raises(WebSocketDisconnect) as closed:
        with client.websocket_connect(_ws_path(token=token)) as conn:
            conn.receive_text()
    assert closed.value.code == 4401

    # A wrong secret: same.
    with pytest.raises(WebSocketDisconnect) as closed:
        with client.websocket_connect(_ws_path(token=token, gw_secret="guess")) as conn:
            conn.receive_text()
    assert closed.value.code == 4401

    # Past the handshake with the PTY child secret, but not the operator:
    # the approval is refused and stays pending; a denial still lands.
    with client.websocket_connect(_ws_path(token=token, gw_child=_PTY_CHILD_SECRET)) as conn:
        _ready(conn)
        refused = _rpc(conn, "r1", "approval.respond", {"choice": "once", "session_id": "sid-desktop"})
        assert refused["error"]["code"] == 4033
        assert "LG-GV-05" in refused["error"]["message"]
        assert len(ap._gateway_queues.get("desktop-key", [])) == 1
        assert agent.is_alive()

        denied = _rpc(conn, "r2", "approval.respond", {"choice": "deny", "session_id": "sid-desktop"})

    assert denied.get("result") == {"resolved": 1}, denied
    agent.join(5)
    assert out["decision"] == {"resolved": True, "choice": "deny"}

    from agent.governance_audit import iter_records

    refusals = [
        r for r in iter_records(led.path)
        if r["event"] == "approval.decision"
        and "unauthenticated_approver_refused" in str(r.get("outcome", {}).get("origin"))
    ]
    assert refusals and refusals[-1]["decision"] == "deny"
    final = _gateway_decisions(led)[-1]
    assert final["decision"] == "deny" and final["approver"] == {}
