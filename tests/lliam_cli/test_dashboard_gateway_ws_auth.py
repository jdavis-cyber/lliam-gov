"""JER-73 — dashboard wiring for gateway caller authentication.

* The PTY child's ``/api/ws`` attach URL carries the handshake-only PTY
  child secret under strict posture (loopback mode) — never the desktop's
  gateway secret, which would make the PTY's opener the local operator — and
  nothing new on low-side.
* In gated mode a PTY opened by an authenticated user attaches with a
  credential bound to that user, so ``/api/ws`` binds their principal.
* ``gateway_ws`` tells ``handle_ws`` whether the credential was
  non-scrapeable (ticket / internal) and which human principal it carried.
* The parent-pinned gateway secret is never copied raw into the PTY env.
"""

from __future__ import annotations

import asyncio
import urllib.parse
from types import SimpleNamespace

import pytest

from lliam_cli import web_server
from lliam_cli.dashboard_auth import ws_tickets
from tui_gateway import transport as gw_transport


class _QP:
    def __init__(self, q):
        self._q = q

    def get(self, k, default=""):
        return self._q.get(k, default)


def _fake_ws(query):
    return SimpleNamespace(
        query_params=_QP(query),
        client=SimpleNamespace(host="127.0.0.1"),
        url=SimpleNamespace(path="/api/ws"),
        state=SimpleNamespace(),
    )


@pytest.fixture
def app_state():
    ws_tickets._reset_for_tests()
    gw_transport._reset_gateway_secret_for_tests("launch-secret", child="pty-child")
    keys = ("bound_host", "bound_port", "auth_required")
    prev = {k: getattr(web_server.app.state, k, None) for k in keys}
    yield web_server.app.state
    for k, v in prev.items():
        setattr(web_server.app.state, k, v)
    ws_tickets._reset_for_tests()
    gw_transport._reset_gateway_secret_for_tests(None)


def _query(url):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


def test_loopback_attach_url_carries_child_secret_under_strict(app_state, monkeypatch):
    app_state.bound_host, app_state.bound_port, app_state.auth_required = "127.0.0.1", 9119, False
    monkeypatch.setattr(gw_transport, "handshake_required", lambda: True)
    q = _query(web_server._build_gateway_ws_url())
    assert q == {"token": web_server._SESSION_TOKEN, "gw_child": "pty-child"}
    assert "launch-secret" not in web_server._build_gateway_ws_url()


def test_loopback_attach_url_unchanged_on_low_side(app_state, monkeypatch):
    app_state.bound_host, app_state.bound_port, app_state.auth_required = "127.0.0.1", 9119, False
    monkeypatch.setattr(gw_transport, "handshake_required", lambda: False)
    q = _query(web_server._build_gateway_ws_url())
    assert q == {"token": web_server._SESSION_TOKEN}


def test_gated_attach_url_uses_principal_bound_child_credential(app_state):
    app_state.bound_host, app_state.bound_port, app_state.auth_required = "fly.example", 443, True
    cred = ws_tickets.mint_child_credential(user_id="alice@agency.mil", provider="oauth")
    assert _query(web_server._build_gateway_ws_url(child_credential=cred)) == {"internal": cred}
    # Without one, the anonymous process credential (unchanged behaviour).
    assert _query(web_server._build_gateway_ws_url()) == {
        "internal": ws_tickets.internal_ws_credential()
    }


def test_child_credential_resolves_to_user_and_is_revocable(app_state):
    app_state.auth_required = True
    ws_tickets.internal_ws_credential()
    cred = ws_tickets.mint_child_credential(user_id="alice@agency.mil", provider="oauth")
    ws = _fake_ws({"internal": cred})
    assert web_server._ws_auth_reason(ws) == (None, "internal")
    assert web_server._ws_human_identity(ws)["user_id"] == "alice@agency.mil"

    # The process credential still resolves, but to no human.
    ws2 = _fake_ws({"internal": ws_tickets.internal_ws_credential()})
    assert web_server._ws_auth_reason(ws2) == (None, "internal")
    assert web_server._ws_human_identity(ws2) is None

    ws_tickets.revoke_child_credential(cred)
    assert web_server._ws_auth_reason(_fake_ws({"internal": cred}))[0] == "internal_invalid"


def test_ticket_identity_is_captured_for_the_handler(app_state):
    app_state.auth_required = True
    ticket = ws_tickets.mint_ticket(user_id="bob@agency.mil", provider="oauth")
    ws = _fake_ws({"ticket": ticket})
    assert web_server._ws_auth_reason(ws) == (None, "ticket")
    assert web_server._ws_human_identity(ws) == {
        "user_id": "bob@agency.mil", "provider": "oauth",
        "minted_at": ws.state.dashboard_auth_identity["minted_at"],
    }


@pytest.mark.parametrize(
    "auth_required,query_factory,expect_auth,expect_user",
    [
        (False, lambda: {"token": web_server._SESSION_TOKEN}, False, None),
        (True, lambda: {"ticket": ws_tickets.mint_ticket(user_id="u1", provider="p")}, True, "u1"),
        (True, lambda: {"internal": ws_tickets.internal_ws_credential()}, True, None),
    ],
)
def test_gateway_ws_passes_auth_context(app_state, monkeypatch, auth_required,
                                        query_factory, expect_auth, expect_user):
    app_state.bound_host, app_state.bound_port = "127.0.0.1", 9119
    app_state.auth_required = auth_required
    monkeypatch.setattr(web_server, "_DASHBOARD_EMBEDDED_CHAT_ENABLED", True)
    monkeypatch.setattr(web_server, "_ws_request_is_allowed", lambda ws: True)
    calls = []

    async def fake_handle_ws(ws, **kw):
        calls.append(kw)

    import tui_gateway.ws as tws

    monkeypatch.setattr(tws, "handle_ws", fake_handle_ws)
    ws = _fake_ws(query_factory())

    async def _close(code=1000):
        calls.append({"closed": code})

    ws.close = _close
    asyncio.run(web_server.gateway_ws(ws))
    assert calls[0]["authenticated"] is expect_auth
    principal = calls[0]["principal"]
    assert (principal or {}).get("user_id") == expect_user


def test_pty_env_never_inherits_raw_gateway_secret(app_state, monkeypatch):
    app_state.bound_host, app_state.bound_port, app_state.auth_required = "127.0.0.1", 9119, False
    monkeypatch.setenv("LLIAM_TUI_GATEWAY_SECRET", "pinned")
    monkeypatch.setenv("HERMES_TUI_GATEWAY_SECRET", "pinned")
    monkeypatch.setattr("lliam_cli.main._make_tui_argv", lambda *a, **kw: (["node", "tui"], None))
    monkeypatch.setattr(gw_transport, "handshake_required", lambda: True)
    _argv, _cwd, env = web_server._resolve_chat_argv()
    assert "LLIAM_TUI_GATEWAY_SECRET" not in env
    assert "HERMES_TUI_GATEWAY_SECRET" not in env
    q = _query(env["LLIAM_TUI_GATEWAY_URL"])
    assert q["gw_child"] == "pty-child"
    assert "gw_secret" not in q
    assert "launch-secret" not in env["LLIAM_TUI_GATEWAY_URL"]
