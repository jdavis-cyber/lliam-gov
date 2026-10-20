"""Fail-closed behaviour of declared security controls (lliam_cli/declared_controls.py).

* security.require_mfa — a network-bound dashboard refuses to start under
  strict posture unless every login provider enforces MFA.
* security.device_auth — computer_use refuses unenrolled hosts under strict.
* enforce_declared_controls_at_startup — unenforceable configuration raises
  under strict, is advisory otherwise, and the shipped overlay passes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from lliam_cli import declared_controls as dc

_STRICT_MFA = {"security": {"posture": "strict", "require_mfa": True}}


class _Provider:
    def __init__(self, name, *, mfa=False, session=True):
        self.name = name
        self.enforces_mfa = mfa
        self.supports_session = session


# --------------------------------------------------------------------------- #
# security.require_mfa
# --------------------------------------------------------------------------- #

def test_non_mfa_provider_refused_under_strict():
    msg = dc.dashboard_mfa_refusal("0.0.0.0", providers=[_Provider("basic")], config=_STRICT_MFA)
    assert msg and "basic" in msg and "multi-factor" in msg


def test_mixed_providers_refused_if_any_lacks_mfa():
    providers = [_Provider("self-hosted", mfa=True), _Provider("nous")]
    msg = dc.dashboard_mfa_refusal("0.0.0.0", providers=providers, config=_STRICT_MFA)
    assert msg and "authentication: nous." in msg


def test_mfa_providers_allowed():
    providers = [_Provider("self-hosted", mfa=True), _Provider("drain", session=False)]
    assert dc.dashboard_mfa_refusal("0.0.0.0", providers=providers, config=_STRICT_MFA) is None


def test_mfa_gate_off_low_side_or_flag_off():
    assert dc.dashboard_mfa_refusal(
        "0.0.0.0", providers=[_Provider("basic")], config={"security": {"require_mfa": True}}
    ) is None
    assert dc.dashboard_mfa_refusal(
        "0.0.0.0", providers=[_Provider("basic")],
        config={"security": {"posture": "strict", "require_mfa": False}},
    ) is None


def _stub_uvicorn(monkeypatch):
    import contextlib

    import uvicorn

    class _Config:
        loaded = True
        host = "127.0.0.1"
        port = 8000

        def __init__(self, *a, **kw):
            pass

        def load(self):
            pass

        class lifespan_class:
            should_exit = False
            state: dict = {}

            def __init__(self, *a, **kw):
                pass

            async def startup(self):
                pass

            async def shutdown(self):
                pass

    class _Server:
        should_exit = False
        started = True
        servers: list = []
        lifespan = None

        @staticmethod
        def capture_signals():
            return contextlib.nullcontext()

        async def startup(self, sockets=None):
            pass

        async def main_loop(self):
            pass

        async def shutdown(self, sockets=None):
            pass

    monkeypatch.setattr(uvicorn, "Config", _Config)
    monkeypatch.setattr(uvicorn, "Server", lambda config: _Server())


def test_start_server_refuses_network_bind_without_mfa(monkeypatch):
    from lliam_cli import web_server
    from lliam_cli.dashboard_auth import clear_providers, register_provider
    from tests.lliam_cli.conftest_dashboard_auth import StubAuthProvider

    monkeypatch.setattr("lliam_cli.config.load_config", lambda: _STRICT_MFA)
    clear_providers()
    register_provider(StubAuthProvider())
    _stub_uvicorn(monkeypatch)
    try:
        with pytest.raises(SystemExit, match="multi-factor"):
            web_server.start_server(host="0.0.0.0", port=9119, open_browser=False)
    finally:
        clear_providers()


def test_start_server_allows_mfa_enforcing_provider(monkeypatch):
    from lliam_cli import web_server
    from lliam_cli.dashboard_auth import clear_providers, register_provider
    from tests.lliam_cli.conftest_dashboard_auth import StubAuthProvider

    monkeypatch.setattr("lliam_cli.config.load_config", lambda: _STRICT_MFA)
    clear_providers()
    provider = StubAuthProvider()
    provider.enforces_mfa = True
    register_provider(provider)
    _stub_uvicorn(monkeypatch)
    try:
        web_server.start_server(host="0.0.0.0", port=9119, open_browser=False)
        assert web_server.app.state.auth_required is True
    finally:
        clear_providers()


def test_start_server_loopback_unaffected(monkeypatch):
    from lliam_cli import web_server

    monkeypatch.setattr("lliam_cli.config.load_config", lambda: _STRICT_MFA)
    _stub_uvicorn(monkeypatch)
    web_server.start_server(host="127.0.0.1", port=9119, open_browser=False)
    assert web_server.app.state.auth_required is False


# --------------------------------------------------------------------------- #
# security.device_auth
# --------------------------------------------------------------------------- #

def _device_cfg(hosts, strict=True):
    cfg = {"security": {"device_auth": {"computer_use_enrolled_hosts": hosts}}}
    if strict:
        cfg["security"]["posture"] = "strict"
    return cfg


def test_device_refused_when_not_enrolled():
    msg = dc.computer_use_device_refusal(_device_cfg([]), hostnames=["ws-1"])
    assert msg and "not enrolled" in msg


def test_device_allowed_when_enrolled():
    assert dc.computer_use_device_refusal(_device_cfg(["WS-1."]), hostnames=["ws-1"]) is None


def test_device_malformed_enrollment_fails_closed():
    msg = dc.computer_use_device_refusal(_device_cfg("ws-1"), hostnames=["ws-1"])
    assert msg and "must be a list" in msg


def test_device_check_off_low_side():
    assert dc.computer_use_device_refusal(_device_cfg([], strict=False), hostnames=["ws-1"]) is None


def test_computer_use_handler_refuses_unenrolled_host(monkeypatch):
    from tools.computer_use import tool as cu

    monkeypatch.setattr("lliam_cli.config.load_config", lambda: _device_cfg([]))
    monkeypatch.setattr(cu, "_get_backend", lambda: pytest.fail("backend must not be reached"))
    out = json.loads(cu.handle_computer_use({"action": "capture"}))
    assert "not enrolled" in out["error"]


# --------------------------------------------------------------------------- #
# Startup configuration check
# --------------------------------------------------------------------------- #

def test_shipped_overlay_has_no_findings():
    overlay = yaml.safe_load((Path(__file__).resolve().parents[2] / "cli-config.gov.yaml").read_text())
    assert overlay["security"]["posture"] == "strict"
    assert dc.declared_control_findings(overlay) == []
    assert dc.enforce_declared_controls_at_startup(overlay) is None


def test_pinning_enabled_without_pins_blocks_under_strict():
    cfg = {"security": {"posture": "strict", "cert_pinning": {"enabled": True, "pins": {}}}}
    with pytest.raises(dc.DeclaredControlError, match="no pins"):
        dc.enforce_declared_controls_at_startup(cfg)


def test_bad_spend_ceiling_blocks_under_strict():
    cfg = {"security": {"posture": "strict", "spend_ceiling": {"enabled": True}}}
    with pytest.raises(dc.DeclaredControlError, match="no ceiling is set"):
        dc.enforce_declared_controls_at_startup(cfg)


def test_bad_spawn_depth_blocks_under_strict():
    cfg = {"security": {"posture": "strict"}, "delegation": {"max_spawn_depth": "deep"}}
    with pytest.raises(dc.DeclaredControlError, match="max_spawn_depth"):
        dc.enforce_declared_controls_at_startup(cfg)


def test_findings_are_advisory_low_side():
    cfg = {"security": {"spend_ceiling": {"enabled": True, "per_session_tokens": -1}}}
    findings = dc.enforce_declared_controls_at_startup(cfg)
    assert findings and "per_session_tokens" in findings[0]
