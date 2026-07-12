"""Control-plane authentication gate tests (LG-IA-11/06/08, P1.5).

Exercises enforce_control_plane_auth_at_startup: the API-server-key RCE gate
and the TLS-verification gate, fail-closed under strict posture, advisory
otherwise. Includes the recurring-pattern regression: a RAW (overlay-less)
config passed by the caller must still block when the effective merged config
is strict — the gate re-resolves posture from load_config().
"""

from __future__ import annotations

import pytest

import lliam_cli.security_audit_startup as sas


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(sas, "_CONTROL_PLANE_CHECKED", False)
    # Neutralize ambient env so each test drives the trigger explicitly.
    for var in ("LLIAM_SKIP_SSL_GUARD", "HERMES_SKIP_SSL_GUARD",
                "LLIAM_SKIP_SSL_VERIFY", "HERMES_SKIP_SSL_VERIFY",
                "API_SERVER_KEY", "API_SERVER_HOST", "API_SERVER_ENABLED"):
        monkeypatch.delenv(var, raising=False)
    yield


# The API server is configured from ENV at runtime (gateway/config.py), NOT the
# load_config() dict — so these tests drive the REAL production trigger (env),
# not a hand-built platforms block (which the merged config never carries).
_STRICT = {"security": {"posture": "strict", "api_server_key_required": True,
                        "require_tls": True}}


def test_network_api_without_key_blocks_under_strict(monkeypatch):
    monkeypatch.setenv("API_SERVER_ENABLED", "true")
    monkeypatch.setenv("API_SERVER_HOST", "0.0.0.0")  # network-accessible bind
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: _STRICT)
    with pytest.raises(sas.ControlPlaneAuthError, match="API_SERVER_KEY|API server"):
        sas.enforce_control_plane_auth_at_startup(config=_STRICT)


def test_network_api_with_key_passes(monkeypatch):
    monkeypatch.setenv("API_SERVER_ENABLED", "true")
    monkeypatch.setenv("API_SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("API_SERVER_KEY", "a-strong-random-key-9f2c4b8a")
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: _STRICT)
    assert sas.enforce_control_plane_auth_at_startup(config=_STRICT) is None


def test_loopback_api_without_key_does_not_block(monkeypatch):
    monkeypatch.setenv("API_SERVER_ENABLED", "true")
    monkeypatch.setenv("API_SERVER_HOST", "127.0.0.1")  # loopback → not exposed
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: _STRICT)
    assert sas.enforce_control_plane_auth_at_startup(config=_STRICT) is None


def test_no_api_server_no_finding(monkeypatch):
    # API server not enabled and no key/host env → nothing to report.
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: _STRICT)
    assert sas.enforce_control_plane_auth_at_startup(config=_STRICT) is None


def test_host_alone_does_not_over_block(monkeypatch):
    """Regression: API_SERVER_HOST set without ENABLED/KEY does NOT start the
    server (gateway/config.py:1539), so the gate must not spuriously refuse
    startup on a stray host env var."""
    monkeypatch.setenv("API_SERVER_HOST", "0.0.0.0")  # host only, not enabled
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: _STRICT)
    assert sas.enforce_control_plane_auth_at_startup(config=_STRICT) is None


def test_advisory_when_not_strict(monkeypatch):
    monkeypatch.setenv("API_SERVER_ENABLED", "true")
    monkeypatch.setenv("API_SERVER_HOST", "0.0.0.0")
    cfg = {"security": {"api_server_key_required": True}}  # no strict posture
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: cfg)
    result = sas.enforce_control_plane_auth_at_startup(config=cfg)
    assert result and any("API_SERVER_KEY" in f for f in result)


def test_raw_config_still_blocks_when_merged_is_strict(monkeypatch):
    """Recurring-pattern regression: the gateway passes a config that may lack
    the overlay-injected strict posture; the gate must re-resolve posture from
    the merged load_config() and still block on the real env trigger."""
    monkeypatch.setenv("API_SERVER_ENABLED", "true")
    monkeypatch.setenv("API_SERVER_HOST", "0.0.0.0")
    merged = {"security": {"posture": "strict", "api_server_key_required": True}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: merged)
    raw = {"some": "home-config"}  # neither posture nor api block
    with pytest.raises(sas.ControlPlaneAuthError):
        sas.enforce_control_plane_auth_at_startup(config=raw)


def test_weak_key_still_blocks_under_strict(monkeypatch):
    """A weak-but-nonempty key must not slip the RCE gate (entropy floor,
    parity with the adapter's connect() guard)."""
    monkeypatch.setenv("API_SERVER_ENABLED", "true")
    monkeypatch.setenv("API_SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("API_SERVER_KEY", "x")  # nonempty but weak
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: _STRICT)
    with pytest.raises(sas.ControlPlaneAuthError, match="WEAK|API_SERVER_KEY"):
        sas.enforce_control_plane_auth_at_startup(config=_STRICT)


def test_strict_coerces_fail_closed_switches(monkeypatch):
    """LG-IA-11/08: strict posture must FORCE api_server_key_required and
    require_tls true — an agent cannot downgrade the gate to advisory by
    writing them false in home config while staying strict."""
    from lliam_cli import posture_resolver as pr
    cfg = {"security": {"posture": "strict",
                        "api_server_key_required": False,
                        "require_tls": False}}
    pr.resolve(cfg)  # mutates cfg in place
    assert cfg["security"]["api_server_key_required"] is True
    assert cfg["security"]["require_tls"] is True


def test_ca_bundle_preflight_skip_is_not_reported_as_tls_disabled(monkeypatch):
    """LG-IA-08 correction: SKIP_SSL_GUARD only skips the CA-bundle *preflight*
    (agent/ssl_guard.py:verify_ca_bundle) — it never sets verify=False, so
    providers/MCP still verify TLS at request time. The other historical
    aliases (SKIP_SSL_VERIFY / INSECURE_SKIP_VERIFY) have NO runtime consumer at
    all. None of them may be reported as 'TLS verification disabled'."""
    monkeypatch.setenv("LLIAM_SKIP_SSL_GUARD", "1")
    monkeypatch.setenv("HERMES_SKIP_SSL_VERIFY", "true")
    monkeypatch.setenv("LLIAM_INSECURE_SKIP_VERIFY", "yes")
    assert sas._tls_verification_disabled() == []


def test_ca_bundle_preflight_skip_does_not_block_under_strict(monkeypatch):
    """The false TLS-disabled claim previously BLOCKED startup under
    strict+require_tls. Skipping the CA preflight is legitimate (a custom
    corporate CA bundle) and must not refuse a strict start."""
    monkeypatch.setenv("LLIAM_SKIP_SSL_GUARD", "1")
    cfg = {"security": {"posture": "strict", "require_tls": True}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: cfg)
    assert sas.enforce_control_plane_auth_at_startup(config=cfg, force=True) is None


def test_no_findings_returns_none(monkeypatch):
    monkeypatch.setenv("API_SERVER_KEY", "strong-key")
    cfg = {"security": {"posture": "strict", "api_server_key_required": True,
                        "require_tls": True}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: cfg)
    assert sas.enforce_control_plane_auth_at_startup(config=cfg) is None


def test_idempotent_per_process(monkeypatch):
    monkeypatch.setenv("API_SERVER_KEY", "strong-key")
    cfg = {"security": {"posture": "strict", "api_server_key_required": True}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: cfg)
    assert sas.enforce_control_plane_auth_at_startup(config=cfg) is None
    # Second call is a no-op (already ran this process) unless forced.
    monkeypatch.setattr(sas, "_CONTROL_PLANE_CHECKED", True)
    assert sas.enforce_control_plane_auth_at_startup(config=cfg) is None
