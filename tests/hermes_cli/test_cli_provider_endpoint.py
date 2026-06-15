"""Tests for the /api/providers/cli readiness endpoint (AI-328 wiring).

Surfaces CLI-backed provider readiness via the providers.cli registry/contract.
Verified by calling the endpoint function directly (avoids host-header/CORS
plumbing) with both a patched registry and the real one.
"""

from __future__ import annotations

import json

import providers.cli as cli
from providers.cli.contract import (
    AuthResult,
    DetectResult,
    ProviderReadinessReport,
    Readiness,
)
from hermes_cli.web_server import get_cli_provider_readiness


def _fake_report() -> ProviderReadinessReport:
    return ProviderReadinessReport(
        id="claude-code",
        display_name="Claude Code CLI",
        readiness=Readiness.NOT_AUTHENTICATED,
        detect=DetectResult(installed=True, path="/usr/local/bin/claude", version="1.0"),
        auth=AuthResult(authenticated=False, source="claude_code_cli"),
        setup_hint="claude setup-token",
    )


def test_endpoint_shape_with_patched_registry(monkeypatch):
    monkeypatch.setattr(cli, "probe_all", lambda: [_fake_report()])
    payload = get_cli_provider_readiness()
    assert "providers" in payload
    assert len(payload["providers"]) == 1
    entry = payload["providers"][0]
    assert entry["id"] == "claude-code"
    assert entry["readiness"] == "not_authenticated"
    assert entry["setup_hint"] == "claude setup-token"
    # JSON-serializable end to end (str-enums serialize cleanly).
    assert json.dumps(payload)


def test_endpoint_real_registry_lists_three_providers():
    payload = get_cli_provider_readiness()
    ids = {p["id"] for p in payload["providers"]}
    assert ids == {"claude-code", "codex", "gemini"}
    for p in payload["providers"]:
        assert p["readiness"] in {
            "not_installed",
            "not_authenticated",
            "ready",
            "degraded",
            "unavailable",
        }


def test_endpoint_includes_render_ready_card():
    payload = get_cli_provider_readiness()
    for entry in payload["providers"]:
        card = entry["card"]
        assert card["id"] == entry["id"]
        assert card["state"] == entry["readiness"]
        assert "selectable" in card and isinstance(card["selectable"], bool)
        # The card's action is a CLI command (or empty) — never an API-key field.
        assert "action_command" in card


def test_endpoint_auth_is_structurally_secret_free():
    """AI-334: the auth object exposes only a boolean signal + non-secret labels.

    Structural guarantee — there is simply no field where a token value could
    live, so the readiness payload can never leak a secret.
    """
    payload = get_cli_provider_readiness()
    for entry in payload["providers"]:
        assert set(entry["auth"].keys()) == {
            "authenticated",
            "source",
            "detail",
            "expired",
        }
        assert isinstance(entry["auth"]["authenticated"], bool)
