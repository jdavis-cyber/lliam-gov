"""Tests for first-run provider card view-models (AI-329 backend half)."""

from __future__ import annotations

import pytest

from providers.cli.cards import to_card
from providers.cli.contract import (
    AuthResult,
    DetectResult,
    ProviderReadinessReport,
    Readiness,
)


def _report(readiness: Readiness, *, setup_hint="", default_model="sonnet"):
    return ProviderReadinessReport(
        id="claude-code",
        display_name="Claude Code CLI",
        readiness=readiness,
        detect=DetectResult(installed=readiness is not Readiness.NOT_INSTALLED),
        auth=AuthResult(authenticated=readiness is Readiness.READY),
        default_model=default_model,
        setup_hint=setup_hint,
    )


@pytest.mark.parametrize(
    "readiness,selectable,tone,status_label",
    [
        (Readiness.READY, True, "positive", "Ready"),
        (Readiness.NOT_INSTALLED, False, "neutral", "Not installed"),
        (Readiness.NOT_AUTHENTICATED, False, "warning", "Needs sign-in"),
        (Readiness.DEGRADED, True, "warning", "Degraded"),
        (Readiness.UNAVAILABLE, False, "error", "Unavailable"),
    ],
)
def test_card_state_mapping(readiness, selectable, tone, status_label):
    card = to_card(_report(readiness))
    assert card.state == readiness.value
    assert card.selectable is selectable
    assert card.tone == tone
    assert card.status_label == status_label


def test_action_command_is_cli_command_not_api_key():
    card = to_card(_report(Readiness.NOT_INSTALLED, setup_hint="npm install -g @anthropic-ai/claude-code"))
    assert card.action_label == "Install"
    assert card.action_command == "npm install -g @anthropic-ai/claude-code"


def test_signin_card_uses_login_command():
    card = to_card(_report(Readiness.NOT_AUTHENTICATED, setup_hint="claude setup-token"))
    assert card.action_label == "Sign in"
    assert card.action_command == "claude setup-token"


def test_ready_card_carries_default_model_and_is_json_safe():
    card = to_card(_report(Readiness.READY, default_model="sonnet"))
    d = card.to_dict()
    assert d["default_model"] == "sonnet"
    assert d["selectable"] is True
    import json

    assert json.dumps(d)


def test_card_never_exposes_secret_fields():
    """AI-334: a card carries only display + a CLI command, never a token field."""
    card = to_card(_report(Readiness.READY))
    assert set(card.to_dict().keys()) == {
        "id",
        "display_name",
        "state",
        "status_label",
        "tone",
        "selectable",
        "action_label",
        "action_command",
        "default_model",
    }
