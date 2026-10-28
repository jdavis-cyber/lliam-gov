"""Strict auxiliary routing validates the concrete client endpoint."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from lliam_cli.auth import AuthError
import agent.auxiliary_client as aux


@pytest.fixture
def strict_aux(monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.provider_allowlist.validate_provider",
        lambda provider, base_url, **kw: SimpleNamespace(
            disposition="deny" if "openrouter.ai" in base_url else "allow",
            reason="endpoint not approved",
        ),
    )


def test_direct_auxiliary_client_is_checked(strict_aux, monkeypatch):
    client = SimpleNamespace(base_url="https://openrouter.ai/api/v1")
    monkeypatch.setattr(aux, "_resolve_provider_client_unchecked", lambda **kw: (client, "m"))
    with pytest.raises(AuthError, match="blocked by governance"):
        aux.resolve_provider_client("openrouter", "m")


def test_auto_fallback_client_is_checked(strict_aux, monkeypatch):
    client = SimpleNamespace(base_url="https://openrouter.ai/api/v1")
    monkeypatch.setattr(aux, "_resolve_auto_unchecked", lambda **kw: (client, "m"))
    with pytest.raises(AuthError, match="blocked by governance"):
        aux._resolve_auto()
