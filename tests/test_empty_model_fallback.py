"""Tests for empty model fallback — when provider is configured but model is missing."""



class TestGetDefaultModelForProvider:
    """Unit tests for lliam_cli.models.get_default_model_for_provider."""

    def test_known_provider_returns_first_model(self):
        from lliam_cli.models import get_default_model_for_provider
        result = get_default_model_for_provider("openai-codex")
        # Should return first model from _PROVIDER_MODELS["openai-codex"]
        assert result
        assert isinstance(result, str)

    def test_openrouter_returns_empty(self):
        """OpenRouter uses dynamic model fetch, no static catalog entry."""
        from lliam_cli.models import get_default_model_for_provider
        # OpenRouter is not in _PROVIDER_MODELS — it uses live fetching
        result = get_default_model_for_provider("openrouter")
        assert result == ""

    def test_unknown_provider_returns_empty(self):
        from lliam_cli.models import get_default_model_for_provider
        assert get_default_model_for_provider("nonexistent-provider") == ""

    def test_custom_provider_returns_empty(self):
        """Custom provider has no model catalog — should return empty."""
        from lliam_cli.models import get_default_model_for_provider
        # Custom providers don't have entries in _PROVIDER_MODELS
        assert get_default_model_for_provider("some-random-custom") == ""

    def test_nous_silent_default_is_not_the_expensive_flagship(self):
        """Nous Portal is a metered aggregator whose curated list is ordered
        most-capable-first, so entry [0] is the priciest flagship
        (anthropic/claude-opus-4.8). The silent fallback (provider set, no model)
        must NOT escalate to it — otherwise an unconfigured profile silently
        bills the most expensive model. Regression for the billing footgun.
        """
        from lliam_cli.models import (
            _PROVIDER_MODELS,
            _PROVIDER_SILENT_DEFAULT_OVERRIDES,
            get_default_model_for_provider,
        )

        result = get_default_model_for_provider("nous")
        assert result, "nous must resolve to a usable default model"
        assert "opus" not in result.lower(), (
            f"silent default escalated to an expensive flagship: {result!r}"
        )
        assert result != _PROVIDER_MODELS["nous"][0], (
            "silent default must not be the most-capable/priciest catalog entry"
        )
        # The override must point at a model that actually exists in the catalog.
        assert result == _PROVIDER_SILENT_DEFAULT_OVERRIDES["nous"]
        assert result in _PROVIDER_MODELS["nous"]

    def test_override_falls_back_to_catalog_when_missing(self):
        """If an override model is no longer in the catalog, fall back to [0]
        rather than returning a stale/absent id."""
        from unittest.mock import patch

        from lliam_cli import models as models_mod

        with patch.dict(
            models_mod._PROVIDER_SILENT_DEFAULT_OVERRIDES,
            {"openai-codex": "does-not-exist-model"},
            clear=False,
        ):
            result = models_mod.get_default_model_for_provider("openai-codex")
            assert result == models_mod._PROVIDER_MODELS["openai-codex"][0]


