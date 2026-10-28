"""Tests for opencode-go / opencode-zen flat-namespace model handling.

OpenCode Go is NOT a vendor/model aggregator like OpenRouter — its
``/v1/models`` endpoint returns bare IDs (``minimax-m2.7``, ``deepseek-v4-flash``)
and the inference API rejects vendor-prefixed names with HTTP 401
"Model not supported".

Two bugs this exercises:

1. ``switch_model('deepseek-v4-flash', current_provider='opencode-go')`` used
   to silently switch the user off opencode-go to native ``deepseek`` because
   ``detect_provider_for_model`` matched the bare name against the static
   deepseek catalog.  Fix: once step d matches the model in the current
   aggregator's live catalog, skip ``detect_provider_for_model``.

2. ``normalize_model_for_provider('minimax/minimax-m2.7', 'opencode-go')``
   used to pass the ``minimax/`` prefix through unchanged.  When user configs
   contained prefixed fallback entries (commonly copied from aggregator slugs),
   the fallback activation path sent ``minimax/minimax-m2.7`` to opencode-go
   which returned HTTP 401.  Fix: opencode-go/opencode-zen strip ANY leading
   ``vendor/`` prefix because their APIs are flat-namespace.
"""

from unittest.mock import patch

from lliam_cli.model_normalize import normalize_model_for_provider
from lliam_cli.model_switch import switch_model


# Live catalog opencode-go currently returns from /v1/models (snapshot).
_OPENCODE_GO_LIVE = [
    "minimax-m2.7", "minimax-m2.5",
    "kimi-k2.6", "kimi-k2.5",
    "glm-5.1", "glm-5",
    "deepseek-v4-pro", "deepseek-v4-flash",
    "qwen3.6-plus", "qwen3.5-plus",
    "mimo-v2-pro", "mimo-v2-omni", "mimo-v2.5-pro", "mimo-v2.5",
]


# ---------------------------------------------------------------------------
# normalize_model_for_provider: strip vendor prefix for flat-namespace providers
# ---------------------------------------------------------------------------


def test_opencode_go_strips_deepseek_prefix():
    assert normalize_model_for_provider(
        "deepseek/deepseek-v4-flash", "opencode-go"
    ) == "deepseek-v4-flash"


def test_opencode_go_strips_minimax_prefix():
    assert normalize_model_for_provider(
        "minimax/minimax-m2.7", "opencode-go"
    ) == "minimax-m2.7"


def test_opencode_go_strips_moonshotai_prefix():
    # Moonshot's aggregator vendor is `moonshotai/...` — a common copy-paste
    # from OpenRouter slugs.  opencode-go serves it bare as `kimi-k2.6`.
    assert normalize_model_for_provider(
        "moonshotai/kimi-k2.6", "opencode-go"
    ) == "kimi-k2.6"


def test_opencode_go_bare_name_unchanged():
    assert normalize_model_for_provider(
        "kimi-k2.6", "opencode-go"
    ) == "kimi-k2.6"


def test_opencode_go_preserves_dot_versioning():
    # opencode-go uses dot-versioned IDs (`mimo-v2.5-pro`, not hyphen).
    assert normalize_model_for_provider(
        "xiaomi/mimo-v2.5-pro", "opencode-go"
    ) == "mimo-v2.5-pro"


def test_opencode_zen_still_hyphenates_claude():
    # Regression: opencode-zen's Claude hyphen conversion must still work.
    assert normalize_model_for_provider(
        "anthropic/claude-sonnet-4.6", "opencode-zen"
    ) == "claude-sonnet-4-6"


def test_opencode_zen_bare_claude_hyphenated():
    assert normalize_model_for_provider(
        "claude-sonnet-4.6", "opencode-zen"
    ) == "claude-sonnet-4-6"


def test_opencode_zen_strips_arbitrary_vendor_prefix():
    assert normalize_model_for_provider(
        "minimax/minimax-m2.5-free", "opencode-zen"
    ) == "minimax-m2.5-free"


def test_openrouter_still_prepends_vendor():
    # Regression: real aggregators must still get vendor/model format.
    assert normalize_model_for_provider(
        "claude-sonnet-4.6", "openrouter"
    ) == "anthropic/claude-sonnet-4.6"


# ---------------------------------------------------------------------------
# switch_model: live-catalog match on opencode-go must not trigger
# cross-provider auto-switch via detect_provider_for_model
# ---------------------------------------------------------------------------


def _run_switch(raw_input: str, live_catalog=None, **extra):
    """Call switch_model with opencode-go as current provider, mocking the
    live catalog so the test doesn't hit the network.

    Both live-catalog lookups are pinned to the same snapshot: the step-d
    catalog search (``list_provider_models``) and the ``/v1/models`` probe
    inside ``validate_requested_model`` (``fetch_api_models``).  Leaving the
    probe live made the result track whatever opencode.ai lists today and
    let its auto-correct rewrite the requested ID."""
    catalog = list(_OPENCODE_GO_LIVE if live_catalog is None else live_catalog)
    defaults = dict(
        current_provider="opencode-go",
        current_model="kimi-k2.6",
        current_base_url="https://opencode.ai/zen/go/v1",
        current_api_key="sk-test-opencode-go",
        is_global=False,
    )
    defaults.update(extra)

    def fake_list_provider_models(provider: str):
        if provider == "opencode-go":
            return list(catalog)
        # For other providers, return empty so tests don't depend on them.
        return []

    def fake_fetch_api_models(api_key, base_url, *args, **kwargs):
        if "opencode.ai/zen/go" in str(base_url or ""):
            return list(catalog)
        # Any other endpoint is unreachable in tests.
        return None

    with patch(
        "lliam_cli.model_switch.list_provider_models",
        side_effect=fake_list_provider_models,
    ), patch(
        "lliam_cli.models.fetch_api_models",
        side_effect=fake_fetch_api_models,
    ) as fetch_mock:
        result = switch_model(raw_input=raw_input, **defaults)
    # Guard the isolation itself: validation must have consulted the pinned
    # snapshot rather than a live endpoint.
    assert fetch_mock.called, "validate_requested_model bypassed the pinned /v1/models probe"
    return result


def test_deepseek_v4_flash_stays_on_opencode_go():
    """Regression: ``/model deepseek-v4-flash`` while on opencode-go must
    NOT switch to native deepseek just because deepseek's static catalog
    also contains that name."""
    result = _run_switch("deepseek-v4-flash")
    assert result.target_provider == "opencode-go", (
        f"Expected to stay on opencode-go, got {result.target_provider}. "
        f"detect_provider_for_model hijacked the bare name."
    )
    assert result.new_model == "deepseek-v4-flash"


def test_deepseek_v4_pro_stays_on_opencode_go():
    """Same bug class as the flash variant."""
    result = _run_switch("deepseek-v4-pro")
    assert result.target_provider == "opencode-go"
    assert result.new_model == "deepseek-v4-pro"


def test_kimi_k2_6_stays_on_opencode_go():
    """Regression guard: this path was always working, keep it working."""
    result = _run_switch("kimi-k2.6", current_model="deepseek-v4-pro")
    assert result.target_provider == "opencode-go"
    assert result.new_model == "kimi-k2.6"


def test_deepseek_v4_flash_exact_id_not_rewritten_to_newer_neighbor():
    """When opencode-go lists both ``deepseek-v4-flash`` and a newer
    neighbour ``deepseek-v4.1-flash``, an exact request must keep the exact
    ID.  Fuzzy auto-correct is only for IDs the catalog does not list."""
    catalog = _OPENCODE_GO_LIVE + ["deepseek-v4.1-flash"]
    result = _run_switch("deepseek-v4-flash", live_catalog=catalog)
    assert result.success
    assert result.target_provider == "opencode-go"
    assert result.new_model == "deepseek-v4-flash"
    assert "Auto-corrected" not in (result.warning_message or "")


def test_deepseek_v4_1_flash_exact_id_stays_on_opencode_go():
    """The newer neighbour also resolves to itself, not back to v4."""
    catalog = _OPENCODE_GO_LIVE + ["deepseek-v4.1-flash"]
    result = _run_switch("deepseek-v4.1-flash", live_catalog=catalog)
    assert result.target_provider == "opencode-go"
    assert result.new_model == "deepseek-v4.1-flash"


def test_deepseek_v4_pro_unaffected_by_flash_neighbor():
    """Adding a newer flash variant must not disturb the pro alias."""
    catalog = _OPENCODE_GO_LIVE + ["deepseek-v4.1-flash"]
    result = _run_switch("deepseek-v4-pro", live_catalog=catalog)
    assert result.target_provider == "opencode-go"
    assert result.new_model == "deepseek-v4-pro"
