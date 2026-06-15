"""Registry of CLI-backed provider adapters (AI-328).

A thin, dependency-light registry the backend/desktop can iterate to report
provider readiness without API keys. Adapters are constructed lazily so probing
the registry never touches the environment until ``probe()`` is called.
"""

from __future__ import annotations

from collections.abc import Iterable

from providers.cli.claude_code import ClaudeCodeCLIProvider
from providers.cli.codex import CodexCLIProvider
from providers.cli.contract import CLIProvider, ProviderReadinessReport
from providers.cli.gemini import GeminiCLIProvider

# Ordered: Anthropic, OpenAI, Google — matches the epic's provider families.
_PROVIDER_CLASSES = (
    ClaudeCodeCLIProvider,
    CodexCLIProvider,
    GeminiCLIProvider,
)


def all_providers() -> list[CLIProvider]:
    """Return a fresh instance of every registered CLI provider adapter."""
    return [cls() for cls in _PROVIDER_CLASSES]


def get_provider(provider_id: str) -> CLIProvider | None:
    """Return a provider adapter by its capability id, or None."""
    for provider in all_providers():
        if provider.capabilities.id == provider_id:
            return provider
    return None


def probe_all(providers: Iterable[CLIProvider] | None = None) -> list[ProviderReadinessReport]:
    """Probe every provider and return normalized readiness reports."""
    targets = list(providers) if providers is not None else all_providers()
    return [p.probe() for p in targets]
