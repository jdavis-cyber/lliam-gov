"""CLI-backed provider runtime contract and adapters (Phase 1 spine).

Unlike :mod:`providers` (declarative API-key/SDK ``ProviderProfile`` objects),
this subpackage models providers whose **authentication and inference are owned
by an external command-line tool** — Claude Code CLI, Codex CLI, and
Gemini/Antigravity CLI.

Design rules (AI-326 / AI-327 / AI-328 / AI-334):

* Lliam-GOV NEVER reads or stores provider tokens. The CLI owns auth; we only
  observe *whether* a provider is authenticated (a boolean signal), never the
  secret itself.
* Provider readiness is reported without API keys: a provider can be
  ``not_installed``, ``not_authenticated``, ``ready``, ``degraded``, or
  ``unavailable``.
* Adapters are driven through injectable probes (``which`` / ``run`` / ``home``)
  so they can be unit-tested against fake CLI binaries without touching the
  real environment.

This is the Phase 1 *spine* — the contract plus one real adapter. The other
adapters (Codex, Gemini) and the desktop first-run UX (AI-329) build on top.
"""

from __future__ import annotations

from providers.cli.contract import (  # noqa: F401
    AuthResult,
    BaseCLIProvider,
    CLIProvider,
    DetectResult,
    ExecutionRequest,
    ExecutionResult,
    HealthResult,
    InvocationMode,
    ProviderCapabilities,
    ProviderError,
    ProviderErrorKind,
    ProviderReadinessReport,
    Readiness,
    normalize_readiness,
)
from providers.cli.claude_code import ClaudeCodeCLIProvider  # noqa: F401
from providers.cli.codex import CodexCLIProvider  # noqa: F401
from providers.cli.gemini import GeminiCLIProvider  # noqa: F401
from providers.cli.registry import (  # noqa: F401
    all_providers,
    get_provider,
    probe_all,
)

__all__ = [
    "AuthResult",
    "BaseCLIProvider",
    "CLIProvider",
    "ClaudeCodeCLIProvider",
    "CodexCLIProvider",
    "DetectResult",
    "ExecutionRequest",
    "ExecutionResult",
    "GeminiCLIProvider",
    "HealthResult",
    "InvocationMode",
    "ProviderCapabilities",
    "ProviderError",
    "ProviderErrorKind",
    "ProviderReadinessReport",
    "Readiness",
    "all_providers",
    "get_provider",
    "normalize_readiness",
    "probe_all",
]
