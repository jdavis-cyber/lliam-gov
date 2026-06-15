# ADR-0001: CLI-backed provider runtime contract

**Status:** Accepted (Phase 1 spine) — AI-326 / AI-327 / AI-328 / AI-334
**Date:** 2026-06-15

## Context

Lliam-GOV must run on a fresh machine and use a **locally authenticated LLM CLI**
for inference — Claude Code CLI (Anthropic), Codex CLI (OpenAI), and
Gemini/Antigravity CLI (Google). These are not API-key-backed SDKs: the CLI owns
authentication, and the app must report provider readiness *without* collecting
or storing API keys.

The existing `providers/` package models declarative, API-key/SDK
`ProviderProfile` objects. CLI-backed providers are a distinct surface and live
under `providers/cli/`.

## Decision

Define a common provider capability contract (`providers/cli/contract.py`):

- **Capability model** — `ProviderCapabilities`: id, display name, invocation
  mode (non-interactive / interactive / adapter-shim), streaming, cancellation,
  model-list support, and `owns_auth`.
- **Probes** — `detect()` (installed? path, version), `check_auth()` (a boolean
  authenticated signal + non-secret source label), `list_models()`,
  `default_model()`.
- **Normalized readiness** — `normalize_readiness(detect, auth)` collapses
  probes into one value: `not_installed`, `not_authenticated`, `ready`,
  `degraded`, `unavailable`. Pure function; exhaustively unit-tested.
- **Error taxonomy** — `ProviderErrorKind` distinguishes app setup, provider not
  installed, provider auth, provider rate limit, provider execution, timeout,
  and cancellation, so UX copy (AI-329) can address the right failure.
- **Report shape** — `ProviderReadinessReport.to_dict()` is what the backend
  (`/api/model/options`) and desktop first-run UX render.
- **Execution skeleton** — `BaseCLIProvider.execute()` refuses to run unless the
  provider is `ready`, isolates env, captures stdout/stderr, and maps failures
  to the taxonomy.

First real adapter: `providers/cli/claude_code.py` (`ClaudeCodeCLIProvider`),
with detect + auth + health probes. All external touchpoints are injectable for
hermetic tests against fake CLI binaries.

## Threat boundaries

- **No token reads, ever (AI-334).** Auth state is inferred from credential-file
  *presence* (or an injected CLI-driven probe), never by opening/parsing the
  token. `AuthResult` carries only a boolean and a non-secret source label. A
  regression test pins this: a credential file with invalid contents must still
  resolve as authenticated without being parsed.
- **No secret transit.** Lliam-GOV never reads provider browser sessions, local
  credential stores, or token files for their values.
- **Subprocess isolation.** `execute()` can start from a minimal environment
  (`PATH`/`HOME` only) so inherited secrets are not leaked into provider CLIs.

## Scope of this ADR (spine only)

This establishes the contract plus one adapter and its tests. Out of scope here:
the Codex and Gemini adapters (AI-328 remainder), streaming/cancellation
runtime, refactoring `web_server.py`'s ad-hoc provider status onto this
contract, and the desktop first-run UX (AI-329).
