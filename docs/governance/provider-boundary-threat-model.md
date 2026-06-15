# Provider subprocess boundary — threat model & data-flow (AI-334)

Status: implemented (runtime + tests). Companion to
`adr-0001-cli-provider-contract.md`.

Lliam-GOV invokes third-party LLM **CLIs** (Claude Code, Codex, Gemini /
Antigravity) as child processes. This document defines the security boundary
for those subprocesses, the data sent to each provider, and the threat model.

## 1. Boundary invariants (enforced in `providers/cli/contract.py`)

| Invariant | Mechanism | Test |
|---|---|---|
| **No token read/store** | Lliam-GOV only observes a boolean `authenticated` signal; the CLI owns its auth store under `HOME`/`XDG_*`. `AuthResult` never carries a secret. | `test_contract.py`, contract docstrings |
| **Explicit cwd** | `ExecutionRequest.cwd`; when `None`, a fresh per-execution temp dir is created and removed afterwards — never the Lliam-GOV checkout cwd. | `test_subprocess_boundary.py::test_default_cwd_*` |
| **Env allowlist** | `ENV_ALLOWLIST` + `build_isolated_env()`; isolated child gets only PATH/HOME/locale/XDG vars. All `*_API_KEY` / `*_TOKEN` / `*_SECRET` are dropped. | `test_subprocess_boundary.py::test_*env*` |
| **Timeout** | `ExecutionRequest.timeout_s` wall-clock deadline; `terminate()`→`kill()`. | `test_execution_runtime.py::test_execute_times_out` |
| **Cancellation** | Cooperative `CancelToken`. | `test_execution_runtime.py::test_execute_cancels` |
| **Output-size limit** | `ExecutionRequest.max_output_bytes` (default 2 MB); runtime aborts with `OUTPUT_LIMIT`. | `test_subprocess_boundary.py::test_output_limit_aborts` |
| **Log/audit redaction** | `redaction.redact_secrets()` scrubs credential-like strings; `audit_hook` receives a content-free, redacted, truncated summary on failure only. | `test_redaction.py`, `test_subprocess_boundary.py::test_audit_hook_*` |
| **App logs ≠ provider stderr** | Provider stderr is returned in the `ExecutionResult.stderr` field / `DONE` event; it is never merged into the app logger. The web endpoint logs only tracebacks, not provider output. | code review (`hermes_cli/web_server.py` `execute_cli_provider`) |

## 2. Data-flow: what is sent to each provider

When a user selects a provider and runs a prompt via
`POST /api/providers/cli/{id}/execute`:

- **Sent to the provider CLI (stdin/args):** the user's prompt text and the
  selected model name only. No Lliam-GOV environment, no other env secrets, no
  filesystem access beyond the explicit/temp cwd.
- **Provider handles its own egress:** the CLI talks to its vendor endpoint
  using its own stored credentials. Lliam-GOV does not see or proxy that token.

| Provider CLI | Vendor endpoint (provider-owned) | Auth store (CLI-owned) | Lliam-GOV sends |
|---|---|---|---|
| Claude Code | Anthropic API | `~/.claude` / keychain | prompt + model |
| Codex | OpenAI API | Codex CLI config under `HOME` | prompt + model |
| Gemini / Antigravity | Google API | Gemini CLI config under `HOME` | prompt + model |

Lliam-GOV never adds API keys to the child env; if a user has exported one
globally, env isolation drops it before the child starts.

## 3. Threat model

| # | Threat | Mitigation (today) | Residual / flagged |
|---|---|---|---|
| T1 | **Provider CLI compromise** (malicious/backdoored binary) | env allowlist limits blast radius; explicit empty temp cwd; output cap; timeout/cancel; failures audited. | CLI integrity is provider-owned; supply-chain attestation tracked in AI-338. |
| T2 | **PATH hijacking** (attacker plants a fake `claude`/`codex`/`gemini` earlier in PATH) | detection records resolved path/version; execution uses the same allowlisted PATH. | Pinned absolute-path execution + signature check → **flagged**, depends on packaging/signing (AI-331, certs = Jerome). |
| T3 | **Stale / expired auth** | `AuthResult.expired` → `NOT_AUTHENTICATED` readiness; stream refuses with actionable `PROVIDER_AUTH`. | — |
| T4 | **Malicious cwd** (provider writes into / reads from the app tree) | explicit cwd; default = fresh temp dir, removed after run; caller cwd never deleted. | — |
| T5 | **Prompt/output logging leakage** | runtime does not log prompt/output; audit summary is redacted + truncated + content-free. | Redaction is best-effort last line of defence, not exhaustive. |
| T6 | **Environment-secret leakage to provider** | env allowlist excludes all `*_KEY`/`*_TOKEN`/`*_SECRET`. | — |
| T7 | **Update-channel compromise** (poisoned backend/app update) | — | **Flagged** — depends on signing/notarization (AI-331), release CI (AI-332, GitHub Actions offline), and the backend-distribution-source decision (Jerome). |
| T8 | **Crash-dump / core leakage** | output cap bounds captured bytes; no secrets read into process memory. | OS-level crash-dump policy + symbol stripping tracked in packaging (AI-331). |

## 4. Decision-gated items (owner: Jerome)

T2/T7/T8 cannot be fully closed here:
- **Signing/notarization certs** (Apple Developer ID, Windows Authenticode) — procurement.
- **Backend-distribution source** (signed GitHub Releases vs self-hosted) — intersects egress allowlist.
- **GitHub Actions** offline until next month — release CI / provenance can be scaffolded but not run.

Windows-specific posture (FIPS-on-Windows, POSIX guard rewrite) is parked; the
allowlist includes Windows env names defensively but Windows enforcement is out
of scope for this issue.
