# Model-endpoint posture — subscription-default (operator runbook)

**Control:** ISO/IEC 27001 A.5.23 (information security for use of cloud services);
supports the program requirement that the agent run on **subscription plans by
default, with API keys/rates as the fallback only.** Verified against the clean
Hermes v2026.6.5 rebuild (2026-06-16).

## Invariant

> Lliam-GOV reaches a model through a **subscription OAuth** provider by default.
> Metered **API-key** providers are a deliberate, secondary fallback — never the
> default path.

## Evidence (verifiable in code)

Source of truth: `hermes_cli/auth.py` (provider registry) and
`agent/anthropic_adapter.py` (auth routing).

- **OpenAI / Codex → subscription.** Provider `openai-codex` is
  `auth_type="oauth_external"` with inference at `https://chatgpt.com/backend-api/codex`
  (`DEFAULT_CODEX_BASE_URL`) — the ChatGPT/Codex **subscription** endpoint, not the
  metered API. The separate `openai-api` (`auth_type="api_key"`) is the fallback.
- **Anthropic / Claude → subscription.** The `anthropic` provider accepts
  `CLAUDE_CODE_OAUTH_TOKEN`, and `anthropic_adapter.py` routes Claude Code OAuth
  setup-tokens (`sk-ant-oat*`) as Bearer/OAuth with the Claude Code identity headers
  — the **subscription** path. `ANTHROPIC_API_KEY` (`sk-ant-api*`) is the fallback on
  the same provider.
- **Selection UX defaults to subscription.** The desktop first-run picker
  (`apps/desktop/src/components/chat/.../desktop-onboarding-overlay.tsx`) features the
  subscription option as `RECOMMENDED` ("One subscription … the recommended way to run
  Hermes"); "I have an API key" is a secondary link.
- **Registry ratio:** 6 OAuth/subscription providers vs 27 api-key (fallback)
  providers; no path silently defaults to a metered API key.

## Operator procedure (per host — e.g., the accredited Mac Mini)

1. **Authenticate by subscription, not key:**
   - OpenAI/Codex: select **OpenAI Codex** (OAuth) in the desktop picker, or
     `lliam-gov auth login openai-codex`, and complete the browser device-code step.
     This uses your ChatGPT/Codex subscription.
   - Claude: obtain a Claude Code OAuth token on the host (`claude setup-token` under
     your Claude subscription) so `CLAUDE_CODE_OAUTH_TOKEN` is present; the adapter
     uses it as OAuth.
2. **Only if no subscription is available**, fall back to an API key
   (`openai-api` / `ANTHROPIC_API_KEY`). Treat this as an exception, not the norm.
3. Credentials persist encrypted at rest (keyring-anchored `key_manager`); the
   dashboard/desktop backend is loopback-only (A.8.22).

## Posture notes / residual

- Subscription is the **default by design and UX**, not yet a hard-blocking control;
  enforcing "refuse metered API-key unless explicitly overridden" is a tracked
  optional hardening (provider-layer work, scoped separately).
- Egress to the provider endpoints must be permitted by the host network policy
  (e.g., `chatgpt.com`, `api.openai.com`, `api.anthropic.com`). The rebuild sandbox
  blocks OpenAI egress, which is why live subscription prompts run on the operator
  host, not the build container.
