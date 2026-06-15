# Approved provider CLIs & obligations outside Lliam-GOV (AI-338)

## Approved provider CLI families

| Provider family | CLI (approved) | Lliam-GOV adapter | Auth model |
|---|---|---|---|
| Anthropic | Claude Code CLI (`@anthropic-ai/claude-code`) | `providers/cli/claude_code.py` | CLI owns auth (`claude setup-token`) |
| OpenAI | Codex CLI (`@openai/codex`) | `providers/cli/codex.py` | CLI owns auth (`codex login`) |
| Google | Gemini / Antigravity CLI (`@google/gemini-cli`) | `providers/cli/gemini.py` | CLI owns auth (browser sign-in) |

No other inference providers are approved for the CLI-backed path in this
release. API-key/SDK providers are a separate, declarative surface
(`providers/` `ProviderProfile`) and are out of scope for this evidence package.

## What Lliam-GOV does NOT own (obligations that remain with the operator)

- **Provider accounts.** The user must have an account/subscription with each
  vendor they enable. Lliam-GOV neither provisions nor pays for these.
- **Rate limits & quotas.** Throttling, quotas, and plan tiers are enforced by
  the provider. A `PROVIDER_RATE_LIMIT` error originates from the vendor, not
  Lliam-GOV (the runtime marks it retryable).
- **Credential lifecycle.** Login, token refresh, and revocation happen in the
  provider CLI's own store. Lliam-GOV only reads a boolean "authenticated?"
  signal (AI-334) and never stores or transmits the token.
- **Provider availability & data handling.** When a provider is selected, the
  prompt + model name go to that provider's CLI, which sends them to the vendor
  endpoint under the vendor's terms and data-handling policy. See the
  per-provider data-flow table in
  `docs/governance/provider-boundary-threat-model.md` §2.
- **CLI integrity & updates.** The provider CLIs are third-party software on the
  user's PATH; their supply-chain integrity is the vendor's/user's
  responsibility (path-hijack mitigation is tracked as T2 in the threat model).

## Egress note

Provider CLIs make their own network calls to vendor endpoints. The Lliam-GOV
egress allowlist governs Lliam-GOV's own traffic; the **backend-distribution
source** decision (where the managed backend is fetched from on first launch)
intersects that allowlist and is **pending Jerome's decision** (AI-330).
