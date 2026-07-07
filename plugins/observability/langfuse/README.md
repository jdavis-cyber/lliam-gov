# Langfuse Observability Plugin

This plugin ships bundled with Lliam-GOV but is **opt-in** — it only loads when
you explicitly enable it.

## Enable

Pick one:

```bash
# Interactive: walks you through credentials + SDK install + enable
lliam-gov tools  # → Langfuse Observability

# Manual
pip install langfuse
lliam-gov plugins enable observability/langfuse
```

## Required credentials

Set these in `~/.hermes/.env` (or via `lliam-gov tools`):

```bash
HERMES_LANGFUSE_PUBLIC_KEY=pk-lf-...
HERMES_LANGFUSE_SECRET_KEY=sk-lf-...
HERMES_LANGFUSE_BASE_URL=https://cloud.langfuse.com   # or your self-hosted URL
```

Without the SDK or credentials the hooks no-op silently — the plugin fails
open.

## Verify

```bash
lliam-gov plugins list                 # observability/langfuse should show "enabled"
lliam-gov chat -q "hello"              # then check Langfuse for a "Lliam-GOV turn" trace
```

## Optional tuning

```bash
HERMES_LANGFUSE_ENV=production       # environment tag
HERMES_LANGFUSE_RELEASE=v1.0.0       # release tag
HERMES_LANGFUSE_SAMPLE_RATE=0.5      # sample 50% of traces
HERMES_LANGFUSE_MAX_CHARS=12000      # max chars per field (default: 12000)
HERMES_LANGFUSE_DEBUG=true           # verbose plugin logging
```

## Disable

```bash
lliam-gov plugins disable observability/langfuse
```
