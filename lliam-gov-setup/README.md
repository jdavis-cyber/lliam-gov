# lliam-gov-setup

Reproducible setup + the Claude-on-Max bridge package for **Lliam-GOV** (the
governance-hardened Hermes fork). Everything needed to install on a fresh macOS
machine, run on subscription model plans, and package the desktop app.

| File | What it is |
|---|---|
| **SETUP.md** | The full new-machine runbook (read this first). Stages 1–9 + every gotcha. |
| **install.sh** | Deploys the bridge + helper scripts into `~/.lliam-gov` and applies the deterministic config. Run after `setup-hermes.sh`. Interactive auth stays manual (SETUP.md §4–6). |
| **validate.sh** | Post-install checks: CLI, keyring, isolation, egress, bridge health, a live `claude -p` call + a bridge round-trip. |
| **claude_bridge.py** | Local OpenAI-compatible server (`127.0.0.1:8765`) that routes inference through `claude -p` (Max plan). Tiers: `off`/`read`/`pm`/`pm-write`/`agent` via `~/.lliam-gov/.bridge_env`. |
| **claude_bridge_DESIGN.md** | Design notes for the bridge's capability tiers + governance boundaries. |
| **start-lliam-gov.sh** | Launch the bridge (if down) + the desktop, pinned to `~/.lliam-gov`. |
| **lliam-project.sh** | Point Lliam at a project folder for RAG/implementation (`set`/`add`/`list`/`clear`). |

## Quick start (new machine)
```bash
cd ~ && git clone https://github.com/jdavis-cyber/lliam-gov.git && cd lliam-gov
./setup-hermes.sh && source ~/.zshrc
./lliam-gov-setup/install.sh
# then the interactive auth steps in SETUP.md §4–6, then:
./lliam-gov-setup/validate.sh
```

## Secrets
No secrets are committed. Tokens/keys live only in `~/.lliam-gov/` files
(`.claude_token`, `.linear_key`, `auth.json`), created by the interactive auth
steps. The bridge reads them at runtime; GitHub uses the live `gh auth token`.

## Companion repo changes (committed alongside this dir)
- `agent/anthropic_adapter.py` — Claude OAuth token endpoint fix (→ platform.claude.com).
- `apps/desktop/electron/main.cjs` — `HERMES_HOME` defaults to `~/.lliam-gov`; app spawns/stops the bridge.
- `apps/desktop/package.json` — packaged-app identity (productName `Lliam-GOV`, appId `gov.lliam.desktop`, unsigned).
- `apps/desktop/assets/icon.*`, `public/apple-touch-icon.png` — Lliam-GOV (LG) app icon.
