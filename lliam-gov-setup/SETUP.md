# Lliam-GOV — full setup runbook (fresh machine)

This is an executable runbook for an agent (or person) to install **Lliam-GOV**
— a governance-hardened NousResearch/Hermes fork — on a new macOS machine, run
it on **subscription** model plans (OpenAI Codex and/or Claude Max), and package
it as a real desktop app. It captures every non-obvious fix discovered during the
working install, plus validation tests.

> Target: macOS (Apple Silicon). The CLI command is `hermes` (the Hermes→Lliam
> rename was intentionally NOT done; only the desktop wordmark says LLIAM-GOV).
> Paths use `~` so they port across users. Run stages in order; **verify each
> before moving on**.

---

## 0. Architecture (what you're building)

```
Lliam-GOV desktop (Electron)  ── isolated to HERMES_HOME=~/.lliam-gov ──┐
   │  model calls (OpenAI chat-completions)                            │
   ▼                                                                   │
custom provider  →  http://127.0.0.1:8765/v1  (claude_bridge.py, loopback)
   │                     └─ claude -p (CLAUDE_CODE_OAUTH_TOKEN) → Claude Max
   └─ OR provider=openai-codex → chatgpt.com/backend-api/codex → Codex/gpt-5.5
```

- **Isolated home:** Lliam-GOV is pinned to **`~/.lliam-gov`** via `HERMES_HOME`
  (first-run writes config, egress allowlist, and auth there). On a machine that
  *also* runs the upstream EA Hermes (which defaults to `~/.hermes`), this pin is
  what keeps the two from sharing sessions, skills, auth, or gateway — but no EA
  install is required, and a clean GOV-only box never creates `~/.hermes`.
- **Two model paths:** Codex (`gpt-5.5`, native HTTP) and Claude-on-Max (via the
  local `claude_bridge.py` that shells out to `claude -p`).
- **The bridge** is what lets Claude run on the Max subscription (first-party
  Claude Code), instead of the metered direct Anthropic API.

---

## 1. Prereqs

```bash
sw_vers -productVersion; uname -m          # macOS version + arch (expect arm64)
git --version; node --version; npm --version; python3 --version; xcode-select -p
```
Need: git, **Node ≥ 20**, npm, python3, Xcode CLT. Install missing ones
(`xcode-select --install`; Node via the official installer or Homebrew) before
continuing.

---

## 2. Clone + Python/CLI

```bash
cd ~ && git clone https://github.com/jdavis-cyber/lliam-gov.git
cd lliam-gov
./setup-hermes.sh            # installs uv, Python 3.11, creates venv, installs .[all], symlinks `hermes`
source ~/.zshrc
hermes --version             # expect: Hermes Agent v0.16.0 (...)
```
Decline the interactive setup wizard at the end (onboarding happens in the app).

### 2a. GOTCHA — `keyring` is missing from the venv
The venv built by `uv sync` does **not** include `keyring`, but the governance
home uses at-rest-encrypted `auth.json` → `No module named 'keyring'` and auth
won't save/decrypt. Fix (re-run after any `uv sync`/`setup-hermes.sh`, which wipe it):
```bash
cd ~/lliam-gov && VIRTUAL_ENV="$PWD/venv" uv pip install keyring
venv/bin/python -c "import keyring; print('keyring OK', keyring.get_keyring().__class__.__name__)"
```

---

## 3. Isolated governance home + config

Everything Lliam-GOV runs with **`HERMES_HOME=~/.lliam-gov`**. Create/seed it by
launching the desktop once (Stage 7a) under that env — first-run writes
`~/.lliam-gov/config.yaml`, `egress-allowlist.txt`, etc. — OR run the CLI once:
`HERMES_HOME=~/.lliam-gov ~/lliam-gov/venv/bin/hermes status`.

### 3a. Egress allowlist (governance firewall, fail-closed deny-all)
`~/.lliam-gov/egress-allowlist.txt` — one `host:port` per line. Required hosts:
```
api.anthropic.com:443        # Claude model API
chatgpt.com:443              # Codex/gpt-5.5 backend
auth.openai.com:443          # Codex OAuth refresh
console.anthropic.com:443    # Claude OAuth token exchange/refresh
platform.claude.com:443      # Claude OAuth token exchange/refresh
```
The bridge is on `127.0.0.1` (loopback is egress-exempt). `claude -p`'s own
network goes through a subprocess and is NOT governed by this allowlist.

### 3b. Restore the EA `hermes` symlink (if an EA exists on the machine)
`setup-hermes.sh` repoints `~/.local/bin/hermes` to this repo. If the machine
also has an EA Hermes at `~/.hermes/hermes-agent`, point the symlink back:
`ln -sf ~/.hermes/hermes-agent/venv/bin/hermes ~/.local/bin/hermes` and always
invoke Lliam-GOV via `~/lliam-gov/venv/bin/hermes` (never the bare `hermes`).

---

## 4. Provider auth A — OpenAI Codex (subscription, gpt-5.5)

In the desktop first-run (Stage 7a) pick **"OpenAI OAuth (ChatGPT)"** → device
code → authorize in browser with the ChatGPT/Codex subscription account. Then:
```bash
HERMES_HOME=~/.lliam-gov ~/lliam-gov/venv/bin/hermes config set model.default gpt-5.5
HERMES_HOME=~/.lliam-gov ~/lliam-gov/venv/bin/hermes config set model.provider openai-codex
HERMES_HOME=~/.lliam-gov ~/lliam-gov/venv/bin/hermes config set model.openai_runtime auto
```
GOTCHA: do NOT use `openai_runtime: codex_app_server` (needs an uninstalled
`codex` CLI binary → empty responses). `auto` uses the HTTP backend.

This provider is **self-contained**: `gpt-5.5` + `auto` makes native HTTPS calls
to `chatgpt.com` and needs **no** `codex` CLI binary — its only requirements are
the OpenAI OAuth token (`auth.json`, written to `~/.lliam-gov`) and the egress
hosts in §3a. The `codex`/`gemini` CLIs are optional; install them to the same
npm global prefix (`npm i -g @openai/codex @google/gemini-cli`) only if you want
those runtimes. So **both** providers install without ever touching `~/.hermes`.

---

## 5. Provider auth B — Claude on Max via the bridge

This is what makes Claude run on the **Max subscription** (not the metered API).

### 5a. Install the Claude Code CLI + mint a token
Uses the system Node from §1 — the CLI installs into your npm global prefix
(`npm prefix -g`/bin) and is exposed on the bridge's PATH via `~/.local/bin`.
No `~/.hermes` and no EA install required.
```bash
npm install -g @anthropic-ai/claude-code      # lands in your npm global prefix (on PATH)
ln -sf "$(command -v claude)" ~/.local/bin/claude   # expose on the bridge PATH (/opt/homebrew/bin:~/.local/bin)
claude setup-token                            # browser auth with Max → prints a token
```
`setup-token` prints a token for the `CLAUDE_CODE_OAUTH_TOKEN` env var (it does
NOT update the Keychain). Save it (value never echoed):
```bash
( umask 077; printf 'CLAUDE_CODE_OAUTH_TOKEN=%s\n' 'PASTE_TOKEN' > ~/.lliam-gov/.claude_token )
```
Verify Max actually serves it:
```bash
set -a; . ~/.lliam-gov/.claude_token; set +a
echo "Reply with only OK" | claude -p --output-format json --model sonnet --allowedTools "" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('is_error',d.get('is_error'),d.get('result'))"
```

### 5b. Deploy the bridge + point the model at it
The bridge package (this directory) deploys to `~/.lliam-gov`:
```bash
~/lliam-gov/lliam-gov-setup/install.sh        # copies bridge+scripts, applies config (see below)
```
Or manually:
```bash
cp ~/lliam-gov/lliam-gov-setup/{claude_bridge.py,start-lliam-gov.sh,lliam-project.sh} ~/.lliam-gov/
chmod +x ~/.lliam-gov/*.sh
HERMES_HOME=~/.lliam-gov ~/lliam-gov/venv/bin/hermes config set model.provider custom
HERMES_HOME=~/.lliam-gov ~/lliam-gov/venv/bin/hermes config set model.base_url http://127.0.0.1:8765/v1
HERMES_HOME=~/.lliam-gov ~/lliam-gov/venv/bin/hermes config set model.default claude-via-cli
HERMES_HOME=~/.lliam-gov ~/lliam-gov/venv/bin/hermes config set model.api_key sk-local-bridge
```
In the desktop, the bridge model shows as **"Via Cli"** in the model picker.

### 5c. GOTCHA — the OAuth token-endpoint fix (already patched in this repo)
`agent/anthropic_adapter.py` `_OAUTH_TOKEN_URL` upstream pointed at the dead
`console.anthropic.com/v1/oauth/token` (404 on the initial code exchange). This
repo changes it to `https://platform.claude.com/v1/oauth/token`. If you ever see
"Token exchange failed: 404" from `hermes auth add anthropic --type oauth`, that's
the patch.

### 5d. GOTCHA — clean subprocess env (already handled in `claude_bridge.py`)
The bridge runs `claude` in a **minimal env** (PATH/HOME + only
`CLAUDE_CODE_OAUTH_TOKEN`). If it inherits an outer Claude Code session's
`CLAUDE_CODE_*` vars, the nested `claude -p` lands on a metered path → "out of
extra usage". `_clean_env()` scrubs them.

---

## 6. Capability tiers + tools (the `pm`/`agent` stack)

The bridge reads **`CLAUDE_BRIDGE_TOOLS`** from `~/.lliam-gov/.bridge_env`
(default `off`). Tiers (each opt-in, responder as floor):

| Tier | Grants |
|---|---|
| `off` | pure chat (fallback) |
| `read` | Read/Grep/Glob + **WebSearch** (research), sandboxed to the workspace |
| `pm` | read + **GitHub & Linear MCP, read-only** |
| `pm-write` | pm + GitHub/Linear **writes** (create/update issues) |
| `agent` | implement: Read/Grep/Glob/Edit/Write in the project folder (no raw Bash) |

Set with e.g. `echo CLAUDE_BRIDGE_TOOLS=pm > ~/.lliam-gov/.bridge_env`.

### 6a. GitHub MCP — reuses the `gh` CLI login
```bash
gh auth status         # ensure logged in (scopes repo, workflow, read:org)
```
The bridge fetches the token live via `gh auth token` (read-only tier uses
`https://api.githubcopilot.com/mcp/readonly`). No key file needed.

### 6b. Linear MCP — needs a Personal API Key
Linear's official MCP is OAuth-only, so the bridge uses a **local** key-based
server (`npx -y @tacticlaunch/mcp-linear`). Create a Linear Personal API Key
(Settings → Security & access) and save it:
```bash
printf 'Paste Linear API key: '; read -rs K; echo
( umask 077; printf 'LINEAR_API_KEY=%s\n' "$K" > ~/.lliam-gov/.linear_key ); unset K
```

### 6c. Project folder (RAG / implementation target)
Use the desktop's native picker: **Settings → Default project directory** → it
writes `~/Library/Application Support/Hermes/project-dir.json` `{"dir":"..."}`,
which the bridge reads and exposes to Claude (read-only in pm/read; writable in
`agent`). No terminal needed.

---

## 7. Desktop app

### 7a. Run (dev)
```bash
cd ~/lliam-gov && npm install                                  # workspace install at ROOT first
cd apps/desktop && env HERMES_HOME=~/.lliam-gov npm start       # tsc+vite build, launch Electron
```
Confirm the blue **LLIAM-GOV** wordmark.

### 7b. Build the real packaged app (`/Applications/Lliam-GOV.app`)
Build config (in `apps/desktop/package.json`, already set here): productName
`Lliam-GOV`, appId `gov.lliam.desktop`, `mac.identity: null`, icon `assets/icon`.
Code (in `apps/desktop/electron/main.cjs`, already set here): `resolveHermesHome()`
falls back to `~/.lliam-gov` (never the EA), and `startLliamBridge()`/`stopLliamBridge()`
launch/kill the bridge with the app.
```bash
cd ~/lliam-gov/apps/desktop
CSC_IDENTITY_AUTO_DISCOVERY=false npm run pack          # electron-builder --dir (unsigned)
codesign --force --deep --sign - release/mac-arm64/Lliam-GOV.app   # arm64 REQUIRES a signature
cp -R release/mac-arm64/Lliam-GOV.app /Applications/
```

### 7c. GOTCHA — packaged-app backend bootstrap (404)
A packaged app expects an installed backend at `HERMES_HOME/hermes-agent` and
otherwise tries to fresh-install via upstream `install.sh` (404 on the fork).
Point it at the repo install:
```bash
ln -sfn ~/lliam-gov ~/.lliam-gov/hermes-agent
cat > ~/lliam-gov/.hermes-bootstrap-complete <<EOF
{ "schemaVersion": 1, "pinnedCommit": "$(git -C ~/lliam-gov rev-parse HEAD)",
  "pinnedBranch": "main", "adopted": true,
  "completedAt": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)", "desktopVersion": "0.15.1" }
EOF
```
Then `open -a /Applications/Lliam-GOV.app`. (Locally-built ⇒ no quarantine ⇒ no
Gatekeeper prompt. If a downloaded copy is ever blocked: right-click → Open once.)

---

## 8. Validation

Run `~/lliam-gov/lliam-gov-setup/validate.sh` (see that script). It checks: CLI
version, keyring import, isolation (`HERMES_HOME`, EA untouched), egress hosts,
bridge health, a `claude -p` Max-plan call, and a bridge `/v1/chat/completions`
round-trip. Manual end-to-end: launch the app, send "reply with your model
family" → expect a real Claude (or gpt-5.5) answer.

---

## 9. Gotchas quick-reference

1. **keyring** missing from venv → reinstall after any `uv sync` (§2a).
2. **`codex_app_server`** runtime needs an uninstalled binary → use `auto` (§4).
3. **Egress deny-all** → add the 5 hosts (§3a).
4. **Claude OAuth 404** → `_OAUTH_TOKEN_URL` = platform.claude.com (§5c, patched).
5. **"out of extra usage"** via the bridge → clean subprocess env (§5d, handled);
   if it persists, your Max usage window is genuinely exhausted.
6. **Linear** is OAuth-only remotely → use the local key-based MCP (§6b).
7. **Packaged app 404** → symlink `hermes-agent` + bootstrap marker (§7c).
8. **arm64 unsigned app won't launch** → `codesign --force --deep -s -` (§7b).
9. **`~/.local/bin/hermes`** may belong to an EA — use the repo venv binary.
