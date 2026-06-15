#!/usr/bin/env bash
# ============================================================================
#  Lliam-GOV — One-Command Governed Install  (macOS · demo / eval posture)
#  J. DAVIS · Executive Architect — AI Governance & Strategy
#
#  Run from the repo root:
#      bash scripts/install-governed-macbook.sh
#
#  Posture: personal MacBook, NO CUI in scope. All governed controls are ON;
#  the FIPS hard-gate is waived for demo via LLIAM_GOV_ALLOW_NON_FIPS=1
#  (POA&M AI-282). NEVER use this profile on a Katmai-managed / CUI device.
# ============================================================================
set -euo pipefail

CYAN=$'\033[38;2;0;168;255m'; GOLD=$'\033[38;2;201;168;76m'
DIM=$'\033[2m'; BOLD=$'\033[1m'; RED=$'\033[31m'; NC=$'\033[0m'
say(){ printf '%s\n' "$*"; }

printf '\n%s%s  ◆  LLIAM-GOV — Governed Install  (macOS · demo/eval)%s\n' "$CYAN" "$BOLD" "$NC"
printf '%s      J. DAVIS · Executive Architect — AI Governance & Strategy%s\n\n' "$DIM" "$NC"

REPO_ROOT="$(pwd)"

# 0 — preconditions ----------------------------------------------------------
if ! grep -q '^name = "lliam-gov"' "$REPO_ROOT/pyproject.toml" 2>/dev/null; then
  printf '%s✗ Run this from the lliam-gov repo root (the folder with pyproject.toml).%s\n' "$RED" "$NC" >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  printf '%s✗ Do not run as root — run as your normal Mac user.%s\n' "$RED" "$NC" >&2
  exit 1
fi

# 1 — uv (Python package manager) --------------------------------------------
if ! command -v uv >/dev/null 2>&1; then
  say "→ Installing uv (one-time)…"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

# 2 — dependencies -----------------------------------------------------------
say "→ Installing dependencies (uv sync) — the first run can take a few minutes…"
uv sync

# 3 — governed workspace -----------------------------------------------------
HERMES_HOME="${HERMES_HOME:-$HOME/.lliam-gov}"
say "→ Governed workspace: $HERMES_HOME  (private, 0700)"
mkdir -p "$HERMES_HOME"
chmod 700 "$HERMES_HOME"

# 4 — egress allowlist (deny-all is the default) -----------------------------
ALLOW="$HERMES_HOME/egress-allowlist.txt"
if [ ! -f "$ALLOW" ]; then
  # Deny-all is the default. Seed exactly the endpoints the three supported
  # provider CLIs (Claude Code / Codex / Gemini) need to authenticate and run
  # inference — nothing else. Without these, a Codex or Gemini turn fails
  # fail-closed with "… is not on the Lliam-GOV allowlist" even though the
  # provider shows "Ready". Add your own hosts below as needed.
  cat > "$ALLOW" <<'ALLOWEOF'
# One host[:port] per line. Deny-all is the default — add only what you need.
# --- Anthropic / Claude Code ---
api.anthropic.com:443
console.anthropic.com:443
platform.claude.com:443
# --- OpenAI Codex (ChatGPT backend + OAuth refresh) ---
chatgpt.com:443
auth.openai.com:443
# --- Google Gemini CLI (Cloud Code inference + OAuth refresh) ---
cloudcode-pa.googleapis.com:443
oauth2.googleapis.com:443
ALLOWEOF
  say "   • seeded egress allowlist: $ALLOW"
fi

# 5 — governed demo/eval environment file ------------------------------------
ENVF="$HERMES_HOME/governed-demo.env"
cat > "$ENVF" <<EOF
# Lliam-GOV — governed DEMO/EVAL profile. Source this before running.
# Posture: personal MacBook, NO CUI in scope.
export HERMES_HOME="$HERMES_HOME"
export LLIAM_GOV_PROFILE=production
export LLIAM_GOV_ENCRYPT_STATE=1
export LLIAM_GOV_EGRESS_ENFORCE=1
export LLIAM_GOV_CAPABILITY_ENFORCE=1
export LLIAM_GOV_SELFMOD_GATE=1
# DEMO-ONLY FIPS opt-out — valid only because no CUI is in scope (POA&M AI-282).
# NEVER set this on a Katmai-managed or CUI-in-scope deployment.
export LLIAM_GOV_ALLOW_NON_FIPS=1
EOF
say "   • wrote governed env: $ENVF"

# 6 — daily-use launcher (double-clickable in Finder) ------------------------
LAUNCH="$HERMES_HOME/start-lliam-gov.command"
cat > "$LAUNCH" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$REPO_ROOT"
set -a; . "$ENVF"; set +a
exec uv run lliam-gov
EOF
chmod +x "$LAUNCH"
say "   • created start launcher: $LAUNCH"

# 7 — posture verification (fail-closed) -------------------------------------
say "→ Verifying governed posture (fails closed on any violation)…"
set -a; . "$ENVF"; set +a
if uv run python -c "from lliam_gov.security.runtime_guard import production_posture_check as p; p()"; then
  printf '%s   ✓ POSTURE OK — all controls active (FIPS gate waived for demo).%s\n' "$GOLD" "$NC"
else
  printf '%s✗ Posture check failed (see message above). Nothing destructive was done.%s\n' "$RED" "$NC" >&2
  exit 1
fi

# 8 — provider selection + finish -------------------------------------------
printf '\n%s%sOne thing left — choose your AI provider:%s\n' "$CYAN" "$BOLD" "$NC"
say "    source \"$ENVF\""
say "    bash scripts/show-providers.sh   # see Claude Code / Codex / Gemini status + setup"
printf '\n%s%sLliam-GOV uses a provider CLI for inference — no API keys needed; the CLI owns login.%s\n' "$DIM" "" "$NC"
say "    • Claude Code:  npm install -g @anthropic-ai/claude-code  &&  claude setup-token"
say "    • Codex:        npm install -g @openai/codex              &&  codex login"
say "    • Gemini:       npm install -g @google/gemini-cli         &&  gemini   (browser sign-in)"
printf '%s    Switch providers anytime — install/login another CLI and re-run show-providers.sh.%s\n' "$DIM" "$NC"
printf '\n%s%sThen, any time you want to start Lliam-GOV:%s\n' "$CYAN" "$BOLD" "$NC"
say "    double-click  $LAUNCH"
printf '%s    (or run:  bash \"%s\")%s\n' "$DIM" "$LAUNCH" "$NC"
printf '\n%s◆ Done.%s\n\n' "$GOLD" "$NC"
