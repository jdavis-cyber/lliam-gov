#!/bin/bash
# Deploy the Lliam-GOV bridge package into ~/.lliam-gov and apply the
# DETERMINISTIC config. Does NOT perform interactive auth (Codex / Claude /
# Linear) — see SETUP.md §4–6 for those. Idempotent. Run AFTER setup-hermes.sh.
set -euo pipefail

REPO="$HOME/lliam-gov"
GHOME="$HOME/.lliam-gov"
HERMES="$REPO/venv/bin/hermes"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ -x "$HERMES" ] || { echo "ERROR: $HERMES missing — run ./setup-hermes.sh first"; exit 1; }
mkdir -p "$GHOME"

echo "==> keyring into the venv (governance home uses encrypted auth.json)"
( cd "$REPO" && VIRTUAL_ENV="$PWD/venv" uv pip install --quiet keyring ) \
  || "$REPO/venv/bin/python" -m pip install --quiet keyring || true

echo "==> deploy bridge + helper scripts to $GHOME"
cp "$HERE/claude_bridge.py" "$HERE/claude_bridge_DESIGN.md" \
   "$HERE/start-lliam-gov.sh" "$HERE/lliam-project.sh" "$GHOME/"
chmod +x "$GHOME"/start-lliam-gov.sh "$GHOME"/lliam-project.sh
mkdir -p "$GHOME/workspace" "$GHOME/.bridge_cwd"

echo "==> egress allowlist hosts (deny-all firewall; add what the providers need)"
EGRESS="$GHOME/egress-allowlist.txt"
[ -f "$EGRESS" ] || printf '# One host[:port] per line. Deny-all is the default.\n' > "$EGRESS"
for h in api.anthropic.com:443 chatgpt.com:443 auth.openai.com:443 \
         console.anthropic.com:443 platform.claude.com:443; do
  grep -qxF "$h" "$EGRESS" || echo "$h" >> "$EGRESS"
done

echo "==> model config — default to the bridge (Claude-on-Max). For Codex/gpt-5.5"
echo "    instead, see SETUP.md §4."
export HERMES_HOME="$GHOME"
"$HERMES" config set model.provider custom                  >/dev/null
"$HERMES" config set model.base_url http://127.0.0.1:8765/v1 >/dev/null
"$HERMES" config set model.default claude-via-cli            >/dev/null
"$HERMES" config set model.api_key sk-local-bridge          >/dev/null

echo "==> packaged-app backend path (symlink the expected install + bootstrap marker)"
ln -sfn "$REPO" "$GHOME/hermes-agent"
cat > "$REPO/.hermes-bootstrap-complete" <<EOF
{ "schemaVersion": 1, "pinnedCommit": "$(git -C "$REPO" rev-parse HEAD)",
  "pinnedBranch": "$(git -C "$REPO" rev-parse --abbrev-ref HEAD)", "adopted": true,
  "completedAt": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)", "desktopVersion": "0.15.1" }
EOF

cat <<'NEXT'

Deployed. Remaining MANUAL (interactive) steps — see SETUP.md:
  §4  Codex OAuth   : desktop onboarding "OpenAI OAuth (ChatGPT)" or `hermes auth add openai-codex`
  §5a Claude token  : `claude setup-token` -> save to ~/.lliam-gov/.claude_token
  §6b Linear key    : save Personal API Key to ~/.lliam-gov/.linear_key (optional)
  tier              : echo CLAUDE_BRIDGE_TOOLS=pm > ~/.lliam-gov/.bridge_env
Then: ~/lliam-gov/lliam-gov-setup/validate.sh
NEXT
