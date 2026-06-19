#!/bin/bash
# Validate a Lliam-GOV install. Read-only checks + live model calls.
# Usage: ~/lliam-gov/lliam-gov-setup/validate.sh
REPO="$HOME/lliam-gov"; G="$HOME/.lliam-gov"; HERMES="$REPO/venv/bin/hermes"
pass=0; fail=0; warn=0
ok(){ echo "  ✓ $1"; pass=$((pass+1)); }
no(){ echo "  ✗ $1"; fail=$((fail+1)); }
wn(){ echo "  ⚠ $1"; warn=$((warn+1)); }
chk(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else no "$1"; fi; }

echo "== CLI & venv =="
chk "hermes --version"            "'$HERMES' --version"
chk "keyring importable"          "'$REPO/venv/bin/python' -c 'import keyring'"

echo "== isolation =="
chk "governance home ~/.lliam-gov" "test -d '$G'"
if [ -d "$HOME/.hermes/hermes-agent" ]; then
  case "$(readlink "$HOME/.local/bin/hermes" 2>/dev/null)" in
    *"/.hermes/"*) ok "EA owns ~/.local/bin/hermes (not the fork)";;
    *) wn "~/.local/bin/hermes does not point at the EA — invoke the fork via its venv binary";;
  esac
fi

echo "== egress allowlist =="
for h in api.anthropic.com chatgpt.com auth.openai.com console.anthropic.com platform.claude.com; do
  chk "allows $h" "grep -q '^$h:443' '$G/egress-allowlist.txt'"
done

echo "== auth material =="
[ -f "$G/.claude_token" ] && ok "claude token present" || wn "no ~/.lliam-gov/.claude_token (Claude path needs it)"
[ -f "$G/.linear_key" ]   && ok "linear key present"   || wn "no ~/.lliam-gov/.linear_key (Linear MCP needs it)"
[ -f "$G/auth.json" ]     && ok "auth.json present (Codex)" || wn "no auth.json (Codex OAuth not done)"

echo "== bridge =="
if curl -sf http://127.0.0.1:8765/health >/dev/null 2>&1; then
  ok "bridge health 200"
  curl -s http://127.0.0.1:8765/health | python3 -c "import sys,json;d=json.load(sys.stdin);print('    mode:',d.get('tools_mode'),'| token:',d.get('token_present'),'| projects:',d.get('project_dirs'))" 2>/dev/null
else
  wn "bridge not running (launch the app, or: nohup \$REPO/venv/bin/python \$G/claude_bridge.py &)"
fi

echo "== live: claude -p on the Max plan =="
if [ -f "$G/.claude_token" ]; then
  set -a; . "$G/.claude_token"; set +a
  R=$(echo "Reply with only OK" | "$HOME/.local/bin/claude" -p --output-format json --model sonnet --allowedTools "" 2>/dev/null \
      | python3 -c "import sys,json;d=json.load(sys.stdin);print('OK' if not d.get('is_error') else 'ERR: '+str(d.get('result'))[:70])" 2>/dev/null)
  [ "$R" = "OK" ] && ok "claude -p answered (Max plan serves it)" || no "claude -p: $R"
fi

echo "== live: bridge /v1/chat/completions round-trip =="
if curl -sf http://127.0.0.1:8765/health >/dev/null 2>&1; then
  R=$(curl -s --max-time 150 http://127.0.0.1:8765/v1/chat/completions -H 'Content-Type: application/json' \
      -d '{"model":"x","messages":[{"role":"user","content":"Reply with exactly one word: VALIDATED"}]}' 2>/dev/null \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['choices'][0]['message']['content'][:60])" 2>/dev/null)
  case "$R" in *VALIDATED*) ok "bridge round-trip ($R)";; *) no "bridge round-trip: ${R:-no response}";; esac
fi

echo
echo "RESULT: PASS=$pass FAIL=$fail WARN=$warn"
[ "$fail" -eq 0 ] && echo "Core install looks good." || echo "See failures above + SETUP.md §9 gotchas."
