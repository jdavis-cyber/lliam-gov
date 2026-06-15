#!/usr/bin/env bash
# ============================================================================
#  Lliam-GOV — Provider readiness (CLI-backed)
#  Shows which of Claude Code / Codex / Gemini are ready, and the EXACT
#  install/login command for any that aren't. No API keys — each provider CLI
#  owns its own auth (AI-334); Lliam-GOV never reads or stores provider tokens.
#
#  Usage (from the repo root):  bash scripts/show-providers.sh
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

exec uv run python - <<'PY'
from providers.cli import probe_all, to_card

print("Lliam-GOV — provider readiness (CLI owns auth; no API keys):\n")
_ORDER = {"ready": 0, "degraded": 1, "not_authenticated": 2, "not_installed": 3, "unavailable": 4}
cards = sorted((to_card(r) for r in probe_all()), key=lambda c: _ORDER.get(c.state, 9))
for c in cards:
    mark = "✓" if c.selectable else "•"
    line = f"  {mark} {c.display_name:18} {c.status_label}"
    if c.action_command:
        line += f"   →  {c.action_label}: {c.action_command}"
    print(line)

ready = [c for c in cards if c.selectable]
print()
if ready:
    print(f"Ready to use: {', '.join(c.display_name for c in ready)}.")
    print("Start Lliam-GOV:  uv run lliam-gov")
else:
    print("No provider is ready yet — run one of the commands above, then re-run this script.")
PY
