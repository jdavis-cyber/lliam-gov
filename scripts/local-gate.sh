#!/usr/bin/env bash
#
# local-gate.sh (AI-337) — the documented LOCAL merge gate for Lliam-GOV.
#
# While GitHub Actions is offline, local-green is the merge gate. This script
# runs the offline release invariants so a human (or the merge step) can confirm
# readiness before an `--admin` merge. It is intentionally fast and scoped; it
# does NOT run the full 24k-test suite (run scoped, affected-file tests for the
# change under review separately).
#
# Usage:  bash scripts/local-gate.sh
# Exit:   0 = all gates passed; non-zero = a gate failed.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

FAILS=0
section() { printf '\n=== %s ===\n' "$1"; }
run() {
  local label="$1"; shift
  if "$@"; then
    printf 'PASS: %s\n' "$label"
  else
    printf 'FAIL: %s\n' "$label"
    FAILS=$((FAILS + 1))
  fi
}

# 1. Release-readiness metadata + artifact-leakage gate.
section "release-readiness"
run "release-readiness" python3 scripts/release-readiness.py

# 2. Secrets hygiene — no obvious committed secrets in tracked files.
section "secrets-scan (tracked files)"
# Excludes pattern-definition / redaction / security modules and docs/tests,
# whose job is to *describe* these markers (benign references, not secrets).
if git grep -nIE \
     'BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY|sk-ant-[A-Za-z0-9]{6}|AKIA[0-9A-Z]{16}' \
     -- . ':(exclude)*.md' ':(exclude)providers/cli/redaction.py' \
     ':(exclude)agent/redact.py' ':(exclude)lliam_gov/security/*' \
     ':(exclude)*redact*' ':(exclude)tests/*' >/tmp/lliam-secrets-hits 2>/dev/null; then
  echo "Potential secrets in tracked files:"; cat /tmp/lliam-secrets-hits
  FAILS=$((FAILS + 1))
else
  echo "PASS: no obvious secrets in tracked files"
fi

# 3. Desktop platform unit tests (node:test) — fast, hermetic subset.
section "desktop platform tests"
if [ -d apps/desktop/node_modules ] || command -v node >/dev/null 2>&1; then
  run "desktop:platforms" bash -c \
    "cd apps/desktop && node --test electron/bootstrap-marker.test.cjs electron/git-root.test.cjs electron/workspace-cwd.test.cjs"
else
  echo "SKIP: node not available"
fi

# 4. Provider boundary tests (the security-sensitive surface).
section "provider boundary tests"
PYTEST_BIN=".venv/bin/python"
[ -x "$PYTEST_BIN" ] || PYTEST_BIN="python3"
run "providers/cli tests" "$PYTEST_BIN" -m pytest tests/providers/cli/ -q

section "summary"
if [ "$FAILS" -eq 0 ]; then
  echo "LOCAL GATE GREEN — ok to merge (document the --admin override; Actions offline)."
  exit 0
fi
echo "LOCAL GATE RED — $FAILS gate(s) failed."
exit 1
