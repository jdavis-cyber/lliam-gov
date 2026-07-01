#!/usr/bin/env bash
# prohibited_skills_gate.sh — Lliam-GOV prohibited-skill preflight (LG-CH-06 / LG-SC-01).
#
# FAILS the build if any prohibited offensive/jailbreak skill is NOT denied in the
# resolved gov overlay (security.posture: strict). `godmode` is a MANDATORY
# must-disable. Additive: reads the overlay + the skills-allowlist policy; renames
# nothing; calls no existing identifier.
#
# Usage: prohibited_skills_gate.sh [path/to/cli-config.gov.yaml]
# Env:   HERMES_CONFIG (overlay path) used if no arg given.
# Exit:  0 = all prohibited skills denied, 1 = a prohibited skill is not denied.
set -euo pipefail

OVERLAY="${1:-${HERMES_CONFIG:-cli-config.gov.yaml}}"
# Mandatory must-disable + dual-use deny-by-default set (LG-SC-01).
PROHIBITED=(godmode obliteratus sherlock web-pentest oss-forensics)

if [ ! -f "$OVERLAY" ]; then
  echo "::error::gov overlay not found: $OVERLAY"
  exit 1
fi

# Collect the denied set from BOTH the overlay (skills.disabled[]) and, if present,
# the detailed policy file (policy/skills-allowlist.yaml skills.disabled[] +
# exceptions.never_eligible[]). A skill denied in either is denied.
DENIED="$(python3 - "$OVERLAY" <<'PY'
import os, sys, yaml
denied = set()
def add(path):
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
    except Exception:
        return
    sk = (cfg.get("skills") or {})
    for n in (sk.get("disabled") or []):
        denied.add(str(n).strip())
    exc = (cfg.get("exceptions") or {})
    for n in (exc.get("never_eligible") or []):
        denied.add(str(n).strip())

overlay = sys.argv[1]
add(overlay)
# detailed policy alongside the overlay and in the repo policy/ dir
for cand in (
    os.path.join(os.path.dirname(os.path.abspath(overlay)), "policy", "skills-allowlist.yaml"),
    "policy/skills-allowlist.yaml",
):
    if os.path.isfile(cand):
        add(cand)
print("\n".join(sorted(n for n in denied if n)))
PY
)"

RC=0
for s in "${PROHIBITED[@]}"; do
  if printf '%s\n' "$DENIED" | grep -Fxq "$s"; then
    echo "  [OK]   prohibited skill '$s' is denied."
  else
    echo "::error::Prohibited skill '$s' is NOT denied in $OVERLAY (LG-CH-06 / LG-SC-01)."
    RC=1
  fi
done

if [ "$RC" -eq 0 ]; then
  echo "[prohibited-skills] PASS — all prohibited skills denied in the gov profile."
else
  echo "[prohibited-skills] FAIL — add the missing skill(s) to skills.disabled[]."
fi
exit "$RC"
