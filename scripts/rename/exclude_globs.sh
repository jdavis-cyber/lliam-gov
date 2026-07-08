#!/usr/bin/env bash
# scripts/rename/exclude_globs.sh
#
# Single source of truth for the hermes-identifier rg exclusion globs.
# Sourced by inventory.sh (and any other rename/* scripts) so the
# exclusion set can't drift apart across scripts.
#
# Mirror this array exactly in tests/rename/test_no_hermes_identifiers.py
# (EXCLUDES list) — the guard test and this script must agree on what's
# excluded, or "rename complete" means two different things.
#
# EXCLUDES: (a) upstream attribution — D4, license obligation;
#           (b) generated output — regenerated, never hand-renamed;
#           (c) historical evidence/audit logs — frozen, editing them is tampering;
#           (d) these planning docs — they quote the OLD name on purpose (history);
#               renaming their hermes mentions would corrupt the record.
#           (e) the rename keep-register / verify-report — meta-docs that MUST
#               quote the old name to document the surviving keeps.
HERMES_EXCLUDES=(
  -g '!**/node_modules/**' -g '!**/.git/**' -g '!**/dist/**' -g '!**/build/**'
  -g '!**/*.egg-info/**' -g '!graphify-out/**' -g '!evidence/**'
  -g '!**/*.lock' -g '!**/package-lock.json'
  -g '!NOTICE' -g '!ATTRIBUTION*' -g '!LICENSE*' -g '!docs/upstream/**'
  -g '!docs/governance/plans/**'   # these plans quote the old name on purpose
  -g '!docs/governance/verification/*keep-register.md'   # keep-registers document the kept old-name tokens
  -g '!docs/governance/verification/R-rename-report.md'  # R.V report cites the keeps
)
