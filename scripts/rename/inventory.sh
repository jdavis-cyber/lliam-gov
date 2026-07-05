#!/usr/bin/env bash
# scripts/rename/inventory.sh
#
# Lliam-owned hermes identifiers (must reach 0 except the migration routine).
# EXCLUDES: (a) upstream attribution — D4, license obligation;
#           (b) generated output — regenerated, never hand-renamed;
#           (c) historical evidence/audit logs — frozen, editing them is tampering;
#           (d) these planning docs — they quote the OLD name on purpose (history);
#               renaming their hermes mentions would corrupt the record.
# These exclusion globs MUST match tests/rename/test_no_hermes_identifiers.py exactly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./exclude_globs.sh
source "${SCRIPT_DIR}/exclude_globs.sh"

REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Run FROM the repo root and search "." — rg resolves relative exclusion globs like
# 'docs/governance/plans/**' against the cwd, not the path argument; invoking this
# script from elsewhere would silently leak excluded paths into the report.
cd "${REPO_ROOT}"
# rg exits 1 on zero matches — at R.8 that is SUCCESS, not failure; only 2+ is an error.
rg -i --stats hermes "${HERMES_EXCLUDES[@]}" . || [[ $? -eq 1 ]]
