#!/usr/bin/env bash
# scripts/rename/inventory.sh
#
# Lliam-owned hermes identifiers (must reach 0 except the migration routine).
# EXCLUDES: (a) upstream attribution — D4, license obligation;
#           (b) generated output — regenerated, never hand-renamed;
#           (c) historical evidence/audit logs — frozen, editing them is tampering;
#           (d) these planning docs — they quote the OLD name on purpose (history);
#               renaming their hermes mentions would corrupt the record.
# These exclusion globs MUST match the guard test below exactly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./exclude_globs.sh
source "${SCRIPT_DIR}/exclude_globs.sh"

REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

rg -i --stats hermes "${HERMES_EXCLUDES[@]}" "${REPO_ROOT}"
