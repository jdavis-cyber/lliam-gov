#!/usr/bin/env bash
# deps_hash_gate.sh — Lliam-GOV dependency pin + hash gate (LG-SS-01).
#
# FAILS the build if the supply chain isn't pinned + hash-verifiable:
#   1) uv.lock present and carries sha256 hashes (the cryptographic pin);
#   2) pyproject.toml PyPI deps all carry an upper bound (== or <next_major);
#   3) if `uv` is available, `uv sync --locked --no-install-project` confirms the
#      lock is consistent with pyproject (hash-verified install path). Skipped
#      with a notice when uv isn't installed (the grep checks above are the floor).
#
# Additive: reads pyproject.toml / uv.lock; calls `uv` as it ships. Renames nothing.
# Exit: 0 = pinned + hashed, 1 = unpinned/unhashed.
set -euo pipefail

LOCK="${LOCK:-uv.lock}"
PYPROJECT="${PYPROJECT:-pyproject.toml}"
RC=0

echo "::group::LG-SS-01 — lockfile hashes"
if [ ! -f "$LOCK" ]; then
  echo "::error::lockfile $LOCK is missing (LG-SS-01)."; RC=1
else
  NH=$(grep -cE 'hash = "sha256:' "$LOCK" || true)
  if [ "${NH:-0}" -lt 1 ]; then
    echo "::error::$LOCK contains no sha256 hashes (LG-SS-01). Regenerate with 'uv lock'."; RC=1
  else
    echo "  [OK] $LOCK carries $NH sha256 hashes."
  fi
fi
echo "::endgroup::"

echo "::group::LG-SS-01 — pyproject upper bounds"
# Find PyPI deps in [project].dependencies WITHOUT an upper bound (== or <).
# A dep line is "name[extras] <constraint>". Flag any with no '==' and no '<'.
UNBOUNDED=$(python3 - "$PYPROJECT" <<'PY'
import sys, tomllib
data = tomllib.load(open(sys.argv[1], "rb"))
deps = (data.get("project") or {}).get("dependencies", []) or []
bad = []
for d in deps:
    spec = d.split(";", 1)[0].strip()          # drop env markers
    if "==" in spec or "<" in spec:            # exact pin or upper bound present
        continue
    bad.append(d)
print("\n".join(bad))
PY
)
if [ -n "$UNBOUNDED" ]; then
  echo "::error::PyPI dependencies without an upper bound (LG-SS-01):"
  printf '  - %s\n' $UNBOUNDED
  RC=1
else
  echo "  [OK] all [project].dependencies carry an upper bound (== or <next_major)."
fi
echo "::endgroup::"

echo "::group::LG-SS-01 — hash-verified lock consistency (uv sync --locked)"
if command -v uv >/dev/null 2>&1; then
  if uv sync --locked --no-install-project >/dev/null 2>&1; then
    echo "  [OK] uv.lock is consistent with pyproject (hash-verified install path)."
  else
    echo "::error::'uv sync --locked' failed — uv.lock is stale/inconsistent (LG-SS-01)."
    RC=1
  fi
else
  echo "  [skip] uv not on PATH; relying on the hash + upper-bound checks above."
fi
echo "::endgroup::"

if [ "$RC" -eq 0 ]; then
  echo "[deps-hash] PASS — dependencies pinned with hashes + upper bounds."
else
  echo "[deps-hash] FAIL — see errors above."
fi
exit "$RC"
