"""Guard test: defines "rename complete" for Phase R (hermes -> lliam).

This test is EXPECTED to be RED from Task R.0 until Task R.8. It is the
completeness meter for the rename, not a bug to fix early. Do not add
files to ALLOWED just to make it pass before the rename work is done —
only the specific exceptions documented below belong there.
"""

import subprocess
from pathlib import Path

# Exclusions MUST mirror scripts/rename/exclude_globs.sh byte-for-byte.
# EXCLUDES: (a) upstream attribution — D4, license obligation;
#           (b) generated output — regenerated, never hand-renamed;
#           (c) historical evidence/audit logs — frozen, editing them is tampering;
#           (d) planning docs — they quote the OLD name on purpose (history);
#               renaming their hermes mentions would corrupt the record.
EXCLUDES = [
    "-g", "!**/node_modules/**", "-g", "!**/.git/**", "-g", "!**/dist/**",
    "-g", "!**/build/**", "-g", "!**/*.egg-info/**", "-g", "!graphify-out/**",
    "-g", "!evidence/**", "-g", "!**/*.lock", "-g", "!**/package-lock.json",
    "-g", "!NOTICE", "-g", "!ATTRIBUTION*", "-g", "!LICENSE*", "-g", "!docs/upstream/**",
    "-g", "!docs/governance/plans/**",   # planning docs quote the old name on purpose (history)
]

ALLOWED = {
    # the one-time migration routine is the sole Lliam-owned file allowed to name the old path.
    # Allowed under BOTH paths: R.1 creates it as hermes_cli/migrate_home.py, R.2's `git mv`
    # renames the package to lliam_cli/migrate_home.py. Keeping both entries means this
    # ALLOWED set doesn't need editing between R.1 and R.2.
    "hermes_cli/migrate_home.py",
    "lliam_cli/migrate_home.py",
    # keep for one release if the HERMES_ env fallback is retained (R.8 decision); else remove.
    # Same pre/post-R.2 path duality as migrate_home.py above.
    "hermes_cli/env_compat.py",
    "lliam_cli/env_compat.py",
    # rename infrastructure, not Lliam identity: this guard test and the inventory scripts
    # necessarily say "hermes" in variable names/comments/patterns to describe what they're
    # scanning for. rg matches path prefixes here (not just exact files), so a directory
    # entry is sufficient to cover every file under each tree.
    "tests/rename",
    "scripts/rename",
}


def _is_allowed(path: str) -> bool:
    normalized = path[2:] if path.startswith("./") else path
    if normalized in ALLOWED:
        return True
    return any(
        normalized == allowed or normalized.startswith(allowed + "/")
        for allowed in ALLOWED
    )


def test_no_lliam_owned_hermes_refs():
    # Repo root = two parents up from this file (tests/rename/<this file>).
    # rg must run with this as cwd regardless of pytest's invocation directory,
    # otherwise relative excludes like 'docs/governance/plans/**' silently stop matching.
    repo_root = Path(__file__).resolve().parents[2]

    result = subprocess.run(
        ["rg", "-il", "hermes", *EXCLUDES, "."],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    # rg exit codes: 0 = matches found, 1 = no matches, 2+ = actual error.
    assert result.returncode in (0, 1), (
        f"rg failed to run (exit {result.returncode}): {result.stderr}"
    )

    out = result.stdout.splitlines()   # one path per line; .split() would shred spaced filenames
    offenders = [f for f in out if not _is_allowed(f)]
    assert not offenders, (
        f"{len(offenders)} Lliam-owned hermes files remain; "
        f"first 20: {offenders[:20]} (run scripts/rename/inventory.sh for the full list)"
    )
