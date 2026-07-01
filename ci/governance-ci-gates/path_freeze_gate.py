#!/usr/bin/env python3
"""path_freeze_gate.py — Lliam-GOV PATH-FREEZE guardrail (LG-SD-01).

Fails a PR that RENAMES or DELETES a frozen path (the governance overlay must be
additive). Detects renames via ``git diff --name-status -M``. Additive changes
(new files = status A, in-place edits = status M) always pass.

PATH-FREEZE: this is a NEW additive script; it touches no frozen file itself.

Usage:
    path_freeze_gate.py --manifest <manifest.yaml> --base <sha> --head <sha>

Exit codes: 0 = clean, 1 = a frozen path was renamed/deleted, 2 = usage error.
"""
from __future__ import annotations

import argparse
import subprocess
import sys

try:
    import yaml
except Exception as e:  # pragma: no cover
    print(f"::error::path_freeze_gate requires PyYAML ({e})")
    sys.exit(2)


def _frozen(manifest_path: str) -> set[str]:
    data = yaml.safe_load(open(manifest_path, encoding="utf-8")) or {}
    return set(data.get("frozen_paths", []) or [])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--base", required=True, help="base ref/sha")
    ap.add_argument("--head", required=True, help="head ref/sha")
    a = ap.parse_args()

    frozen = _frozen(a.manifest)
    if not frozen:
        print("::warning::path-freeze manifest is empty; nothing to enforce.")
        return 0

    try:
        out = subprocess.check_output(
            ["git", "diff", "--name-status", "-M", f"{a.base}...{a.head}"],
            text=True,
        )
    except subprocess.CalledProcessError as e:  # pragma: no cover
        print(f"::error::git diff failed: {e}")
        return 2

    violations: list[str] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if not parts:
            continue
        status = parts[0]
        # Rename: "R<score>\told\tnew" ; Delete: "D\told"
        if status.startswith("R") and len(parts) == 3:
            old, new = parts[1], parts[2]
            if old in frozen:
                violations.append(f"RENAME of frozen path: {old} -> {new}")
        elif status.startswith("D") and len(parts) == 2:
            if parts[1] in frozen:
                violations.append(f"DELETE of frozen path: {parts[1]}")

    if violations:
        print("::error::PATH-FREEZE violation (LG-SD-01). The governance overlay "
              "must be additive — frozen modules may be modified in place but never "
              "renamed, moved, or deleted:")
        for v in violations:
            print(f"  - {v}")
        print("Remediation: keep the original path; add a NEW file instead, or "
              "apply a 'path-freeze-waived' label with an approved waiver.")
        return 1

    print(f"[path-freeze] OK — no frozen path renamed or deleted "
          f"({len(frozen)} paths guarded).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
