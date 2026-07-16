#!/usr/bin/env python3
"""ssp_reconciliation_gate.py — SSP ↔ enforcement reconciliation (LG-IN-07, P4.3).

Reads docs/governance/traceability-171r3.yaml (the machine-readable
requirement-to-config matrix behind docs/governance/SSP.md) and FAILS CLOSED
(exit 1) when:
  * any of the 17 NIST SP 800-171 r3 families is missing, has an invalid
    status, no implementing controls, or no config points;
  * a family's config point does not resolve to a REAL enforced artifact
    (same resolver as the LG-GV-03 regulatory gate: config_key present in
    cli-config.gov.yaml, file exists, module exists);
  * SSP.md has no section heading for a family in the matrix.

Exit: 0 = reconciled, 1 = failure, 2 = error.
PATH-FREEZE: NEW additive script; read-only over governance files.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except Exception as e:  # pragma: no cover
    print(f"::error::ssp_reconciliation_gate requires PyYAML ({e})")
    sys.exit(2)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from regulatory_reconciliation_gate import _resolve_config_point  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXPECTED_FAMILIES = [f"03.{i:02d}" for i in range(1, 18)]
_VALID_STATUS = {"implemented", "inherited"}


def _emit(msg: str, *, error: bool = False) -> None:
    import os
    prefix = "::error::" if error and os.environ.get("GITHUB_ACTIONS") else ""
    print(f"{prefix}{msg}")


def _load_yaml(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def check_ssp(*, repo_root: Path = _REPO_ROOT,
              expected_families: list[str] | None = None) -> list[str]:
    failures: list[str] = []
    gov = repo_root / "docs" / "governance"
    expected = expected_families or _EXPECTED_FAMILIES

    trc_path = gov / "traceability-171r3.yaml"
    if not trc_path.exists():
        return ["traceability-171r3.yaml missing"]
    try:
        trc = _load_yaml(trc_path)
    except Exception as e:
        return [f"traceability matrix unreadable: {e}"]
    try:
        overlay = _load_yaml(repo_root / "cli-config.gov.yaml")
    except Exception as e:
        return [f"overlay unreadable: {e}"]

    families = trc.get("families") or []
    seen = [f.get("family") for f in families]
    for fid in expected:
        if fid not in seen:
            failures.append(f"{fid}: missing from traceability matrix")

    ssp_path = gov / "SSP.md"
    ssp = ssp_path.read_text(encoding="utf-8") if ssp_path.exists() else ""
    if not ssp:
        failures.append("SSP.md missing")

    for fam in families:
        fid = fam.get("family", "<missing>")
        if fam.get("status") not in _VALID_STATUS:
            failures.append(f"{fid}: invalid status {fam.get('status')!r}")
        if not fam.get("controls"):
            failures.append(f"{fid}: no implementing controls")
        points = fam.get("config_points") or []
        if not points:
            failures.append(f"{fid}: no config points")
        for point in points:
            err = _resolve_config_point(point, overlay=overlay,
                                        repo_root=repo_root)
            if err:
                failures.append(f"{fid}: {err}")
        if ssp and not re.search(rf"^###? {re.escape(fid)}\b", ssp, re.M):
            failures.append(f"{fid}: no section in SSP.md")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    args = parser.parse_args(argv)
    try:
        failures = check_ssp(repo_root=Path(args.repo_root))
    except Exception as e:  # pragma: no cover
        _emit(f"ssp_reconciliation_gate: error ({e})", error=True)
        return 2
    if failures:
        _emit(f"[LG-IN-07] SSP NOT RECONCILED ({len(failures)}):", error=True)
        for f in failures:
            _emit(f"    - {f}", error=True)
        return 1
    _emit("[LG-IN-07] OK — all 17 800-171 r3 families reconcile to real "
          "enforced config points.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
