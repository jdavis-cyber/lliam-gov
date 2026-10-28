#!/usr/bin/env python3
"""soa_gate.py — Statement-of-Applicability reconciliation (LG-RM-04/07, P4.2).

Reads docs/governance/control-catalog.yaml (the machine source of truth for
the 188-control canon) and docs/governance/SoA.md (the assessor-facing
statement) and FAILS CLOSED (exit 1) when:
  * the catalog does not carry the expected control total, or a control has
    an invalid status, or a pending (planned/partial) control has no
    poam_ref, or a poam_ref does not resolve to an item in poam.yaml;
  * an SoA row is missing for a catalog control (or vice versa), or an SoA
    row's status contradicts the catalog;
  * the SoA does not record the godmode exclusion.

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
    print(f"::error::soa_gate requires PyYAML ({e})")
    sys.exit(2)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXPECTED_TOTAL = 188
_VALID_STATUS = {"implemented", "partial", "planned", "inherited"}
_SOA_STATUS_WORDS = {
    "Implemented": "implemented",
    "Partially Implemented": "partial",
    "Planned": "planned",
    "Inherited": "inherited",
}
_ROW_RE = re.compile(
    r"^\| (LG-[A-Z]{2}-\d{2}) \|.*\| *(Implemented|Partially Implemented|"
    r"Planned|Inherited) *\|", re.M)


def _emit(msg: str, *, error: bool = False) -> None:
    import os
    prefix = "::error::" if error and os.environ.get("GITHUB_ACTIONS") else ""
    print(f"{prefix}{msg}")


def _load_yaml(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def check_soa(*, repo_root: Path = _REPO_ROOT,
              expected_total: int = _EXPECTED_TOTAL) -> list[str]:
    failures: list[str] = []
    gov = repo_root / "docs" / "governance"

    try:
        catalog = _load_yaml(gov / "control-catalog.yaml")
    except Exception as e:
        return [f"control catalog unreadable: {e}"]
    controls = catalog.get("controls") or []
    ids = [c.get("id") for c in controls]
    if len(ids) != expected_total:
        failures.append(f"catalog has {len(ids)} controls, "
                        f"expected {expected_total}")
    if len(set(ids)) != len(ids):
        failures.append("catalog has duplicate control ids")

    try:
        poam = _load_yaml(gov / "poam.yaml")
        poam_ids = {i.get("id") for i in (poam.get("items") or [])}
    except Exception as e:
        poam_ids = set()
        failures.append(f"poam.yaml unreadable: {e}")

    cat_status: dict[str, str] = {}
    for c in controls:
        cid = c.get("id", "<missing>")
        status = c.get("status")
        cat_status[cid] = status
        if status not in _VALID_STATUS:
            failures.append(f"{cid}: invalid status {status!r}")
        if status in ("planned", "partial"):
            ref = c.get("poam_ref")
            if not ref:
                failures.append(f"{cid}: {status} without poam_ref")
            elif ref not in poam_ids:
                failures.append(f"{cid}: poam_ref '{ref}' not in poam.yaml")

    soa_path = gov / "SoA.md"
    if not soa_path.exists():
        failures.append("SoA.md missing")
        return failures
    soa = soa_path.read_text(encoding="utf-8")
    soa_rows = {m.group(1): _SOA_STATUS_WORDS[m.group(2)]
                for m in _ROW_RE.finditer(soa)}

    for cid, status in cat_status.items():
        if cid not in soa_rows:
            failures.append(f"{cid}: in catalog but missing from SoA.md")
        elif soa_rows[cid] != status:
            failures.append(f"{cid}: status mismatch — catalog "
                            f"'{status}' vs SoA '{soa_rows[cid]}'")
    for cid in soa_rows:
        if cid not in cat_status:
            failures.append(f"{cid}: in SoA.md but not in catalog")

    if "godmode" not in soa:
        failures.append("SoA.md does not record the godmode exclusion")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    args = parser.parse_args(argv)
    try:
        failures = check_soa(repo_root=Path(args.repo_root))
    except Exception as e:  # pragma: no cover
        _emit(f"soa_gate: error ({e})", error=True)
        return 2
    if failures:
        _emit(f"[LG-RM-04] SoA NOT RECONCILED ({len(failures)}):", error=True)
        for f in failures:
            _emit(f"    - {f}", error=True)
        return 1
    _emit(f"[LG-RM-04] OK — SoA reconciled to the {_EXPECTED_TOTAL}-control "
          "catalog; godmode exclusion recorded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
