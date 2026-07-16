#!/usr/bin/env python3
"""osv_gate.py — Lliam-GOV blocking OSV severity gate (P3.4 / LG-SS-02).

Evaluates an osv-scanner JSON results file and exits non-zero when any
vulnerability meets or exceeds a severity threshold. The existing
.github/workflows/osv-scanner.yml runs the scan (fail-on-vuln disabled so
pre-existing advisories don't block routine merges); this gate is the gov-side
BLOCKING check for a CUI build/release — run it on the scan output with
``--fail-on high``. Reading a results file (not calling the network) keeps it
deterministic and locally runnable. Renames nothing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List, Tuple

_SEVERITY_ORDER = {"low": 1, "moderate": 2, "medium": 2, "high": 3, "critical": 4}


def _severity_rank(value: str) -> int:
    return _SEVERITY_ORDER.get(str(value or "").strip().lower(), 0)


def _vuln_severity(vuln: dict) -> str:
    # osv-scanner puts severity in a few shapes; check the common ones.
    ds = vuln.get("database_specific") or {}
    if ds.get("severity"):
        return str(ds["severity"])
    sev = vuln.get("severity")
    if isinstance(sev, list) and sev:
        # CVSS vector entries — treat any present as high (conservative).
        return "high"
    if isinstance(sev, str):
        return sev
    return ""


def evaluate(results_path: Path, *, fail_on: str = "high") -> Tuple[int, List[str]]:
    """Return (exit_code, findings). exit_code != 0 when a vuln >= fail_on."""
    threshold = _severity_rank(fail_on)
    try:
        data = json.loads(Path(results_path).read_text(encoding="utf-8"))
    except Exception as e:
        return 1, [f"could not read OSV results ({e}) — failing closed"]
    findings: List[str] = []
    blocking = False
    for result in data.get("results") or []:
        for pkg in result.get("packages") or []:
            name = ((pkg.get("package") or {}).get("name")) or "<unknown>"
            for vuln in pkg.get("vulnerabilities") or []:
                sev = _vuln_severity(vuln)
                vid = vuln.get("id", "<no-id>")
                if _severity_rank(sev) >= threshold and threshold > 0:
                    findings.append(f"{name}: {vid} ({sev or 'unrated'}) >= {fail_on}")
                    blocking = True
    return (1 if blocking else 0), findings


def run_gate(results_path: Path, *, fail_on: str = "high") -> int:
    rc, findings = evaluate(Path(results_path), fail_on=fail_on)
    if rc == 0:
        print(f"[osv] OK — no vulnerabilities at or above '{fail_on}'.")
        return 0
    print(f"[osv] BLOCKING — {len(findings)} vulnerability(ies) >= '{fail_on}':")
    for f in findings:
        print(f"  {f}")
    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: osv_gate.py <osv-results.json> [--fail-on high]")
        sys.exit(2)
    _fail_on = "high"
    if "--fail-on" in sys.argv:
        _fail_on = sys.argv[sys.argv.index("--fail-on") + 1]
    sys.exit(run_gate(Path(sys.argv[1]), fail_on=_fail_on))
