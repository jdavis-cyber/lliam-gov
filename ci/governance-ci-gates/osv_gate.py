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
import math
import sys
from pathlib import Path
from typing import List, Tuple

_SEVERITY_ORDER = {"low": 1, "moderate": 2, "medium": 2, "high": 3, "critical": 4}


def _severity_rank(value: str) -> int:
    return _SEVERITY_ORDER.get(str(value or "").strip().lower(), 0)


def _roundup_tenth(value: float) -> float:
    return math.ceil((value - 1e-10) * 10.0) / 10.0


def _cvss3_score(vector: str) -> float | None:
    """Return the CVSS v3.x base score for an OSV vector, or None."""
    raw = str(vector or "").strip()
    try:
        numeric = float(raw)
        return numeric if 0 <= numeric <= 10 else None
    except ValueError:
        pass
    if not raw.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics = {}
    for item in raw.split("/")[1:]:
        key, sep, value = item.partition(":")
        if sep:
            metrics[key] = value
    try:
        scope = metrics["S"]
        av = {"N": .85, "A": .62, "L": .55, "P": .20}[metrics["AV"]]
        ac = {"L": .77, "H": .44}[metrics["AC"]]
        pr = ({"N": .85, "L": .62, "H": .27} if scope == "U"
              else {"N": .85, "L": .68, "H": .50})[metrics["PR"]]
        ui = {"N": .85, "R": .62}[metrics["UI"]]
        c = {"N": 0.0, "L": .22, "H": .56}[metrics["C"]]
        i = {"N": 0.0, "L": .22, "H": .56}[metrics["I"]]
        a = {"N": 0.0, "L": .22, "H": .56}[metrics["A"]]
    except (KeyError, TypeError):
        return None
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = (6.42 * iss if scope == "U"
              else 7.52 * (iss - .029) - 3.25 * ((iss - .02) ** 15))
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    base = impact + exploitability
    if scope == "C":
        base *= 1.08
    return _roundup_tenth(min(base, 10.0))


def _score_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return ""


def _vuln_severity(vuln: dict) -> str:
    # osv-scanner puts severity in a few shapes; check the common ones.
    ds = vuln.get("database_specific") or {}
    if ds.get("severity"):
        return str(ds["severity"])
    sev = vuln.get("severity")
    if isinstance(sev, list) and sev:
        ranks = []
        for entry in sev:
            score = _cvss3_score(entry.get("score")) if isinstance(entry, dict) else None
            if score is None:
                return "critical"  # unsupported advertised severity fails closed
            ranks.append(_score_severity(score))
        return max(ranks, key=_severity_rank) if ranks else ""
    if isinstance(sev, str):
        return sev
    return ""


def evaluate(results_path: Path, *, fail_on: str = "high") -> Tuple[int, List[str]]:
    """Return (exit_code, findings). exit_code != 0 when a vuln >= fail_on."""
    threshold = _severity_rank(fail_on)
    if threshold == 0:
        return 1, [f"invalid OSV severity threshold '{fail_on}' — failing closed"]
    try:
        data = json.loads(Path(results_path).read_text(encoding="utf-8"))
    except Exception as e:
        return 1, [f"could not read OSV results ({e}) — failing closed"]
    if not isinstance(data, dict) or not isinstance(data.get("results", []), list):
        return 1, ["OSV results have an invalid shape — failing closed"]
    findings: List[str] = []
    blocking = False
    for result in data.get("results") or []:
        for pkg in result.get("packages") or []:
            name = ((pkg.get("package") or {}).get("name")) or "<unknown>"
            for vuln in pkg.get("vulnerabilities") or []:
                sev = _vuln_severity(vuln)
                vid = vuln.get("id", "<no-id>")
                if not sev:
                    findings.append(f"{name}: {vid} (unrated) — failing closed")
                    blocking = True
                elif _severity_rank(sev) >= threshold:
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
