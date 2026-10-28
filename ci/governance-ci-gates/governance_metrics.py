#!/usr/bin/env python3
"""governance_metrics.py — Governance metrics from the audit ledger
(LG-MO-09, P5.2).

Computes the governance-effectiveness metrics the management review consumes
(LG-MO-09 / QT-02 quality objectives): event counts by type + severity, deny
rate, critical count, and alert counts. Reads the hash-chained ledger (JSONL);
the metrics are the input pack for the periodic management review that tunes
the autonomy dial and prevents capability erosion.

Exit: 0 always (a reporting job, not a gate). Prints a JSON summary.
PATH-FREEZE: NEW additive script; read-only over the ledger.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def _iter_ledger(path: Path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


def compute_metrics(*, ledger_path: Path) -> dict:
    by_event: Counter = Counter()
    by_severity: Counter = Counter()
    deny = 0
    critical = 0
    alerts = 0
    total = 0
    for rec in _iter_ledger(ledger_path):
        total += 1
        by_event[str(rec.get("event"))] += 1
        by_severity[str(rec.get("severity"))] += 1
        if str(rec.get("decision")) == "deny":
            deny += 1
        if str(rec.get("severity")) == "critical":
            critical += 1
        if str(rec.get("event")) == "security.alert":
            alerts += 1
    return {
        "total_events": total,
        "by_event": dict(by_event),
        "by_severity": dict(by_severity),
        "deny_count": deny,
        "deny_rate": round(deny / total, 4) if total else 0.0,
        "critical_count": critical,
        "alert_count": alerts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True,
                        help="path to the agent-audit.log ledger")
    args = parser.parse_args(argv)
    metrics = compute_metrics(ledger_path=Path(args.ledger).expanduser())
    print(json.dumps({"job": "governance-metrics", **metrics},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
