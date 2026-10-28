#!/usr/bin/env python3
"""scheduled_redteam.py — Scheduled adversarial / red-team evaluation
(LG-MO-07, P5.2).

Runs the prompt-injection / tool-poisoning / excessive-agency red-team corpus
(tests/governance/test_p45_redteam_corpus.py) on a schedule and writes a
timestamped JSON report artifact. This is the RECURRING assurance job (distinct
from the pre-merge V&V run) — the cATO control-evidence stream the plan
requires (LG-MO-07). A regression (any red-team case failing) exits 1 so the
cron pages.

Exit: 0 = corpus green, 1 = regression, 2 = error.
PATH-FREEZE: NEW additive script; runs the existing corpus, writes a report.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORPUS = "tests/governance/test_p45_redteam_corpus.py"


def _emit(msg: str, *, error: bool = False) -> None:
    import os
    prefix = "::error::" if error and os.environ.get("GITHUB_ACTIONS") else ""
    print(f"{prefix}{msg}")


def _parse_counts(stdout: str) -> tuple[int, int]:
    """Return (passed, failed) parsed from a pytest summary line."""
    import re
    passed = failed = 0
    m = re.search(r"(\d+) passed", stdout)
    if m:
        passed = int(m.group(1))
    m = re.search(r"(\d+) failed", stdout)
    if m:
        failed = int(m.group(1))
    return passed, failed


def run_redteam(*, repo_root: Path = _REPO_ROOT,
                report_dir: Path | None = None,
                stamp: str | None = None) -> dict:
    """Run the red-team corpus; return a report dict and write the artifact."""
    py = repo_root / ".venv" / "bin" / "python"
    py = str(py) if py.exists() else sys.executable
    proc = subprocess.run(
        [py, "-m", "pytest", _CORPUS, "-q"],
        cwd=str(repo_root), capture_output=True, text=True,
    )
    passed, failed = _parse_counts(proc.stdout + proc.stderr)
    report = {
        "job": "scheduled-redteam",
        "corpus": _CORPUS,
        "ran": True,
        "exit_code": proc.returncode,
        "passed": passed,
        "failed": failed,
        "total": passed + failed,
        "categories": ["prompt_injection", "unicode_smuggling", "ssrf",
                       "hardline_command", "indirect_injection_taint",
                       "egress_sink"],
    }
    if report_dir is not None:
        report_dir.mkdir(parents=True, exist_ok=True)
        # stamp is caller-supplied (scripts ban argless now()); fall back to seq
        name = f"redteam-{stamp or 'latest'}.json"
        (report_dir / name).write_text(
            json.dumps(report, indent=2, sort_keys=True))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    parser.add_argument("--report-dir", default=None)
    parser.add_argument("--stamp", default=None,
                        help="UTC stamp for the report filename")
    args = parser.parse_args(argv)
    try:
        rd = Path(args.report_dir) if args.report_dir else None
        report = run_redteam(repo_root=Path(args.repo_root),
                             report_dir=rd, stamp=args.stamp)
    except Exception as e:  # pragma: no cover
        _emit(f"scheduled_redteam: error ({e})", error=True)
        return 2
    if report["total"] == 0:
        _emit("[LG-MO-07] red-team corpus produced no results", error=True)
        return 2
    if report["failed"]:
        _emit(f"[LG-MO-07] RED-TEAM REGRESSION: {report['failed']} of "
              f"{report['total']} failed", error=True)
        return 1
    _emit(f"[LG-MO-07] OK — red-team corpus green ({report['passed']} "
          f"adversarial cases; defenses hold).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
