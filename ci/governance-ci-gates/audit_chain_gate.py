#!/usr/bin/env python3
"""audit_chain_gate.py — Lliam-GOV audit-chain integrity gate (LG-AU-08, P1.3).

Walks a hash-chained governance audit ledger and FAILS CLOSED (exit 1) on any
break: an edited record (record_hash mismatch), a deletion/reorder/insert
(prev_hash mismatch), or a seq gap. This is the standing DETECTIVE control for
tamper (spec §10) — wired both as a blocking CI step and as a cron job (the
scheduled verification LG-AU-08 requires).

Exit codes:
  0  PASS — chain verified, OR no ledger present (nothing to verify: in CI
     there is normally no production ledger; the gate is a no-op then, and the
     verifier's teeth are exercised by the unit tests + the P1.3 demo). Also
     0 when the effective profile is not strict (capability-preserving —
     non-gov branches are unaffected).
  1  FAIL — a chain break was found. The first break (seq + reason) is printed.
  2  ERROR — the verifier could not run (bad args, unimportable package).

PATH-FREEZE: a NEW additive script; imports agent.governance_audit read-only.

Usage:
    audit_chain_gate.py [--ledger <path>] [--require-strict]
      --ledger         explicit ledger path; else the config-resolved default
      --require-strict no-op (exit 0) unless the effective gov posture is strict
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Allow running as a bare script from the repo root (CI/cron) without install.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _emit(msg: str, *, error: bool = False) -> None:
    prefix = "::error::" if error and os.environ.get("GITHUB_ACTIONS") else ""
    print(f"{prefix}{msg}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit-chain integrity gate (LG-AU-08)")
    parser.add_argument("--ledger", default=None, help="ledger path (default: config-resolved)")
    parser.add_argument(
        "--require-strict", action="store_true",
        help="no-op unless the effective gov posture is strict",
    )
    args = parser.parse_args(argv)

    try:
        from agent import governance_audit as ga
    except Exception as e:
        _emit(f"audit_chain_gate: cannot import governance_audit ({e})", error=True)
        return 2

    if args.require_strict:
        try:
            from lliam_cli import config as _cfg
            from lliam_cli import posture_resolver as _pr
            if not _pr.is_strict(_cfg.load_config()):
                _emit("[audit-chain] non-strict profile — gate is a no-op (OK).")
                return 0
        except Exception as e:
            # Cannot determine posture — do not silently pass a strict deploy.
            _emit(f"audit_chain_gate: posture check failed ({e})", error=True)
            return 2

    ledger_path = Path(args.ledger) if args.ledger else ga.resolve_ledger_path()
    if not ledger_path.exists():
        _emit(f"[audit-chain] no ledger at {ledger_path} — nothing to verify (OK).")
        return 0

    try:
        result = ga.verify_chain(ledger_path)
    except Exception as e:
        _emit(f"audit_chain_gate: verify_chain errored ({e})", error=True)
        return 2

    if result.ok:
        # NOTE: internal-consistency PASS only. An unsigned hash chain has no
        # high-water mark, so suffix-truncation / whole-file deletion cannot be
        # detected here — that is the job of external anchoring + an external
        # record count (spec §4.2; deviation-register LG-AU-08-R1). Wording is
        # deliberately "internally consistent", not "complete/untampered".
        _emit(
            f"[audit-chain] internally consistent — {result.checked} records "
            f"linked from genesis ({ledger_path}). "
            "(Truncation/whole-file deletion needs external anchoring — see LG-AU-08-R1.)"
        )
        return 0

    _emit(
        f"[audit-chain] TAMPER DETECTED at seq={result.break_seq} "
        f"(index {result.break_index}): {result.reason} — ledger {ledger_path}",
        error=True,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
