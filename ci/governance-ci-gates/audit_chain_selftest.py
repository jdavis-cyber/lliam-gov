#!/usr/bin/env python3
"""audit_chain_selftest.py — CI self-test for the audit-chain gate (LG-AU-08).

Exercises the real verifier from a bare checkout (no pip install needed —
agent.governance_audit's module-load imports are stdlib-only): build a valid
hash-chained ledger and assert verify_chain PASSES, then tamper one record and
assert it FAILS with the first break reported. This gives the CI gate genuine
teeth even though the CI checkout has no production ledger of its own.

Exit 0 on success, 1 on any assertion failure, 2 on error.
PATH-FREEZE: NEW additive script; imports agent.governance_audit read-only.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def main() -> int:
    try:
        from agent import governance_audit as ga
    except Exception as e:
        print(f"::error::audit_chain_selftest: import failed ({e})")
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="lg-au-selftest-"))
    led = ga.GovernanceLedger(tmp / "agent-audit.log")
    led.emit("session.start", action="agent.run", source_module="selftest")
    led.emit("tool.dispatch", action="tool.write_file",
             parameters={"path": "x"}, source_module="selftest")
    led.emit("tool.result", action="tool.write_file",
             outcome={"status": "success", "class": None}, source_module="selftest")

    good = ga.verify_chain(led.path)
    if not good.ok or good.checked != 3:
        print(f"::error::selftest: expected PASS on a good chain, got {good!r}")
        return 1
    print(f"[selftest] good chain: PASS ({good.checked} records verified)")

    # Tamper the middle record in place; its seal must no longer verify.
    lines = led.path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["action"] = "tool.exfiltrate"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    led.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    bad = ga.verify_chain(led.path)
    if bad.ok:
        print("::error::selftest: tampered chain verified as OK — verifier is blind")
        return 1
    if bad.break_seq != 2:
        print(f"::error::selftest: expected break at seq=2, got seq={bad.break_seq}")
        return 1
    print(f"[selftest] tampered chain: FAIL as expected "
          f"(break_seq={bad.break_seq}: {bad.reason})")
    print("[selftest] audit-chain verifier OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
