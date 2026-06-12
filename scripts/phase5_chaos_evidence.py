"""Phase 5 chaos / fail-closed evidence harness (AI-229, WBS LG-5.5).

Deliberately breaks each key control dependency and proves Lliam-GOV fails
CLOSED — refuses the protected operation rather than degrading open. Each
scenario writes a pass/fail line; the run exits non-zero unless every
scenario fails closed. Artifacts land under ``evidence/phase5/chaos/``.

Scenarios (Rev. 3 §9 Phase 5):

1. Audit log unavailable        -> tool dispatch refuses (fail-closed audit)
2. Keyring unavailable          -> protected key operation refuses
3. Egress misconfigured/empty   -> non-allowlisted traffic denied
4. Rejected self-mod proposal   -> payload never enters live state

This harness uses isolated temp homes and monkeypatched failure injection;
it never touches a real operator home. Run:

    UV_PROJECT_ENVIRONMENT=... uv run python scripts/phase5_chaos_evidence.py \\
        --out evidence/phase5/chaos
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Allow running as a bare script (scripts/ is sys.path[0], not the repo root).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _fresh_home() -> str:
    d = tempfile.mkdtemp(prefix="lliam-chaos-")
    os.chmod(d, 0o700)
    return d


def scenario_audit_unavailable() -> tuple[bool, str]:
    """Make the audit dir uncreatable; a *granted* dispatch must still refuse.

    Injection note: the logger hardens its OWN audit dir to 0700 on every
    init (``_ensure_dirs``), so chmod-ing a pre-made audit dir is undone.
    The unspoofable break is a read-only HERMES_HOME — the logger's
    ``audit/`` mkdir then raises before any chmod, and dispatch must return
    the audit error instead of running the handler. The probe is granted
    its capability so the refusal can ONLY come from the audit dependency,
    not the capability gate.
    """
    home = _fresh_home()
    os.environ["HERMES_HOME"] = home
    os.environ["LLIAM_GOV_CAPABILITY_ENFORCE"] = "1"
    os.environ["LLIAM_GOV_CAPABILITIES"] = "fs_write"

    import lliam_gov.security.audit_logger as al
    al._shared_audit_logger = None

    from model_tools import handle_function_call
    from tools.registry import registry

    registry.register(
        name="chaos_probe_tool", toolset="file",  # -> fs_write, granted
        schema={"name": "chaos_probe_tool", "parameters": {"type": "object", "properties": {}}},
        handler=lambda *a, **kw: "SHOULD-NOT-RUN", check_fn=None,
        requires_env=None, is_async=False, description="", emoji="",
    )
    os.chmod(home, 0o500)  # read-only home -> audit/ mkdir fails, un-undoable
    try:
        result = handle_function_call("chaos_probe_tool", {"x": 1}, session_id="chaos")
        ran = "SHOULD-NOT-RUN" in result
        failed_closed = ("audit" in result.lower()) and not ran
        return failed_closed, f"read-only-home dispatch -> {result[:160]}"
    finally:
        registry.deregister("chaos_probe_tool")
        os.chmod(home, 0o700)
        al._shared_audit_logger = None


def scenario_keyring_unavailable() -> tuple[bool, str]:
    """A wedged keyring must make the key-manager probe refuse."""
    os.environ["HERMES_HOME"] = _fresh_home()
    from lliam_gov.security import encrypted_file
    from lliam_gov.security.runtime_guard import KeychainUnavailable, keychain_check

    encrypted_file.reset_shared_key_manager()
    orig = encrypted_file.get_shared_key_manager

    def _broken():
        raise RuntimeError("keyring locked (chaos injection)")

    encrypted_file.get_shared_key_manager = _broken
    try:
        keychain_check()
        return False, "keychain_check did NOT refuse on a broken keyring"
    except KeychainUnavailable as exc:
        return True, f"keychain probe failed closed -> {str(exc)[:140]}"
    finally:
        encrypted_file.get_shared_key_manager = orig


def scenario_egress_misconfigured() -> tuple[bool, str]:
    """Enforcement on + empty allowlist must deny non-loopback egress."""
    os.environ["HERMES_HOME"] = _fresh_home()
    os.environ["LLIAM_GOV_EGRESS_ENFORCE"] = "1"
    os.environ.pop("LLIAM_GOV_EGRESS_ALLOWLIST", None)
    from lliam_gov.security.egress import EgressDenied, check_egress

    try:
        check_egress("model-provider.example", 443)
        return False, "egress was NOT denied with an empty allowlist"
    except EgressDenied as exc:
        return True, f"empty-allowlist egress denied -> {str(exc)[:140]}"


def scenario_selfmod_rejected() -> tuple[bool, str]:
    """A rejected self-mod proposal must never enter live state."""
    os.environ["HERMES_HOME"] = _fresh_home()
    os.environ["LLIAM_GOV_SELFMOD_GATE"] = "1"
    os.environ.pop("LLIAM_GOV_PRIVILEGED_USERS", None)
    from lliam_gov.security.selfmod_gate import (
        list_proposals,
        propose,
        reject_proposal,
    )

    pid = propose("tool:create_skill", "chaos: should be rejected", {"payload": "x"})
    reject_proposal(pid, "chaos run: reject to prove no live-state leak")
    pending = list_proposals("pending")
    rejected = list_proposals("rejected")
    ok = not pending and any(p.proposal_id == pid for p in rejected)
    return ok, f"rejected proposal {pid}: pending={len(pending)}, in_rejected={ok}"


SCENARIOS = [
    ("audit_log_unavailable", scenario_audit_unavailable),
    ("keyring_unavailable", scenario_keyring_unavailable),
    ("egress_misconfigured", scenario_egress_misconfigured),
    ("selfmod_rejected_no_leak", scenario_selfmod_rejected),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="evidence/phase5/chaos")
    args = parser.parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for name, fn in SCENARIOS:
        try:
            ok, detail = fn()
        except Exception as exc:  # a scenario harness error is a FAIL
            ok, detail = False, f"harness error: {exc}"
        results.append({"scenario": name, "failed_closed": ok, "detail": detail})

    all_ok = all(r["failed_closed"] for r in results)
    report = {
        "generated": _stamp(),
        "all_failed_closed": all_ok,
        "scenarios": results,
    }
    (out_dir / f"chaos-run-{_stamp()}.json").write_text(json.dumps(report, indent=2))

    lines = ["# Phase 5 chaos / fail-closed evidence (AI-229, WBS LG-5.5)", ""]
    lines.append(f"Generated: {report['generated']}  |  all failed closed: {all_ok}")
    lines.append("")
    for r in results:
        mark = "PASS (failed closed)" if r["failed_closed"] else "FAIL (did NOT fail closed)"
        lines.append(f"## {r['scenario']} — {mark}")
        lines.append(f"    {r['detail']}")
        lines.append("")
    (out_dir / "chaos-evidence-2026-06-12.md").write_text("\n".join(lines))

    print("\n".join(lines))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
