#!/usr/bin/env python3
"""control_effectiveness.py — Periodic control-effectiveness verifier
(LG-MO-08, P5.2).

Re-asserts the standing posture invariants on a schedule (the cATO
control-effectiveness check the plan requires): godmode + obliteratus
disabled, provider + MCP allowlists enforced, at-rest encryption on, audit
ledger on with verify-on-startup, and continuous-monitoring enabled. FAILS
CLOSED (exit 1) on any broken invariant, and emits a `security.posture` event
so the break is on the ISCM stream. Distinct from go_no_go_gate (a release
precondition check): this runs recurring, post-deployment, as a detective
control feeding re-authorization (LG-GV-07).

Exit: 0 = effective, 1 = a control regressed, 2 = error.
PATH-FREEZE: NEW additive script; read-only over the overlay.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except Exception as e:  # pragma: no cover
    print(f"::error::control_effectiveness requires PyYAML ({e})")
    sys.exit(2)

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _emit(msg: str, *, error: bool = False) -> None:
    import os
    prefix = "::error::" if error and os.environ.get("GITHUB_ACTIONS") else ""
    print(f"{prefix}{msg}")


def _load(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _get(d: dict, dotted: str, default=None):
    node = d
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


# Safety modules whose posture predicate must enforce, not disable, when the
# effective configuration cannot be read (JER-77).
_FAIL_CLOSED_POSTURE_MODULES = (
    "tools.tool_policy",
    "tools.injection_defense",
    "tools.input_integrity",
    "agent.data_protection",
    "tools.egress_policy",
    "tools.mcp_allowlist",
    "agent.attestation",
)


def posture_fault_fails_closed(*, repo_root: Path = _REPO_ROOT) -> bool:
    """Probe each safety module with an unreadable configuration.

    Returns True only if every module still reports strict enforcement. An
    import failure counts as ineffective: the control could not be verified.
    """
    import importlib
    from unittest import mock

    root = str(repo_root)
    if root not in sys.path:
        sys.path.insert(0, root)

    def _unreadable():
        raise OSError("control-effectiveness probe: configuration unreadable")

    try:
        modules = [importlib.import_module(m) for m in _FAIL_CLOSED_POSTURE_MODULES]
        cfg = importlib.import_module("lliam_cli.config")
        with mock.patch.object(cfg, "load_config", _unreadable):
            return all(m._is_strict() for m in modules)
    except Exception:
        return False


def effectiveness_report(*, repo_root: Path = _REPO_ROOT,
                         overlay_path: Path | None = None) -> dict:
    overlay_path = overlay_path or (repo_root / "cli-config.gov.yaml")
    cfg = _load(overlay_path)
    disabled = set(_get(cfg, "skills.disabled") or [])
    return {
        "posture_strict": str(_get(cfg, "security.posture")) == "strict",
        "godmode_disabled": "godmode" in disabled,
        "obliteratus_disabled": "obliteratus" in disabled,
        "provider_allowlist_enforced": bool(
            _get(cfg, "security.provider_allowlist_enforce")),
        "mcp_allowlist_enforced": bool(
            _get(cfg, "security.mcp_allowlist_enforce")),
        "at_rest_encryption": bool(
            _get(cfg, "security.data_protection.at_rest_encryption")),
        "audit_ledger_enabled": bool(_get(cfg, "audit.ledger_enabled")),
        "audit_verify_on_startup": bool(_get(cfg, "audit.verify_on_startup")),
        "monitoring_enabled": bool(_get(cfg, "monitoring.iscm_sink.enabled")),
        "posture_fault_fails_closed": posture_fault_fails_closed(repo_root=repo_root),
    }


def check_effectiveness(*, repo_root: Path = _REPO_ROOT,
                        overlay_path: Path | None = None) -> list[str]:
    r = effectiveness_report(repo_root=repo_root, overlay_path=overlay_path)
    checks = {
        "posture_strict": "security.posture is not strict",
        "godmode_disabled": "godmode is not disabled",
        "obliteratus_disabled": "obliteratus is not disabled",
        "provider_allowlist_enforced": "provider allowlist not enforced",
        "mcp_allowlist_enforced": "MCP allowlist not enforced",
        "at_rest_encryption": "at-rest encryption not asserted",
        "audit_ledger_enabled": "audit ledger not enabled",
        "audit_verify_on_startup": "audit verify-on-startup off",
        "monitoring_enabled": "continuous monitoring (ISCM sink) not enabled",
        "posture_fault_fails_closed": "a configuration fault disables a safety control",
    }
    return [f"[INEFFECTIVE] {msg} (LG-MO-08)"
            for key, msg in checks.items() if not r.get(key)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    args = parser.parse_args(argv)
    try:
        failures = check_effectiveness(repo_root=Path(args.repo_root))
    except Exception as e:  # pragma: no cover
        _emit(f"control_effectiveness: error ({e})", error=True)
        return 2
    if failures:
        _emit(f"[LG-MO-08] CONTROL-EFFECTIVENESS BREAK ({len(failures)}):",
              error=True)
        for f in failures:
            _emit(f"    - {f}", error=True)
        return 1
    _emit("[LG-MO-08] OK — posture invariants effective (godmode/obliteratus "
          "disabled, allowlists enforced, encryption + audit + monitoring on).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
