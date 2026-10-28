#!/usr/bin/env python3
"""regulatory_reconciliation_gate.py — Regulatory-register reconciliation (LG-GV-03, P4.1).

Reads docs/governance/regulatory-register.yaml and FAILS CLOSED (exit 1) when
any legal/regulatory/contractual obligation is not bound to enforcement:
  * an obligation with no control ids or no config points;
  * a config point that does not resolve to a REAL enforced artifact —
    a `config_key` dotted path absent from cli-config.gov.yaml, a `file`
    that does not exist, or a `module` .py that does not exist;
  * a `partial` obligation with no `poam_ref` (unfinished work must be
    tracked, never silently declared);
  * a governance-block register/policy binding in cli-config.gov.yaml that
    points at a missing file.

Exit: 0 = fully reconciled (report printed), 1 = unbound obligation, 2 = error.
PATH-FREEZE: NEW additive script; read-only over governance files.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except Exception as e:  # pragma: no cover
    print(f"::error::regulatory_reconciliation_gate requires PyYAML ({e})")
    sys.exit(2)

_REPO_ROOT = Path(__file__).resolve().parents[2]

_REGISTER_REL = "docs/governance/regulatory-register.yaml"
_OVERLAY_REL = "cli-config.gov.yaml"
_VALID_STATUS = {"implemented", "partial", "inherited"}


def _emit(msg: str, *, error: bool = False) -> None:
    import os
    prefix = "::error::" if error and os.environ.get("GITHUB_ACTIONS") else ""
    print(f"{prefix}{msg}")


def _load_yaml(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _key_exists(cfg: dict, dotted: str) -> bool:
    node = cfg
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return True


def _resolve_config_point(point: dict, *, overlay: dict,
                          repo_root: Path) -> str | None:
    """Return an error string when the config point does not resolve."""
    kind = point.get("kind")
    if kind == "config_key":
        key = point.get("key", "")
        if not key or not _key_exists(overlay, key):
            return f"config_key '{key}' not present in {_OVERLAY_REL}"
        return None
    if kind == "file":
        rel = point.get("path", "")
        if not rel or not (repo_root / rel).exists():
            return f"file '{rel}' does not exist"
        return None
    if kind == "module":
        rel = point.get("path", "")
        if not rel or not rel.endswith(".py") or not (repo_root / rel).exists():
            return f"module '{rel}' does not exist"
        return None
    return f"unknown config-point kind '{kind}'"


def check_register(*, repo_root: Path = _REPO_ROOT) -> list[str]:
    """Reconcile every obligation to enforcement. Returns failure strings."""
    failures: list[str] = []
    reg_path = repo_root / _REGISTER_REL
    if not reg_path.exists():
        return [f"register missing: {_REGISTER_REL}"]
    try:
        register = _load_yaml(reg_path)
    except Exception as e:
        return [f"register unreadable: {e}"]
    try:
        overlay = _load_yaml(repo_root / _OVERLAY_REL)
    except Exception as e:
        return [f"overlay unreadable: {e}"]

    obligations = register.get("obligations") or []
    if not obligations:
        return ["register has no obligations"]

    for ob in obligations:
        oid = ob.get("id", "<missing-id>")
        if not ob.get("id") or not ob.get("source") or not ob.get("obligation"):
            failures.append(f"{oid}: missing id/source/obligation text")
        status = ob.get("status")
        if status not in _VALID_STATUS:
            failures.append(f"{oid}: invalid status {status!r} "
                            f"(expected one of {sorted(_VALID_STATUS)})")
        if status == "partial" and not ob.get("poam_ref"):
            failures.append(f"{oid}: 'partial' obligation has no poam_ref")
        controls = ob.get("controls") or []
        if not controls:
            failures.append(f"{oid}: no control bindings")
        points = ob.get("config_points") or []
        if not points:
            failures.append(f"{oid}: no config points")
        for point in points:
            err = _resolve_config_point(point, overlay=overlay,
                                        repo_root=repo_root)
            if err:
                failures.append(f"{oid}: {err}")
    return failures


def check_governance_bindings(*, repo_root: Path = _REPO_ROOT) -> list[str]:
    """The governance: block's policy/register bindings resolve to real files."""
    failures: list[str] = []
    try:
        overlay = _load_yaml(repo_root / _OVERLAY_REL)
    except Exception as e:
        return [f"overlay unreadable: {e}"]
    gov = (overlay or {}).get("governance") or {}
    if not gov:
        return ["overlay has no governance: block"]

    policy_path = gov.get("policy_path")
    if not policy_path or not (repo_root / policy_path).exists():
        failures.append(f"governance.policy_path '{policy_path}' missing")

    registers = gov.get("registers") or {}
    if not registers:
        failures.append("governance.registers block missing")
    for name, rel in registers.items():
        if not rel or not (repo_root / str(rel)).exists():
            failures.append(f"governance.registers.{name} '{rel}' missing")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root)

    try:
        failures = check_register(repo_root=repo_root)
        failures += check_governance_bindings(repo_root=repo_root)
    except Exception as e:  # pragma: no cover
        _emit(f"regulatory_reconciliation_gate: error ({e})", error=True)
        return 2

    if failures:
        _emit(f"[LG-GV-03] UNRECONCILED OBLIGATIONS ({len(failures)}):",
              error=True)
        for f in failures:
            _emit(f"    - {f}", error=True)
        return 1
    _emit("[LG-GV-03] OK — regulatory register fully reconciled to "
          "enforced config points.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
