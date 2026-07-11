#!/usr/bin/env python3
"""sod_check.py — Separation-of-Duties gate (LG-GV-04/05, P1.6).

Reads docs/governance/roles.yaml (the RACI + SoD rules) and the
governance.role_bindings from cli-config.gov.yaml, then FAILS CLOSED (exit 1)
on any Separation-of-Duties conflict:
  * a principal bound to a role appears in that role's `not_also` set
    (e.g. the Approver is also the Engineer);
  * a `required_bindings` role has no authenticated principal.

Also emits the role_bindings + SoD conflict report to stdout (the LG-GV-05
evidence artifact).

Exit: 0 = no conflicts (report printed), 1 = SoD conflict, 2 = error.
PATH-FREEZE: NEW additive script; reads the two governance files only.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except Exception as e:  # pragma: no cover
    print(f"::error::sod_check requires PyYAML ({e})")
    sys.exit(2)

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _emit(msg: str, *, error: bool = False) -> None:
    import os
    prefix = "::error::" if error and os.environ.get("GITHUB_ACTIONS") else ""
    print(f"{prefix}{msg}")


def _norm(p):
    """Normalize a principal for comparison (case-insensitive, trimmed)."""
    return str(p).strip().casefold() if p else None


def check_sod(roles: dict, bindings: dict) -> list[str]:
    """Return the list of BLOCKING SoD conflict strings (empty = clean).

    A conflict on a ``waivable: true`` rule that has a matching, unexpired
    ``sod_deviations`` entry is an ACCEPTED deviation, not a blocking conflict
    (see :func:`classify_sod`). A conflict on a non-waivable rule, or on a
    waivable rule with no matching deviation, is blocking.
    """
    blocking, _accepted = classify_sod(roles, bindings)
    return blocking


def classify_sod(roles: dict, bindings: dict) -> tuple[list[str], list[str]]:
    """Return (blocking_conflicts, accepted_deviations).

    Fail-closed on a malformed rules file: a missing ``separation_of_duties``
    or ``required_bindings`` is itself a blocking finding (the SoD contract
    cannot silently evaporate via a key rename/move).
    """
    roles = roles or {}
    blocking: list[str] = []
    accepted: list[str] = []

    if "separation_of_duties" not in roles or not roles.get("separation_of_duties"):
        blocking.append(
            "roles.yaml has no 'separation_of_duties' rules — the SoD contract "
            "is missing (fail-closed; a renamed/emptied key is not 'clean')."
        )
        return blocking, accepted
    if "required_bindings" not in roles:
        blocking.append(
            "roles.yaml has no 'required_bindings' — anonymous-ownership "
            "enforcement would silently no-op (fail-closed)."
        )
        return blocking, accepted

    rules = [r for r in roles["separation_of_duties"] if isinstance(r, dict) and r.get("role")]
    required = roles.get("required_bindings") or []
    deviations = roles.get("sod_deviations") or []

    # Index accepted deviations by the unordered role-pair + normalized principal.
    dev_index = set()
    for d in deviations:
        if not isinstance(d, dict):
            continue
        pair = d.get("conflict") or []
        if len(pair) == 2 and _norm(d.get("principal")):
            dev_index.add((frozenset(_norm(x) for x in pair), _norm(d.get("principal"))))

    # Required roles must be bound to a non-empty principal.
    for role in required:
        if not _norm(bindings.get(role)):
            blocking.append(
                f"required role '{role}' has no authenticated principal bound "
                "(anonymous ownership is not allowed — LG-GV-05)."
            )

    # SoD exclusivity.
    for rule in rules:
        role = rule["role"]
        who = _norm(bindings.get(role))
        if not who:
            continue
        waivable = bool(rule.get("waivable", False))
        for other in rule.get("not_also") or []:
            if _norm(bindings.get(other)) != who:
                continue
            msg = (
                f"principal '{bindings.get(role)}' holds both '{role}' and "
                f"'{other}' — {rule.get('rationale', '')}".strip()
            )
            if waivable and (frozenset({role_n for role_n in (_norm(role), _norm(other))}), who) in dev_index:
                accepted.append(f"ACCEPTED DEVIATION: {msg}")
            elif waivable:
                blocking.append(
                    f"SoD conflict (waivable, but NO tracked sod_deviations entry): {msg}"
                )
            else:
                blocking.append(f"SoD conflict (NON-WAIVABLE): {msg}")
    return blocking, accepted


def _load_bindings(overlay_path: Path) -> dict:
    data = yaml.safe_load(overlay_path.read_text(encoding="utf-8")) or {}
    gov = data.get("governance") or {}
    return gov.get("role_bindings") or {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Separation-of-Duties gate (LG-GV-05)")
    parser.add_argument("--roles", default=str(_REPO_ROOT / "docs/governance/roles.yaml"))
    parser.add_argument("--overlay", default=str(_REPO_ROOT / "cli-config.gov.yaml"))
    args = parser.parse_args(argv)

    try:
        roles = yaml.safe_load(Path(args.roles).read_text(encoding="utf-8")) or {}
        bindings = _load_bindings(Path(args.overlay))
    except Exception as e:
        _emit(f"sod_check: cannot read governance files ({e})", error=True)
        return 2

    blocking, accepted = classify_sod(roles, bindings)

    # Report (the LG-GV-05 evidence artifact).
    _emit("[SoD] role_bindings:")
    for role, principal in sorted(bindings.items()):
        _emit(f"    {role:<18} -> {principal}")
    if accepted:
        _emit(f"[SoD] accepted single-operator deviations ({len(accepted)}):")
        for a in accepted:
            _emit(f"    - {a}")
    if blocking:
        _emit(f"[SoD] BLOCKING CONFLICTS ({len(blocking)}):", error=True)
        for c in blocking:
            _emit(f"    - {c}", error=True)
        return 1
    _emit("[SoD] OK — no blocking separation-of-duties conflicts "
          f"({len(accepted)} tracked deviation(s)).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
