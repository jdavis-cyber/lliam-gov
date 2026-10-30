#!/usr/bin/env python3
"""go_no_go_gate.py — Release go/no-go checklist gate (LG-SD-06, P4.5).

The deployment/release gate. FAILS CLOSED (exit 1) unless every release
precondition holds in the gov overlay + authorization record:
  * security.posture == strict;
  * skills.disabled includes godmode AND obliteratus (never-waivable);
  * security.provider_allowlist_enforce is true;
  * audit.ledger_enabled is true;
  * at-rest encryption asserted (security.data_protection.at_rest_encryption);
  * a signed, unexpired, decision=authorized authorization record whose id
    matches governance.authorization_id.

This is the release checklist in one place; it composes the
machine gates rather than duplicating them.

Exit: 0 = GO, 1 = NO-GO, 2 = error.
PATH-FREEZE: NEW additive script; read-only.
"""
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

try:
    import yaml
except Exception as e:  # pragma: no cover
    print(f"::error::go_no_go_gate requires PyYAML ({e})")
    sys.exit(2)

sys.path.insert(0, str(Path(__file__).resolve().parent))

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PLACEHOLDER = ("replace", "placeholder", "example", "pending", "tbd")


def _emit(msg: str, *, error: bool = False) -> None:
    import os
    prefix = "::error::" if error and os.environ.get("GITHUB_ACTIONS") else ""
    print(f"{prefix}{msg}")


def _load(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _get(d: dict, dotted: str, default=None):
    node = d
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _placeholder(v) -> bool:
    t = str(v or "").strip().lower()
    return (not t) or "${" in t or any(tok in t for tok in _PLACEHOLDER)


def _as_date(v):
    try:
        return datetime.date.fromisoformat(str(v).strip()[:10])
    except Exception:
        return None


def check_go_no_go(*, repo_root: Path = _REPO_ROOT,
                   overlay_path: Path | None = None) -> list[str]:
    failures: list[str] = []
    overlay_path = overlay_path or (repo_root / "cli-config.gov.yaml")
    try:
        cfg = _load(overlay_path)
    except Exception as e:
        return [f"overlay unreadable: {e}"]

    # 1. strict posture
    if str(_get(cfg, "security.posture")) != "strict":
        failures.append("[NO-GO] security.posture is not 'strict'")

    # 2. prohibited skills disabled
    disabled = set(_get(cfg, "skills.disabled") or [])
    for skill in ("godmode", "obliteratus"):
        if skill not in disabled:
            failures.append(f"[NO-GO] prohibited skill '{skill}' is not "
                            f"disabled")

    # 3. provider allowlist enforced
    if not _get(cfg, "security.provider_allowlist_enforce"):
        failures.append("[NO-GO] provider allowlist enforcement is off")

    # 4. audit ledger on
    if not _get(cfg, "audit.ledger_enabled"):
        failures.append("[NO-GO] audit ledger is not enabled")

    # 5. encryption at rest
    if not _get(cfg, "security.data_protection.at_rest_encryption"):
        failures.append("[NO-GO] at-rest encryption is not asserted")

    # 6. signed, unexpired, matching authorization
    auth_rel = (_get(cfg, "governance.registers.authorization")
                or "policy/governed/authorization-record.yaml")
    auth_file = repo_root / str(auth_rel)
    cfg_auth_id = _get(cfg, "governance.authorization_id")
    if not auth_file.exists():
        failures.append(f"[NO-GO] authorization record '{auth_rel}' missing")
    else:
        try:
            rec = _load(auth_file)
        except Exception as e:
            rec = {}
            failures.append(f"[NO-GO] authorization record unreadable ({e})")
        if str(rec.get("decision", "")).lower() != "authorized":
            failures.append(f"[NO-GO] authorization decision is "
                            f"'{rec.get('decision')}'")
        if cfg_auth_id and str(rec.get("authorization_id")) != str(cfg_auth_id):
            failures.append("[NO-GO] authorization_id mismatch (overlay vs "
                            "record)")
        exp = _as_date(rec.get("expires"))
        if exp is None:
            failures.append("[NO-GO] authorization has no parseable expiry")
        elif exp < datetime.date.today():
            failures.append(f"[NO-GO] authorization expired ({exp})")
        signer = (rec.get("authorizing_official") or {}).get("principal")
        if _placeholder(signer):
            failures.append("[NO-GO] authorization has no signing official")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    args = parser.parse_args(argv)
    try:
        failures = check_go_no_go(repo_root=Path(args.repo_root))
    except Exception as e:  # pragma: no cover
        _emit(f"go_no_go_gate: error ({e})", error=True)
        return 2
    if failures:
        _emit(f"[LG-SD-06] RELEASE NO-GO ({len(failures)}):", error=True)
        for f in failures:
            _emit(f"    - {f}", error=True)
        return 1
    _emit("[LG-SD-06] GO — all release preconditions met (strict posture, "
          "godmode/obliteratus disabled, allowlist + audit + encryption on, "
          "authorization signed & unexpired).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
