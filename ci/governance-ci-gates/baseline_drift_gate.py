#!/usr/bin/env python3
"""baseline_drift_gate.py — Lliam-GOV baseline-drift gate (LG-CH-03 / LG-CH-09).

Compares the EFFECTIVE gov config against docs/governance/baseline-critical-keys.yaml
and FAILS CLOSED (exit 1) on any *critical*-severity drift. warn-severity drift is
logged, not blocking. No-op (exit 0) when the effective profile is not strict, so
non-gov branches are unaffected (capability-preserving).

Effective config resolution (most-faithful first):
  1. hermes_cli.config.load_config() with HERMES_CONFIG=overlay — the real merged
     + posture-coerced config (DEFAULT + home + overlay + posture_resolver).
  2. Fallback: parse the overlay YAML directly (every critical key is set
     explicitly in cli-config.gov.yaml, so this is sufficient when the package
     isn't importable, e.g. a lightweight CI runner).

PATH-FREEZE: a NEW additive script; reads the overlay + the baseline file only.

Usage:
    baseline_drift_gate.py --overlay <cli-config.gov.yaml> \
        --baseline docs/governance/baseline-critical-keys.yaml [--phase P0]
"""
from __future__ import annotations

import argparse
import os
import sys

try:
    import yaml
except Exception as e:  # pragma: no cover
    print(f"::error::baseline_drift_gate requires PyYAML ({e})")
    sys.exit(2)

_MISSING = object()


def _get(d, dotted: str):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


def _load_effective(overlay_path: str) -> tuple[dict, str]:
    """Return (config, source). Try the real loader, else parse the overlay."""
    os.environ["HERMES_CONFIG"] = overlay_path
    try:
        from hermes_cli.config import load_config  # type: ignore
        return load_config(), "effective (load_config: DEFAULT+home+overlay+posture_resolver)"
    except Exception:
        try:
            with open(overlay_path, encoding="utf-8") as f:
                return (yaml.safe_load(f) or {}), "overlay-yaml (fallback; hermes_cli not importable)"
        except Exception as e:  # pragma: no cover
            print(f"::error::cannot read overlay {overlay_path}: {e}")
            sys.exit(2)


def _matches(val, entry: dict) -> bool:
    if val is _MISSING:
        return False
    if "expect" in entry:
        if val != entry["expect"]:
            return False
    if "expect_contains" in entry:
        try:
            if not set(entry["expect_contains"]).issubset(set(val or [])):
                return False
        except TypeError:
            return False
    if "forbid" in entry:
        if val in (entry["forbid"] or []):
            return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--overlay", default=os.environ.get("HERMES_CONFIG", "cli-config.gov.yaml"))
    ap.add_argument("--baseline", default="docs/governance/baseline-critical-keys.yaml")
    ap.add_argument("--phase", default="P0",
                    help="only enforce keys whose activated_in starts with this (default P0)")
    a = ap.parse_args()

    baseline = yaml.safe_load(open(a.baseline, encoding="utf-8")) or {}
    cfg, source = _load_effective(a.overlay)
    print(f"[baseline-drift] effective config source: {source}")

    # Capability-preserving no-op when not the gov/strict profile.
    posture = _get(cfg, "security.posture")
    required = baseline.get("posture_required", "strict")
    if posture != required:
        print(f"[baseline-drift] security.posture={posture!r} != {required!r}; "
              f"non-gov profile — skipping drift gate (no-op).")
        return 0

    crit_drift, warn_drift, checked = [], [], 0
    for entry in baseline.get("critical_keys", []):
        act = str(entry.get("activated_in", ""))
        if not act.startswith(a.phase):     # only keys active by this phase
            continue
        checked += 1
        val = _get(cfg, entry["key"])
        if _matches(val, entry):
            continue
        shown = "MISSING" if val is _MISSING else repr(val)
        rec = (entry["key"], entry, shown)
        if entry.get("severity") == "critical":
            crit_drift.append(rec)
        else:
            warn_drift.append(rec)

    for key, entry, got in warn_drift:
        want = entry.get("expect", entry.get("expect_contains"))
        print(f"::warning::[baseline-drift] (warn) {key}: expected {want!r}, got {got} "
              f"[{entry.get('control','')}]")

    if crit_drift:
        print(f"::error::CRITICAL baseline drift (LG-CH-03) — failing closed. "
              f"{len(crit_drift)} critical key(s) drifted from the approved baseline:")
        for key, entry, got in crit_drift:
            want = entry.get("expect", entry.get("expect_contains"))
            print(f"  - {key}: expected {want!r}, got {got}  [{entry.get('control','')}]")
        print("Remediation: restore the key in cli-config.gov.yaml, or record an "
              "approved deviation (docs/governance/deviation-register.md, LG-CH-08).")
        return 1

    print(f"[baseline-drift] PASS — {checked} '{a.phase}*' critical/active keys match "
          f"the approved baseline ({len(warn_drift)} warn-level note(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
