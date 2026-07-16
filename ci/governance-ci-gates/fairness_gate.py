#!/usr/bin/env python3
"""fairness_gate.py — Fairness re-evaluation gate (LG-PF-07, P4.4).

Runs fairness evaluation/recalibration as a CI gate on model / provider /
system-prompt-seed change. FAILS CLOSED (exit 1) when:
  * a fairness-relevant artifact (model_manifest.yaml,
    policy/provider-allowlist.yaml, lliam_cli/default_soul.py) has changed
    and NO fairness-evaluation record in
    docs/governance/fairness-evaluations.yaml matches the CURRENT hashes —
    i.e. the change landed without a recorded fairness evaluation;
  * the matching evaluation record is unsigned/placeholder-valued or its
    outcome is not 'pass' / 'pass_with_conditions';
  * the bias risk register (docs/governance/bias-risk-register.yaml,
    LG-PF-06) is missing or empty.

The gate never blocks runtime work (CI/preflight only — capability
preserving); it makes an UNEVALUATED fairness-relevant change unmergeable.

Exit: 0 = evaluated, 1 = unevaluated change / bad register, 2 = error.
PATH-FREEZE: NEW additive script; read-only.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

try:
    import yaml
except Exception as e:  # pragma: no cover
    print(f"::error::fairness_gate requires PyYAML ({e})")
    sys.exit(2)

_REPO_ROOT = Path(__file__).resolve().parents[2]

# The fairness-relevant artifact set: what the agent says (prompt seed),
# which models it may run (manifest), and where inference may route
# (provider allowlist). A change to any of these is a fairness-relevant
# change per LG-PF-07.
_TRACKED = {
    "model_manifest": "model_manifest.yaml",
    "provider_allowlist": "policy/provider-allowlist.yaml",
    "prompt_seed": "lliam_cli/default_soul.py",
}

_PLACEHOLDER_TOKENS = ("replace", "placeholder", "example", "changeme",
                       "pending", "tbd", "fixme")
_VALID_OUTCOMES = {"pass", "pass_with_conditions"}


def _emit(msg: str, *, error: bool = False) -> None:
    import os
    prefix = "::error::" if error and os.environ.get("GITHUB_ACTIONS") else ""
    print(f"{prefix}{msg}")


def _is_placeholder(value) -> bool:
    text = str(value or "").strip()
    if not text or "${" in text:
        return True
    lowered = text.lower()
    return any(tok in lowered for tok in _PLACEHOLDER_TOKENS)


def current_hashes(*, repo_root: Path = _REPO_ROOT) -> dict[str, str]:
    """sha256 of each fairness-relevant artifact (empty-string hash if absent)."""
    out: dict[str, str] = {}
    for name, rel in _TRACKED.items():
        p = repo_root / rel
        data = p.read_bytes() if p.exists() else b""
        out[name] = hashlib.sha256(data).hexdigest()
    return out


def check_fairness(*, repo_root: Path = _REPO_ROOT) -> list[str]:
    failures: list[str] = []
    gov = repo_root / "docs" / "governance"

    # LG-PF-06 — the bias register must exist with named accountability.
    bias_path = gov / "bias-risk-register.yaml"
    if not bias_path.exists():
        failures.append("bias-risk-register.yaml missing (LG-PF-06)")
    else:
        try:
            bias = yaml.safe_load(bias_path.read_text(encoding="utf-8")) or {}
            risks = bias.get("risks") or []
            if not risks:
                failures.append("bias risk register is empty (LG-PF-06)")
            for r in risks:
                if _is_placeholder(r.get("owner_role")):
                    failures.append(f"bias risk {r.get('id')}: no accountable "
                                    f"owner (LG-PF-06)")
        except Exception as e:
            failures.append(f"bias register unreadable ({e}) (LG-PF-06)")

    # LG-PF-07 — the CURRENT fairness-relevant state must have a matching
    # evaluation record. A drifted artifact with no re-evaluation fails.
    hashes = current_hashes(repo_root=repo_root)
    eval_path = gov / "fairness-evaluations.yaml"
    if not eval_path.exists():
        failures.append("fairness-evaluations.yaml missing (LG-PF-07)")
        return failures
    try:
        evals = (yaml.safe_load(eval_path.read_text(encoding="utf-8"))
                 or {}).get("evaluations") or []
    except Exception as e:
        failures.append(f"fairness evaluations unreadable ({e}) (LG-PF-07)")
        return failures

    matched = None
    for entry in evals:
        baseline = entry.get("baseline") or {}
        if all(baseline.get(k) == v for k, v in hashes.items()):
            matched = entry
            break
    if matched is None:
        drifted = []
        for entry in evals:
            baseline = entry.get("baseline") or {}
            drifted.extend(k for k, v in hashes.items()
                           if baseline.get(k) not in (None, v))
        what = ", ".join(sorted(set(drifted))) or "all tracked artifacts"
        failures.append(
            f"fairness-relevant change ({what}: {_TRACKED}) has NO matching "
            f"fairness-evaluation record — re-evaluate and record before "
            f"merging (LG-PF-07)")
        return failures

    if _is_placeholder(matched.get("evaluator_role")):
        failures.append(f"evaluation {matched.get('id')}: evaluator missing/"
                        f"placeholder (LG-PF-07)")
    if _is_placeholder(matched.get("date")):
        failures.append(f"evaluation {matched.get('id')}: no date (LG-PF-07)")
    if str(matched.get("outcome", "")).lower() not in _VALID_OUTCOMES:
        failures.append(f"evaluation {matched.get('id')}: outcome "
                        f"'{matched.get('outcome')}' is not a pass (LG-PF-07)")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    args = parser.parse_args(argv)
    try:
        failures = check_fairness(repo_root=Path(args.repo_root))
    except Exception as e:  # pragma: no cover
        _emit(f"fairness_gate: error ({e})", error=True)
        return 2
    if failures:
        _emit(f"[LG-PF-07] FAIRNESS GATE FAILED ({len(failures)}):",
              error=True)
        for f in failures:
            _emit(f"    - {f}", error=True)
        return 1
    _emit("[LG-PF-07] OK — current model/provider/prompt state has a "
          "recorded fairness evaluation; bias register accountable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
