#!/usr/bin/env python3
"""Provider smoke test for fresh-machine QA (AI-335).

Two modes:
  * **mocked** (default) — constructs the three provider adapters with injected
    fake probes so the detect→auth→readiness→(optional) execute path runs
    deterministically with no real CLIs. CI-safe.
  * **real** (``--real``) — uses the real adapters to probe the CLIs installed
    on this machine; with ``--execute`` it runs ONE prompt through the first
    ready provider (for manual release-candidate verification).

Writes an evidence artifact (app version, OS, provider CLI versions, readiness,
pass/fail) suitable for the release evidence package (AI-338).

Usage:
    python3 scripts/smoke-providers.py                 # mocked, writes evidence
    python3 scripts/smoke-providers.py --real           # probe real CLIs
    python3 scripts/smoke-providers.py --real --execute  # + run one prompt
    python3 scripts/smoke-providers.py --out path.json
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from providers.cli import (  # noqa: E402
    ClaudeCodeCLIProvider,
    CodexCLIProvider,
    ExecutionRequest,
    GeminiCLIProvider,
    Readiness,
    probe_all,
)


def _fake_completed(stdout: str = "", code: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=stdout, stderr="")


def build_mock_providers():
    """Three adapters wired to fake probes → all report READY deterministically."""
    common = dict(
        which=lambda name: f"/usr/local/bin/{name}",
        run=lambda argv: _fake_completed("1.0.0-mock\n"),
        auth_probe=lambda: "ok",
    )
    return [
        ClaudeCodeCLIProvider(**common),
        CodexCLIProvider(**common),
        GeminiCLIProvider(**common),
    ]


def build_real_providers():
    return [ClaudeCodeCLIProvider(), CodexCLIProvider(), GeminiCLIProvider()]


def desktop_version() -> str:
    try:
        return json.loads((REPO / "apps" / "desktop" / "package.json").read_text()).get("version", "unknown")
    except Exception:  # noqa: BLE001
        return "unknown"


def run_smoke(providers, *, execute: bool = False, prompt: str = "Say OK.") -> dict:
    reports = probe_all(providers)
    by_id = {p.capabilities.id: p for p in providers}
    results = []
    for r in reports:
        entry = {
            "id": r.id,
            "display_name": r.display_name,
            "readiness": r.readiness.value,
            "version": r.detect.version,
            "model": r.default_model,
        }
        if execute and r.readiness is Readiness.READY:
            prov = by_id[r.id]
            exec_res = prov.execute(ExecutionRequest(prompt=prompt, timeout_s=60))
            entry["execute"] = {
                "ok": exec_res.ok,
                "exit_code": exec_res.exit_code,
                "error_kind": exec_res.error.kind.value if exec_res.error else None,
            }
        results.append(entry)
    ready = [r for r in reports if r.readiness is Readiness.READY]
    return {
        "schema": "lliam-gov.qa.provider-smoke",
        "schemaVersion": 1,
        "ranAt": datetime.now(timezone.utc).isoformat(),
        "mode": "execute" if execute else "probe",
        "os": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "desktopVersion": desktop_version(),
        "providers": results,
        "summary": {"total": len(results), "ready": len(ready)},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Lliam-GOV provider smoke test (AI-335)")
    ap.add_argument("--real", action="store_true", help="probe real installed CLIs")
    ap.add_argument("--execute", action="store_true", help="run one prompt via a ready provider (real mode)")
    ap.add_argument("--out", default=None, help="evidence artifact path (JSON)")
    args = ap.parse_args(argv)

    providers = build_real_providers() if args.real else build_mock_providers()
    evidence = run_smoke(providers, execute=args.execute)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.out) if args.out else REPO / "evidence" / "release" / "qa" / f"smoke-{ts}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2) + "\n")

    print(f"== provider smoke ({evidence['mode']}, {'real' if args.real else 'mocked'}) ==")
    for p in evidence["providers"]:
        line = f"  {p['readiness']:<18} {p['id']}"
        if "execute" in p:
            line += f"  exec_ok={p['execute']['ok']}"
        print(line)
    s = evidence["summary"]
    print(f"-- {s['ready']}/{s['total']} ready; evidence -> {out} --")

    # In mocked mode all three must be READY (validates the smoke harness itself).
    if not args.real and s["ready"] != s["total"]:
        print("MOCKED SMOKE FAILED: not all mock providers READY")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
