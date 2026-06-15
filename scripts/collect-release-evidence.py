#!/usr/bin/env python3
"""Collect the Lliam-GOV deployable-release evidence manifest (AI-338).

Walks the evidence inventory defined in `evidence/release/README.md`, checks
each stable path, hashes present artifacts, and writes a machine-readable
`evidence/release/manifest.json` plus a human summary. Decision-gated artifacts
(signing, checksums, QA results) are reported PENDING — never fabricated — so the
manifest always reflects true release readiness. Ties into the audit-log AEP
(`lliam_gov/security/aep_export.py`) as the release-level overlay.

Usage:
    python3 scripts/collect-release-evidence.py
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "evidence" / "release" / "manifest.json"

# (id, description, stable path relative to repo, gating note)
INVENTORY = [
    ("threat-model", "Provider boundary threat model (T1–T8)",
     "docs/governance/provider-boundary-threat-model.md", None),
    ("data-flow", "Architecture / data-flow / provider-boundary notes",
     "docs/operate/managed-backend-bootstrap.md", None),
    ("sbom-python-node", "CycloneDX SBOMs",
     "evidence/sbom/cyclonedx-2026-06-12-post-bump.json", None),
    ("dependency-review", "Dependency review",
     "evidence/sbom/dependency-review-2026-06-12.md", None),
    ("dependency-policy", "Dependency audit policy",
     "docs/governance/dependency-audit-policy.md", None),
    ("readiness-gate", "Release-readiness gate script",
     "scripts/release-readiness.py", None),
    ("deployment-tiers", "Deployment tiers + AIMS scope",
     "evidence/release/deployment-tiers.md", None),
    ("provider-approvals", "Approved providers + external obligations",
     "evidence/release/provider-approvals.md", None),
    ("residual-risks", "Residual risks & accepted limitations",
     "evidence/release/residual-risks.md", None),
    ("audit-aep", "Audit-log AEP exporter",
     "lliam_gov/security/aep_export.py", None),
    # Decision-gated — expected PENDING until the gating work lands.
    ("signing-records", "Signing / notarization records",
     "evidence/release/signing/records.json", "PENDING signing certs (AI-331; Jerome)"),
    ("checksums", "Artifact SHA256SUMS",
     "evidence/release/checksums/SHA256SUMS", "PENDING CI build (AI-332; Actions offline)"),
    ("qa-matrix", "Fresh-machine QA matrix results",
     "evidence/release/qa/results.json", "PENDING QA run (AI-335; Mac lane proven)"),
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    items = []
    present = pending = 0
    for ev_id, desc, rel, gating in INVENTORY:
        p = REPO / rel
        if p.exists():
            items.append({
                "id": ev_id, "description": desc, "path": rel,
                "status": "present", "sha256": sha256(p),
            })
            present += 1
        else:
            items.append({
                "id": ev_id, "description": desc, "path": rel,
                "status": "pending", "gating": gating or "artifact not yet produced",
            })
            pending += 1

    manifest = {
        "schema": "lliam-gov.release.evidence",
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "desktopVersion": _desktop_version(),
        "summary": {"present": present, "pending": pending, "total": len(items)},
        "items": items,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(manifest, indent=2) + "\n")

    print("== Lliam-GOV release evidence ==")
    for it in items:
        mark = "PRESENT" if it["status"] == "present" else "PENDING"
        extra = f"  ({it.get('gating')})" if it["status"] == "pending" else ""
        print(f"  {mark}  {it['id']:<20} {it['path']}{extra}")
    print(f"-- {present} present, {pending} pending; manifest -> {OUT.relative_to(REPO)} --")
    return 0


def _desktop_version() -> str:
    try:
        pkg = json.loads((REPO / "apps" / "desktop" / "package.json").read_text())
        return pkg.get("version", "unknown")
    except Exception:  # noqa: BLE001
        return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
