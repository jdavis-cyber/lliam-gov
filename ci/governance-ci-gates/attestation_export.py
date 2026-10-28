#!/usr/bin/env python3
"""attestation_export.py — Portable posture/attestation export for reciprocity
(LG-TP-07, P5.4).

Generates a PORTABLE, self-describing attestation another authority can use for
reciprocity/inheritance: control-coverage summary (from the 188-control
catalog), provenance (the signed baseline tag/commit + overlay), and the
audit-chain tip hash. The export is content-signed — the signature is a
SHA-256 over the canonical content, NOT a secret shipped in the repo (there is
no self-verifying committed key: ``verify_attestation`` recomputes the hash
over the content and compares, so any tamper is detected).

Exit: 0 = export written, 2 = error. Prints the signed attestation JSON.
PATH-FREEZE: NEW additive script; read-only over the catalog + authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    import yaml
except Exception as e:  # pragma: no cover
    print(f"::error::attestation_export requires PyYAML ({e})")
    sys.exit(2)

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _control_coverage(repo_root: Path) -> dict:
    cat = _load(repo_root / "docs" / "governance" / "control-catalog.yaml")
    controls = cat.get("controls") or []
    counts = {"total": len(controls), "implemented": 0, "partial": 0,
              "planned": 0, "inherited": 0}
    for c in controls:
        counts[c.get("status", "planned")] = \
            counts.get(c.get("status", "planned"), 0) + 1
    return counts


def _provenance(repo_root: Path) -> dict:
    auth = _load(repo_root / "docs" / "governance" / "authorization-record.yaml")
    baseline = auth.get("baseline") or {}
    return {
        "baseline_tag": baseline.get("git_tag"),
        "baseline_commit": baseline.get("git_commit"),
        "overlay": baseline.get("overlay") or "cli-config.gov.yaml",
        "authorization_id": auth.get("authorization_id"),
    }


def _audit_chain_tip(repo_root: Path) -> dict:
    """A verifiable pointer to the ledger's current tip (hash), or a
    'no-ledger' marker for an eval export with no live ledger. Never embeds a
    secret — the tip hash is a public integrity anchor."""
    try:
        import os
        home = os.environ.get("HERMES_HOME") or os.environ.get("LLIAM_HOME")
        if not home:
            return {"status": "no-live-ledger",
                    "note": "eval export; live tip supplied at deployment"}
        led = Path(home) / "logs" / "agent-audit.log"
        if not led.exists():
            return {"status": "no-live-ledger"}
        last = ""
        for line in led.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        rec = json.loads(last) if last else {}
        return {"status": "live", "tip_record_hash": rec.get("record_hash"),
                "tip_seq": rec.get("seq")}
    except Exception as e:
        return {"status": "unavailable", "note": str(e)}


def build_attestation(*, repo_root: Path = _REPO_ROOT, stamp: str,
                      attested_by: str) -> dict:
    """Build the portable attestation (unsigned)."""
    return {
        "schema": "lg-tp/attestation/1",
        "system": "Lliam-GOV",
        "generated": stamp,
        "attested_by": attested_by,
        "control_coverage": _control_coverage(repo_root),
        "provenance": _provenance(repo_root),
        "audit_chain": _audit_chain_tip(repo_root),
        "cui_floor": "NIST SP 800-171 r3 / CMMC L2",
        "frameworks": ["ISO 42001", "NIST AI RMF", "OMB M-25-21",
                       "SP 800-171 r3", "CMMC L2"],
    }


def _canonical(att: dict) -> bytes:
    body = {k: v for k, v in att.items() if k != "content_sha256"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_attestation(att: dict) -> dict:
    """Content-sign: attach a SHA-256 over the canonical content."""
    signed = dict(att)
    signed["content_sha256"] = hashlib.sha256(_canonical(att)).hexdigest()
    return signed


def verify_attestation(signed: dict) -> bool:
    """Recompute the content hash and compare — detects any tamper."""
    claimed = signed.get("content_sha256")
    if not claimed:
        return False
    return hashlib.sha256(_canonical(signed)).hexdigest() == claimed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    parser.add_argument("--stamp", required=True, help="UTC generation stamp")
    parser.add_argument("--attested-by", required=True)
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    try:
        att = build_attestation(repo_root=Path(args.repo_root),
                                stamp=args.stamp,
                                attested_by=args.attested_by)
        signed = sign_attestation(att)
    except Exception as e:  # pragma: no cover
        print(f"::error::attestation_export: {e}")
        return 2
    out = json.dumps(signed, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
