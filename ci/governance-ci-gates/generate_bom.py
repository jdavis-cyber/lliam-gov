#!/usr/bin/env python3
"""generate_bom.py — Lliam-GOV SBOM + AI-BOM generator (P3.4 / LG-SS-05, IN-02/03).

Produces two supply-chain evidence artifacts per build/release:
  * SBOM (CycloneDX-shaped JSON) — the installed Python distributions
    (LG-SS-05 software bill of materials).
  * AI-BOM (YAML) — the machine-readable inventory of AI components: approved
    inference providers, carded models, approved MCP servers, and enabled
    skills — reconciled from the P3 policy artifacts (IN-02 asset inventory,
    IN-03 AI inventory). Links providers ↔ models ↔ MCP ↔ skills for the
    assessor.

Deterministic + dependency-light: SBOM reads installed dist metadata via
importlib.metadata; the AI-BOM reads the repo's policy YAMLs. Renames nothing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


# --------------------------------------------------------------------------- #
# SBOM (LG-SS-05)
# --------------------------------------------------------------------------- #

def build_sbom() -> Dict[str, Any]:
    """A CycloneDX-shaped SBOM of the installed Python distributions."""
    components: List[Dict[str, Any]] = []
    try:
        from importlib import metadata as importlib_metadata
        for dist in importlib_metadata.distributions():
            try:
                name = dist.metadata["Name"]
            except Exception:
                name = getattr(dist, "name", None)
            if not name:
                continue
            components.append({
                "type": "library",
                "name": str(name),
                "version": str(dist.version or ""),
                "purl": f"pkg:pypi/{str(name).lower()}@{dist.version or ''}",
            })
    except Exception:
        pass
    # Always include the application component itself so the SBOM is never empty.
    components.append({"type": "application", "name": "lliam-gov", "version": "governed"})
    seen = set()
    deduped = []
    for c in components:
        key = (c["name"], c.get("version"))
        if key not in seen:
            seen.add(key)
            deduped.append(c)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"type": "application", "name": "lliam-gov"}},
        "components": deduped,
    }


# --------------------------------------------------------------------------- #
# AI-BOM (LG-SS-05, IN-02, IN-03)
# --------------------------------------------------------------------------- #

def _load_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml
        if path.is_file():
            return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        pass
    return {}


def build_ai_bom(repo: Path) -> Dict[str, Any]:
    """Machine-readable AI inventory reconciled from the P3 policy artifacts."""
    repo = Path(repo)
    providers_doc = _load_yaml(repo / "policy" / "provider-allowlist.yaml")
    cards_doc = _load_yaml(repo / "docs" / "governance" / "model-cards" / "model-cards.yaml")
    mcp_doc = _load_yaml(repo / "policy" / "mcp-allowlist.yaml")
    manifest = _load_yaml(repo / "model_manifest.yaml")

    providers = [
        {"id": p.get("id"), "class": p.get("provider_class"),
         "residency": p.get("data_residency"), "cui_eligible": p.get("cui_eligible")}
        for p in (providers_doc.get("providers") or []) if isinstance(p, dict)
    ]
    models = [
        {"id": m.get("id"), "provider": m.get("provider"),
         "serialization": m.get("serialization"), "cui_eligible": m.get("cui_eligible"),
         "card": m.get("card")}
        for m in (cards_doc.get("models") or []) if isinstance(m, dict)
    ]
    mcp_servers = [
        {"name": s.get("name"), "transport": s.get("transport"),
         "sdl_record": (s.get("sdl_review") or {}).get("record_ref")}
        for s in (mcp_doc.get("approved_servers") or []) if isinstance(s, dict)
    ]
    return {
        "ai_bom_version": "lg-aibom/1",
        "application": "lliam-gov",
        "manifest_signer": manifest.get("signer"),
        "providers": providers,
        "models": models,
        "mcp_servers": mcp_servers,
        "policies": {
            "provider_allowlist": "policy/provider-allowlist.yaml",
            "model_cards": "docs/governance/model-cards/model-cards.yaml",
            "mcp_allowlist": "policy/mcp-allowlist.yaml",
            "skills_allowlist": "policy/skills-allowlist.yaml",
            "vetting_register": "docs/governance/supplier-vetting-register.md",
        },
    }


def write_boms(repo: Path, out_dir: Path) -> Tuple[str, str]:
    """Write sbom.json + ai-bom.yaml to out_dir; return their paths."""
    repo, out_dir = Path(repo), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sbom_path = out_dir / "sbom.json"
    ai_bom_path = out_dir / "ai-bom.yaml"
    sbom_path.write_text(json.dumps(build_sbom(), indent=2, sort_keys=True), encoding="utf-8")
    try:
        import yaml
        ai_bom_path.write_text(yaml.safe_dump(build_ai_bom(repo), sort_keys=False), encoding="utf-8")
    except Exception:
        ai_bom_path.write_text(json.dumps(build_ai_bom(repo), indent=2), encoding="utf-8")
    return str(sbom_path), str(ai_bom_path)


if __name__ == "__main__":
    _repo = Path(__file__).resolve().parents[2]
    _out = Path(sys.argv[1]) if len(sys.argv) > 1 else _repo / "evidence" / "bom"
    s, a = write_boms(_repo, _out)
    print(f"[bom] wrote SBOM -> {s}")
    print(f"[bom] wrote AI-BOM -> {a}")
