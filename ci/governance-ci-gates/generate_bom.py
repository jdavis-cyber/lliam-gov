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

Hashes are never copied forward as if real (JER-78): each skill's
``content_hash`` is the sha256 computed from its directory in this checkout,
and the manifest's ``signed_hash`` / ``signature`` are carried only when
provisioned. Anything absent or still a template is emitted as an explicit
``UNPROVISIONED: <reason>`` marker, never a hash-shaped placeholder.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Tuple


# --------------------------------------------------------------------------- #
# SBOM (LG-SS-05)
# --------------------------------------------------------------------------- #

def build_sbom(repo: Path | None = None) -> Dict[str, Any]:
    """A CycloneDX-shaped SBOM from the repository's locked dependencies."""
    repo = Path(repo) if repo is not None else Path(__file__).resolve().parents[2]
    lock_path = repo / "uv.lock"
    if not lock_path.is_file():
        raise FileNotFoundError(f"required lockfile missing: {lock_path}")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    components: List[Dict[str, Any]] = []
    for package in lock.get("package") or []:
        if not isinstance(package, dict) or not package.get("name") or not package.get("version"):
            continue
        name, version = str(package["name"]), str(package["version"])
        components.append({"type": "library", "name": name, "version": version,
                           "purl": f"pkg:pypi/{name.lower()}@{version}"})
    if not components:
        raise ValueError("uv.lock contains no versioned package entries")
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

def _load_yaml(path: Path, *, required: bool = True) -> Dict[str, Any]:
    try:
        import yaml
        if not path.is_file():
            raise FileNotFoundError(f"required AI-BOM input missing: {path}")
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"AI-BOM input is not a mapping: {path}")
        return data
    except Exception:
        if required:
            raise
        return {}


# Explicit marker for a value this build cannot attest (absent or template).
UNPROVISIONED = "UNPROVISIONED"

# Template shapes — mirrors lliam_cli/provisioning.py (this script runs in CI
# with only PyYAML installed, so it does not import the application package).
_TEMPLATE_TOKENS = (
    "REPLACE", "PLACEHOLDER", "RECOMPUTE", "UNPROVISIONED", "CHANGEME", "EXAMPLE",
)
_ANGLE_SLOT = re.compile(r"<[^<>]*>")
_SKILL_ROOTS = ("skills", "optional-skills")


def _is_template(value: Any) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    if not text or text.lower() in {"none", "null"} or "${" in text:
        return True
    if _ANGLE_SLOT.search(text):
        return True
    upper = text.upper()
    return any(token in upper for token in _TEMPLATE_TOKENS)


def _unprovisioned(reason: str) -> str:
    return f"{UNPROVISIONED}: {reason}"


def is_unprovisioned_marker(value: Any) -> bool:
    return str(value or "").startswith(UNPROVISIONED)


def skill_content_sha256(skill_dir: Path) -> str:
    """Full sha256 over a skill directory: relative path, NUL, bytes per file.

    Same shape as tools/skills_guard.content_hash (which truncates its digest
    for display); bytecode caches are skipped so the digest is checkout-stable.
    """
    h = hashlib.sha256()
    for f in sorted(Path(skill_dir).rglob("*")):
        if not f.is_file() or "__pycache__" in f.parts or f.suffix == ".pyc":
            continue
        h.update(f.relative_to(skill_dir).as_posix().encode("utf-8"))
        h.update(b"\x00")
        h.update(f.read_bytes())
    return f"sha256:{h.hexdigest()}"


def _skill_content_hash(repo: Path, name: Any) -> str:
    skill = str(name or "").strip()
    if not skill:
        return _unprovisioned("skill entry has no name")
    dirs = sorted(
        md.parent
        for root in _SKILL_ROOTS
        if (repo / root).is_dir()
        for md in (repo / root).rglob("SKILL.md")
        if md.parent.name == skill
    )
    if not dirs:
        return _unprovisioned(f"no skill directory named '{skill}' in the repository")
    if len(dirs) > 1:
        rels = ", ".join(d.relative_to(repo).as_posix() for d in dirs)
        return _unprovisioned(f"skill name '{skill}' is ambiguous ({rels})")
    return skill_content_sha256(dirs[0])


def _signed_skill_hash(manifest: Dict[str, Any], name: Any) -> str:
    hashes = manifest.get("skill_hashes")
    value = hashes.get(name) if isinstance(hashes, dict) else None
    if value is None:
        return _unprovisioned(f"model_manifest.yaml has no skill_hashes.{name}")
    if _is_template(value):
        return _unprovisioned(f"model_manifest.yaml skill_hashes.{name} is a template value")
    return str(value).strip()


def _manifest_signature(manifest: Dict[str, Any]) -> str:
    signature = manifest.get("signature")
    if _is_template(signature):
        return _unprovisioned(
            "model_manifest.yaml signature is a template value; re-sign with the provisioned key")
    return str(signature).strip()


def build_ai_bom(repo: Path) -> Dict[str, Any]:
    """Machine-readable AI inventory reconciled from the P3 policy artifacts."""
    repo = Path(repo)
    providers_doc = _load_yaml(repo / "policy" / "provider-allowlist.yaml")
    cards_doc = _load_yaml(repo / "policy" / "governed" / "model-cards.yaml")
    mcp_doc = _load_yaml(repo / "policy" / "mcp-allowlist.yaml")
    skills_doc = _load_yaml(repo / "policy" / "skills-allowlist.yaml")
    manifest = _load_yaml(repo / "model_manifest.yaml")

    providers = [
        {"id": p.get("id"), "class": p.get("provider_class"),
         "residency": p.get("data_residency"), "cui_eligible": p.get("cui_eligible")}
        for p in (providers_doc.get("providers") or []) if isinstance(p, dict)
    ]
    models = [
        {"id": m.get("id"), "provider": m.get("provider"),
         "serialization": m.get("serialization"), "cui_eligible": m.get("cui_eligible")}
        for m in (cards_doc.get("models") or []) if isinstance(m, dict)
    ]
    mcp_servers = [
        {"name": s.get("name"), "transport": s.get("transport"),
         "sdl_record": (s.get("sdl_review") or {}).get("record_ref")}
        for s in (mcp_doc.get("approved_servers") or []) if isinstance(s, dict)
    ]
    skills = [
        {"name": s.get("name"), "source": s.get("source"),
         "ast_audit": s.get("ast_audit"), "provenance": s.get("provenance"),
         "attestation": s.get("attestation"),
         "content_hash": _skill_content_hash(repo, s.get("name")),
         "signed_hash": _signed_skill_hash(manifest, s.get("name"))}
        for s in (((skills_doc.get("security") or {}).get("skill_allowlist")) or [])
        if isinstance(s, dict)
    ]
    if not providers or not models:
        raise ValueError("AI-BOM provider/model inventories must not be empty")
    return {
        "ai_bom_version": "lg-aibom/1",
        "application": "lliam-gov",
        "manifest_signer": manifest.get("signer"),
        "providers": providers,
        "models": models,
        "mcp_servers": mcp_servers,
        "skills": skills,
        "attestations": {
            "manifest_signature": _manifest_signature(manifest),
            "model_primary": (manifest.get("models") or {}).get("primary"),
            "model_fallback": (manifest.get("models") or {}).get("fallback"),
        },
        "relationships": [
            {"model": m.get("id"), "provider": m.get("provider")}
            for m in models
        ],
        "policies": {
            "provider_allowlist": "policy/provider-allowlist.yaml",
            "model_cards": "policy/governed/model-cards.yaml",
            "mcp_allowlist": "policy/mcp-allowlist.yaml",
            "skills_allowlist": "policy/skills-allowlist.yaml",
        },
    }


def write_boms(repo: Path, out_dir: Path) -> Tuple[str, str]:
    """Write sbom.json + ai-bom.yaml to out_dir; return their paths."""
    repo, out_dir = Path(repo), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sbom_path = out_dir / "sbom.json"
    ai_bom_path = out_dir / "ai-bom.yaml"
    sbom_path.write_text(json.dumps(build_sbom(repo), indent=2, sort_keys=True), encoding="utf-8")
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
