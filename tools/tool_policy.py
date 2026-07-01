"""tools/tool_policy.py — Lliam-GOV skill/tool enablement gate (least functionality).

ADDITIVE OVERLAY MODULE — no existing Hermes/Lliam module, file, CLI command,
tool name, skill path, or scanner identifier is renamed, moved, or refactored by
anything in here. (PATH-FREEZE.)

Realizes:
  * LG-SC-01 — deny-by-default skill/plugin allowlist; disable the godmode
    jailbreak skill and the other offensive optional-skills as a
    least-functionality exclusion.
  * LG-SC-02 — provenance + static AST audit before load (wraps the existing
    tools/skills_ast_audit.ast_scan_path + tools/skill_provenance).
  * LG-AZ-02 / LG-CH-04 — startup enablement gate that refuses to register any
    denied skill/tool.

How it is wired (capability-preserving, additive):
  ``policy_denied_skill_names()`` is unioned into the EXISTING chokepoint
  ``agent.skill_utils.get_disabled_skill_names()``. That function feeds skill
  discovery (``tools/skills_tool._find_all_skills``), slash-command registration
  (``agent/skill_commands.scan_skill_commands``) and the prompt builder — so a
  denied skill is refused at registration everywhere at once, by policy, without
  renaming any skill or touching the registry's identifiers.

  A denied skill is one that is:
    * named in the policy denylist (``skills.disabled`` in the policy file or the
      effective gov config), OR in the always-deny ``never_eligible`` set, OR in
      the built-in offensive backstop set; or
    * (fuller gate) carries jailbreak/abliteration intent in its SKILL.md
      tags/description (``deny_tags``), even if re-vendored under a new name.

  The named-deny path runs on the hot config path and is cheap + deterministic.
  The intent/tag + allowlist + AST checks run in ``enforce_skill_enablement()``
  (the explicit startup gate), which logs each denial/hold with a clear reason.

Capability preservation (graduated, NOT blanket-deny):
  * Offensive/jailbreak skills (godmode, obliteratus, web-pentest, sherlock,
    oss-forensics) are HARD-DENIED under strict posture — categorically unsafe.
  * A skill that is merely *not yet on the allowlist* is, by default, LOGGED
    (detect-and-log), NOT blocked — so the ~120 built-in skills keep working.
    Full deny-by-default of unlisted skills is opt-in via the policy
    (``unlisted_disposition: hold``) once the allowlist has been curated.
  * The whole gate is a NO-OP unless ``security.posture == strict`` — low-side
    deployments are completely unaffected.

Never raises into the skill path: a policy fault logs and falls back to the
offensive backstop denylist rather than breaking skill listing.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger("hermes.governance.tool_policy")

# Built-in backstop: under strict posture these are ALWAYS denied even if the
# policy file is missing/unparseable. Mandatory must-disable are a subset.
_OFFENSIVE_BACKSTOP: Tuple[str, ...] = (
    "godmode", "obliteratus", "web-pentest", "sherlock", "oss-forensics",
)
_NEVER_ELIGIBLE: Tuple[str, ...] = ("godmode", "obliteratus")

# Default intent tags that mark a (possibly re-vendored) offensive skill.
_DEFAULT_DENY_TAGS: Tuple[str, ...] = (
    "jailbreak", "uncensoring", "safety-bypass", "refusal-removal",
    "abliteration", "guardrail-removal", "prompt-injection-offense",
)

_POLICY_FILENAME = "skills-allowlist.yaml"

# Caches (per-process). _POLICY_CACHE keyed on (path, mtime_ns, size).
_POLICY_CACHE: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}
_DENIED_LOGGED: Set[str] = set()
# Tag-scan cache: signature of scanned skill dirs -> set of tag-denied names.
_TAG_SCAN_CACHE: Dict[Tuple[Tuple[str, int], ...], Set[str]] = {}


def _as_set(values: Any) -> Set[str]:
    if values is None:
        return set()
    if isinstance(values, str):
        values = [values]
    try:
        return {str(v).strip() for v in values if str(v).strip()}
    except TypeError:
        return set()


# --------------------------------------------------------------------------- #
# Posture + policy-file resolution
# --------------------------------------------------------------------------- #

def _is_strict() -> bool:
    """True when the effective gov config posture is strict (no-op otherwise)."""
    try:
        from hermes_cli import config as _cfg
        from hermes_cli import posture_resolver as _pr
        return _pr.is_strict(_cfg.load_config())
    except Exception:
        return False


def _candidate_policy_paths() -> List[Path]:
    paths: List[Path] = []
    env = os.environ.get("HERMES_SKILL_POLICY")
    if env and env.strip():
        paths.append(Path(env).expanduser())
    home = os.environ.get("HERMES_HOME")
    if home:
        paths.append(Path(home).expanduser() / "policy" / _POLICY_FILENAME)
    overlay = os.environ.get("HERMES_CONFIG")
    if overlay:
        paths.append(Path(overlay).expanduser().parent / "policy" / _POLICY_FILENAME)
    # Repo-relative fallback (clone layout: <repo>/policy/skills-allowlist.yaml)
    paths.append(Path(__file__).resolve().parent.parent / "policy" / _POLICY_FILENAME)
    return paths


def _resolve_policy_path() -> Optional[Path]:
    for p in _candidate_policy_paths():
        try:
            if p.is_file():
                return p
        except OSError:
            continue
    return None


def load_skill_policy() -> Dict[str, Any]:
    """Parse the skills-allowlist policy file (cached on mtime). {} if absent."""
    path = _resolve_policy_path()
    if path is None:
        return {}
    try:
        st = path.stat()
        key = str(path)
        cached = _POLICY_CACHE.get(key)
        if cached is not None and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
            return cached[2]
        import yaml
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            data = {}
        _POLICY_CACHE[key] = (st.st_mtime_ns, st.st_size, data)
        return data
    except Exception:
        logger.warning("tool_policy: could not read skill policy %s", path, exc_info=True)
        return {}


def _effective_config_disabled() -> Set[str]:
    """skills.disabled from the OVERLAY-aware effective config (load_config)."""
    try:
        from hermes_cli import config as _cfg
        cfg = _cfg.load_config()
        return _as_set((cfg.get("skills") or {}).get("disabled"))
    except Exception:
        return set()


def policy_mode() -> str:
    pol = load_skill_policy()
    mode = ((pol.get("policy") or {}).get("mode") or "enforce")
    return str(mode).strip().lower()


def deny_tags() -> Set[str]:
    pol = load_skill_policy()
    tags = _as_set((pol.get("skills") or {}).get("deny_tags"))
    return tags or set(_DEFAULT_DENY_TAGS)


def allowlist_names() -> Set[str]:
    pol = load_skill_policy()
    entries = ((pol.get("security") or {}).get("skill_allowlist")) or []
    names: Set[str] = set()
    for e in entries:
        if isinstance(e, dict) and e.get("name"):
            names.add(str(e["name"]).strip())
        elif isinstance(e, str):
            names.add(e.strip())
    return names


# --------------------------------------------------------------------------- #
# Named-deny set — the hot chokepoint union (LG-SC-01 / LG-AZ-02)
# --------------------------------------------------------------------------- #

def _skill_dirs() -> List[Path]:
    dirs: List[Path] = []
    try:
        from tools.skills_tool import SKILLS_DIR
        dirs.append(Path(SKILLS_DIR))
    except Exception:
        home = os.environ.get("HERMES_HOME")
        if home:
            dirs.append(Path(home).expanduser() / "skills")
    try:
        from agent.skill_utils import get_external_skills_dirs
        dirs.extend(Path(d) for d in get_external_skills_dirs())
    except Exception:
        pass
    return dirs


def _tag_denied_installed_names() -> Set[str]:
    """Names of INSTALLED skills whose SKILL.md tags/description match deny_tags.

    Catches re-vendored / renamed offensive skills at the registration chokepoint
    (not just at the load gate). Cached on the scanned dirs' mtimes so repeated
    hot-path calls are O(1). Empty if deny_tags is empty.
    """
    tags = deny_tags()
    if not tags:
        return set()
    sig: List[Tuple[str, int]] = []
    dirs: List[Path] = []
    for d in _skill_dirs():
        try:
            if d.is_dir():
                sig.append((str(d), d.stat().st_mtime_ns))
                dirs.append(d)
        except OSError:
            continue
    key = tuple(sig)
    cached = _TAG_SCAN_CACHE.get(key)
    if cached is not None:
        return cached
    denied: Set[str] = set()
    try:
        from agent.skill_utils import iter_skill_index_files as _iter_skills
    except Exception:
        _iter_skills = None
    for d in dirs:
        try:
            # Match the loader's nested-aware traversal (category/name/SKILL.md),
            # not just top-level */SKILL.md. Hermes discovery walks skills
            # recursively via iter_skill_index_files, so a re-vendored offensive
            # skill placed under a supported nested category is still registered
            # — the deny-tag backstop must cover the same paths or it is bypassed
            # under strict posture. (LG-SC-01/02)
            index = _iter_skills(d, "SKILL.md") if _iter_skills else d.glob("*/SKILL.md")
            for md in index:
                meta = _skill_meta(md.parent)
                if not meta:
                    continue
                if _matches_deny_tags(meta, tags):
                    denied.add(str(meta.get("name") or md.parent.name).strip())
        except Exception:
            continue
    _TAG_SCAN_CACHE[key] = denied
    return denied


def policy_denied_skill_names(platform: Optional[str] = None) -> Set[str]:
    """Names refused at registration under strict posture. {} on low-side.

    Unioned into agent.skill_utils.get_disabled_skill_names(). Named denylist
    (policy file + effective gov config) ∪ never_eligible ∪ offensive backstop ∪
    installed skills whose SKILL.md intent tags match deny_tags (re-vendor catch).
    """
    if not _is_strict():
        return set()
    denied: Set[str] = set(_OFFENSIVE_BACKSTOP) | set(_NEVER_ELIGIBLE)
    pol = load_skill_policy()
    denied |= _as_set((pol.get("skills") or {}).get("disabled"))
    denied |= _as_set((pol.get("exceptions") or {}).get("never_eligible"))
    denied |= _effective_config_disabled()
    denied |= _tag_denied_installed_names()
    newly = denied - _DENIED_LOGGED
    if newly:
        _DENIED_LOGGED.update(denied)
        logger.info(
            "Lliam-GOV skill enablement gate (LG-SC-01): denying %d skill(s) for "
            "strict posture: %s", len(denied), ", ".join(sorted(denied)),
        )
    return denied


# --------------------------------------------------------------------------- #
# Fuller per-skill decision + startup enablement gate (LG-SC-02)
# --------------------------------------------------------------------------- #

def ast_audit_clean(skill_dir: Path) -> Tuple[bool, str]:
    """Run the existing AST deep-audit over a skill dir (LG-SC-02).

    Returns (clean, report). clean=True when ast_scan_path finds nothing.
    """
    try:
        from tools.skills_ast_audit import ast_scan_path, format_ast_report
        findings = ast_scan_path(Path(skill_dir))
        if not findings:
            return True, "AST audit: no dynamic-import/obfuscation findings"
        return False, format_ast_report(findings, skill_name=Path(skill_dir).name)
    except Exception as e:  # pragma: no cover - audit must not crash the gate
        return True, f"AST audit unavailable ({e}); not blocking"


def _skill_meta(skill_dir: Path) -> Dict[str, Any]:
    """Best-effort SKILL.md frontmatter (name/tags/description)."""
    try:
        from tools.skills_tool import _parse_frontmatter
        md = Path(skill_dir) / "SKILL.md"
        if md.is_file():
            fm, _ = _parse_frontmatter(md.read_text(encoding="utf-8"))
            return fm if isinstance(fm, dict) else {}
    except Exception:
        pass
    return {}


def _matches_deny_tags(meta: Dict[str, Any], tags: Set[str]) -> Optional[str]:
    hay = " ".join(
        str(meta.get(k, "")) for k in ("tags", "description", "name", "title")
    ).lower()
    for t in tags:
        if t.lower() in hay:
            return t
    return None


def skill_load_decision(
    name: str,
    skill_dir: Optional[Path] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """Decide a single skill's disposition. Returns (decision, reason).

    decision ∈ {"deny", "hold", "allow"}. Only meaningful under strict posture;
    callers on low-side should not invoke this (returns "allow").
    """
    if not _is_strict():
        return "allow", "low-side (posture not strict)"

    nm = (name or "").strip()
    if nm in policy_denied_skill_names():
        mandatory = nm in (set(_NEVER_ELIGIBLE) | _as_set(
            (load_skill_policy().get("exceptions") or {}).get("never_eligible")))
        tag = " (mandatory must-disable)" if mandatory else ""
        return "deny", f"named in least-functionality denylist{tag} (LG-SC-01)"

    if meta is None and skill_dir is not None:
        meta = _skill_meta(skill_dir)
    if meta:
        hit = _matches_deny_tags(meta, deny_tags())
        if hit:
            return "deny", f"SKILL.md intent tag/description matches deny_tag '{hit}' (LG-SC-01/02)"

    allow = allowlist_names()
    if allow and nm not in allow:
        pol = load_skill_policy()
        disp = str(((pol.get("policy") or {}).get("unlisted_disposition")
                    or "log")).strip().lower()
        if disp == "hold":
            return "hold", "not on vetted allowlist; held pending SDL review (LG-SC-01/09)"
        return "allow", "not on allowlist — logged (detect mode; capability preserved)"

    # On the allowlist (or no allowlist curated): optionally require AST audit.
    pol = load_skill_policy()
    if skill_dir is not None and bool((pol.get("security") or {}).get("require_ast_audit")):
        clean, _report = ast_audit_clean(Path(skill_dir))
        if not clean:
            return "hold", "AST audit findings require review before load (LG-SC-02)"
    return "allow", "vetted / built-in"


def enforce_skill_enablement(installed: Iterable[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Startup enablement gate (LG-AZ-02): evaluate installed skills and log.

    ``installed`` is an iterable of {"name": str, "dir": Path-like (optional)}.
    Returns {"denied": [...], "held": [...], "allowed": [...]}. Each deny/hold is
    logged with a clear reason. This does not itself unregister — registration is
    refused via the get_disabled_skill_names() union — it is the explicit,
    auditable evaluation + log surface and the verification hook.
    """
    report: Dict[str, List[str]] = {"denied": [], "held": [], "allowed": []}
    if not _is_strict():
        report["allowed"] = [str(s.get("name", "")) for s in installed]
        return report
    for s in installed:
        name = str(s.get("name", "")).strip()
        sdir = s.get("dir")
        decision, reason = skill_load_decision(
            name, Path(sdir) if sdir else None, s.get("meta"))
        if decision == "deny":
            report["denied"].append(name)
            logger.warning("DENY skill '%s' — %s", name, reason)
        elif decision == "hold":
            report["held"].append(name)
            logger.warning("HOLD skill '%s' — %s", name, reason)
        else:
            report["allowed"].append(name)
    if report["denied"] or report["held"]:
        logger.info(
            "Lliam-GOV enablement gate summary: %d denied, %d held, %d allowed.",
            len(report["denied"]), len(report["held"]), len(report["allowed"]),
        )
    return report


# --------------------------------------------------------------------------- #
# Tool denylist hook (LG-AZ-02 for tools; extensible, skills are the P0.3 focus)
# --------------------------------------------------------------------------- #

def tool_denied(tool_name: str) -> bool:
    """True if a tool family is policy-denied under strict posture.

    Reads security.tool_denylist from the effective gov config. Returns False on
    low-side. Provided for registry wiring of tool (not just skill) denial.
    """
    if not _is_strict():
        return False
    try:
        from hermes_cli import config as _cfg
        sec = (_cfg.load_config().get("security") or {})
        return (tool_name or "").strip() in _as_set(sec.get("tool_denylist"))
    except Exception:
        return False
