"""tools/tool_policy.py — Lliam-GOV skill/tool enablement gate (least functionality).

ADDITIVE OVERLAY MODULE — no existing Lliam-GOV/Lliam module, file, CLI command,
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
from lliam_cli.env_compat import getenv_compat
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
    """Strict-posture predicate; a configuration fault enforces (fails closed)."""
    from lliam_cli import posture_resolver as _pr
    return _pr.enforce_strict_controls("tool-policy PDP")


def _candidate_policy_paths() -> List[Path]:
    paths: List[Path] = []
    env = getenv_compat("SKILL_POLICY")
    if env and env.strip():
        paths.append(Path(env).expanduser())
    home = getenv_compat("HOME")
    if home:
        paths.append(Path(home).expanduser() / "policy" / _POLICY_FILENAME)
    overlay = getenv_compat("CONFIG")
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
        from lliam_cli import config as _cfg
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
    iter_skills = None
    try:
        from agent.skill_utils import iter_skill_index_files
        iter_skills = iter_skill_index_files
    except Exception:
        pass
    for d in dirs:
        try:
            # Match the loader's nested-aware traversal (category/name/SKILL.md),
            # not just top-level */SKILL.md. Lliam-GOV discovery walks skills
            # recursively via iter_skill_index_files, so a re-vendored offensive
            # skill placed under a supported nested category is still registered
            # — the deny-tag backstop must cover the same paths or it is bypassed
            # under strict posture. (LG-SC-01/02)
            index = iter_skills(d, "SKILL.md") if iter_skills else d.glob("*/SKILL.md")
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
    if nm in policy_denied_skill_names() or nm.rsplit(":", 1)[-1] in _NEVER_ELIGIBLE:
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
    if nm not in allow:
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


def policy_held_skill_names() -> Set[str]:
    """Hide unlisted installed skills when strict hold is explicitly activated.

    Re-scan the same local/external roots as discovery on each call so policy
    activation and newly installed skills cannot reuse a permissive cache.
    Actual loads also evaluate the full decision before serving any content.
    """
    if not _is_strict():
        return set()
    pol = load_skill_policy()
    if str((pol.get("policy") or {}).get("unlisted_disposition", "log")).lower() != "hold":
        return set()
    from agent.skill_utils import iter_skill_index_files
    approved = allowlist_names()
    held = set()
    for root in _skill_dirs():
        for md in iter_skill_index_files(root, "SKILL.md"):
            meta = _skill_meta(md.parent)
            name = str(meta.get("name") or md.parent.name)
            if name not in approved:
                held.add(name)
    return held


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
        from lliam_cli import config as _cfg
        sec = (_cfg.load_config().get("security") or {})
        return (tool_name or "").strip() in _as_set(sec.get("tool_denylist"))
    except Exception:
        return False


# =========================================================================== #
# P2.1 — Per-call Policy Decision Point (graduated dispositions)
#
# LG-AZ-01 (single PDP at the dispatch chokepoint), LG-RM-08 (the four-tier
# allow / detect_log / hitl_approve / deny ladder), consuming the policy of
# record policy/tool-risk-policy.yaml. Deny-by-default + fail-closed under
# strict posture; complete no-op on low-side postures. ADDITIVE — everything
# above this line (the P0 enablement gate) is unchanged.
# =========================================================================== #

from dataclasses import dataclass, field

_RISK_POLICY_FILENAME = "tool-risk-policy.yaml"

#: Valid dispositions, ordered least → most restrictive (used for force-up).
_TIER_ORDER: Tuple[str, ...] = ("allow", "detect_log", "hitl_approve", "deny")

#: Sentinel returned by _load_risk_policy() when the policy file exists but
#: could not be parsed — under fail_closed this must resolve every call to deny.
_POLICY_LOAD_ERROR = {"__policy_load_error__": True}

# Per-process caches (cleared by reset_pdp_state()).
_RISK_POLICY_CACHE: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}

# JIT grants and mutation counters are keyed by the caller's runtime session.
# A process-global singleton lets one gateway user spend another user's budget
# or inherit their approval, so the default key exists only for legacy callers
# that genuinely have no session identity.
_PDP_SESSIONS: Dict[str, Dict[str, Any]] = {}


def _pdp_session(session_id: Optional[str] = None) -> Dict[str, Any]:
    key = str(session_id or "default")
    return _PDP_SESSIONS.setdefault(
        key,
        {"grants": {}, "turn_mutating": 0, "session_mutating": 0},
    )

# File-mutating tools whose concrete target splits the file_write.* classes.
_FILE_WRITE_TOOLS: Tuple[str, ...] = ("write_file", "patch")

# Shell-executing tools whose command splits the shell.* classes.
_SHELL_TOOLS: Tuple[str, ...] = ("terminal",)


@dataclass(frozen=True)
class PolicyDecision:
    """One graduated PDP verdict for a concrete tool call (LG-RM-08)."""

    disposition: str                      # allow | detect_log | hitl_approve | deny
    action_class: str                     # resolved policy class ("unmatched" if none)
    tool_name: str = ""
    reason: str = ""
    origin: str = "class"                 # class | budget | jit — what produced the verdict

    @property
    def allows_execution(self) -> bool:
        """True for the ungated tiers (allow / detect_log) — the call proceeds."""
        return self.disposition in ("allow", "detect_log")


def reset_pdp_state(session_id: Optional[str] = None) -> None:
    """Clear PDP caches/session state (tests + session reset policy)."""
    _RISK_POLICY_CACHE.clear()
    if session_id is None:
        _PDP_SESSIONS.clear()
    else:
        _PDP_SESSIONS.pop(str(session_id or "default"), None)


def pdp_begin_turn(session_id: Optional[str] = None) -> None:
    """Start a new turn: reset the per-turn mutating budget (LG-AZ-10)."""
    _pdp_session(session_id)["turn_mutating"] = 0


def grant_capability(
    action_class: str,
    *,
    approver: str,
    ttl_seconds: Optional[int] = None,
    session_id: Optional[str] = None,
) -> None:
    """Record an approval-backed JIT grant for a default-off capability.

    LG-AZ-07: called from the approval flow (never by the agent itself — the
    agent cannot self-extend). TTL defaults to the policy's grant.ttl_seconds
    (1800s). Scope is per-session; reset_pdp_state() revokes everything.
    A grant NEVER re-enables a deny-tier class (deny is terminal).
    LG-GV-05: when ``security.require_authenticated_approver`` is set, the
    approver must be the authenticated approver principal bound to this
    context (a dashboard_auth user or the desktop app's local operator), else
    PermissionError.
    """
    import time
    from tools.hitl_oversight import _require_bound_approver
    _require_bound_approver(
        str(approver), gate=str(action_class).strip(), origin="jit_grant",
    )
    if ttl_seconds is None:
        policy = _load_risk_policy()
        zsp = policy.get("zero_standing_privilege") if isinstance(policy, dict) else {}
        try:
            ttl_seconds = int(((zsp or {}).get("grant") or {}).get("ttl_seconds") or 1800)
        except Exception:
            ttl_seconds = 1800
    _pdp_session(session_id)["grants"][str(action_class).strip()] = {
        "expires": time.time() + max(0, int(ttl_seconds)),
        "approver": str(approver),
    }
    try:
        from tools.hitl_oversight import record_decision
        record_decision(
            decision="approve", gate=str(action_class).strip(),
            target=str(action_class).strip(),
            description=f"JIT capability grant, ttl={ttl_seconds}s (LG-AZ-07)",
            approver=str(approver), origin="jit_grant",
        )
    except Exception:
        logger.warning("JIT grant ledger record failed (non-blocking)", exc_info=True)


def _active_grant(action_class: str, session_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    import time
    session = _pdp_session(session_id)
    grant = session["grants"].get(action_class)
    if not grant:
        return None
    expires = grant.get("expires")
    if expires is not None and time.time() >= float(expires):
        session["grants"].pop(action_class, None)   # expired → force re-approval
        return None
    return grant


def _pdp_config() -> Dict[str, Any]:
    """security.tool_risk_policy block from the effective gov config."""
    try:
        from lliam_cli import config as _cfg
        sec = (_cfg.load_config().get("security") or {})
        block = sec.get("tool_risk_policy") or {}
        return block if isinstance(block, dict) else {}
    except Exception:
        return {}


def _candidate_risk_policy_paths() -> List[Path]:
    paths: List[Path] = []
    configured = str(_pdp_config().get("policy_path") or "").strip()
    if configured:
        p = Path(configured).expanduser()
        paths.append(p)
        home = getenv_compat("HOME")
        if not p.is_absolute() and home:
            paths.append(Path(home).expanduser() / configured)
    home = getenv_compat("HOME")
    if home:
        paths.append(Path(home).expanduser() / "policy" / _RISK_POLICY_FILENAME)
    overlay = getenv_compat("CONFIG")
    if overlay:
        paths.append(Path(overlay).expanduser().parent / "policy" / _RISK_POLICY_FILENAME)
    # Repo-relative fallback (clone layout: <repo>/policy/tool-risk-policy.yaml)
    paths.append(Path(__file__).resolve().parent.parent / "policy" / _RISK_POLICY_FILENAME)
    return paths


def _load_risk_policy() -> Dict[str, Any]:
    """Parse the risk policy (cached on mtime). {} if absent; sentinel on error."""
    path = None
    for p in _candidate_risk_policy_paths():
        try:
            if p.is_file():
                path = p
                break
        except OSError:
            continue
    if path is None:
        return {}
    try:
        st = path.stat()
        key = str(path)
        cached = _RISK_POLICY_CACHE.get(key)
        if cached is not None and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
            return cached[2]
        import yaml
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ValueError("risk policy root is not a mapping")
        _RISK_POLICY_CACHE[key] = (st.st_mtime_ns, st.st_size, data)
        return data
    except Exception:
        logger.error(
            "tool_policy PDP: could not parse risk policy %s — failing closed",
            path, exc_info=True,
        )
        return _POLICY_LOAD_ERROR


def _class_tiers(policy: Dict[str, Any]) -> Dict[str, str]:
    tiers: Dict[str, str] = {}
    for entry in policy.get("action_classes") or []:
        if not isinstance(entry, dict):
            continue
        cls = str(entry.get("class") or "").strip()
        tier = str(entry.get("tier") or "").strip().lower()
        if cls and tier in _TIER_ORDER:
            tiers[cls] = tier
    return tiers


def _default_disposition(policy: Dict[str, Any]) -> str:
    for source in (_pdp_config(), (policy.get("metadata") or {})):
        try:
            disp = str(source.get("default_disposition") or "").strip().lower()
            if disp in _TIER_ORDER:
                return disp
        except Exception:
            continue
    return "deny"


# --------------------------------------------------------------------------- #
# Action-class resolution against the RESOLVED concrete target (LG-AZ-08)
# --------------------------------------------------------------------------- #

def _classify_file_write(path_arg: str) -> str:
    """Split file_write.* by the resolved target via the file_safety backend."""
    from agent import file_safety as fs
    resolved = os.path.realpath(os.path.expanduser(str(path_arg or "")))
    home = os.path.realpath(os.path.expanduser("~"))
    try:
        if resolved in fs.build_write_denied_paths(home):
            return "file_write.sensitive_path"
        for prefix in fs.build_write_denied_prefixes(home):
            if resolved.startswith(prefix):
                return "file_write.sensitive_path"
    except Exception:
        return "file_write.sensitive_path"   # backend fault → most restrictive
    roots = fs.get_safe_write_roots()
    if roots:
        for root in roots:
            if resolved == root or resolved.startswith(root + os.sep):
                return "file_write.in_safe_root"
        return "file_write.outside_safe_root"
    # No safe root configured: the denylist above still applied; the remaining
    # writes are the shipped-permissive default → bounded-mutation tier.
    if fs.is_write_denied(resolved):
        return "file_write.sensitive_path"   # lliam-home logs / mcp-tokens / pairing
    return "file_write.in_safe_root"


def _classify_shell(command: str) -> str:
    """Split shell.* via the EXISTING approval-guard backends (no re-parse)."""
    from tools import approval as ap
    blocked, _desc = ap._check_sudo_stdin_guard(command or "")
    if blocked:
        return "shell.sudo_stdin"
    hardline, _desc = ap.detect_hardline_command(command or "")
    if hardline:
        return "shell.hardline"
    try:
        normalized = ap._normalize_command_for_detection(command or "").lower()
        for pattern_re, _d in ap.DANGEROUS_PATTERNS_COMPILED:
            if pattern_re.search(normalized):
                return "shell.destructive"
    except Exception:
        return "shell.destructive"           # guard fault → gated tier, not open
    return "shell.non_destructive"


def resolve_action_class(function_name: str, function_args: Optional[Dict[str, Any]] = None) -> str:
    """Map a concrete tool call to its policy action class ("unmatched" if none).

    Every resolvable call lands on an EXPLICIT policy class — including the
    risk-tag fallbacks (network.egress / tool_mutation.bounded) — so the
    graduated ladder covers the whole tool surface with no silent blanket-deny
    of legitimate capability (LG-RM-03 coverage; capability preservation).
    "unmatched" (→ default_disposition) is reserved for calls whose risk
    cannot be classified at all.
    """
    name = (function_name or "").strip()
    args = function_args or {}
    if name in _FILE_WRITE_TOOLS:
        return _classify_file_write(str(args.get("path") or args.get("file_path") or ""))
    if name in _SHELL_TOOLS:
        return _classify_shell(str(args.get("command") or ""))
    if name == "computer_use":
        return "computer_use.desktop_control"
    if name == "memory":
        return "memory_write"                # LG-HO-04 (write_approval backend)
    if name == "skill_manage":
        return "skill_write"                 # LG-HO-04 (write_approval backend)
    if name == "delegate_task":
        return "delegation"                  # LG-AZ-08 scope-narrowing seam
    if name.startswith("browser_"):
        return "browser.unlisted_or_action"  # CUI baseline: browser toolset off
    try:
        from agent.governance_audit_hooks import classify_risk
        risk = classify_risk(name, args)
        if not risk:                         # LG-AU-09 low-risk read/introspection
            return "file_read"
        if "egress" in risk:
            return "network.egress"          # P2.5 splits by egress allowlist
        return "tool_mutation.bounded"       # incl. unknown/MCP tools (P3.3 vets)
    except Exception:
        pass
    return "unmatched"


# --------------------------------------------------------------------------- #
# The PDP — one graduated decision per concrete call (LG-AZ-01 / LG-RM-08)
# --------------------------------------------------------------------------- #

def evaluate_call(
    function_name: str,
    function_args: Optional[Dict[str, Any]] = None,
    *,
    session_id: Optional[str] = None,
) -> PolicyDecision:
    """Resolve one tool call to its graduated disposition.

    Low-side (posture not strict): unconditional allow — the PDP is a complete
    no-op, shipped behavior is untouched. Strict posture: resolve the concrete
    call to an action class and return its policy tier; unmatched classes fall
    to default_disposition (deny), and an unparseable policy fails closed.
    """
    name = (function_name or "").strip()
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr
        strict = _pr.is_strict(_cfg.load_config())
    except Exception:
        return PolicyDecision(
            disposition="deny", action_class="unevaluated", tool_name=name,
            reason="tool-risk configuration unavailable — failing closed",
        )
    if not strict:
        return PolicyDecision(
            disposition="allow", action_class="unevaluated", tool_name=name,
            reason="low-side (posture not strict) — PDP inactive",
        )

    policy = _load_risk_policy()
    if policy is _POLICY_LOAD_ERROR:
        return PolicyDecision(
            disposition="deny", action_class="unmatched", tool_name=name,
            reason="risk policy unparseable — failing closed (fail_closed=true)",
        )

    action_class = resolve_action_class(name, function_args)
    tier = _class_tiers(policy).get(action_class)
    if tier is None:
        default = _default_disposition(policy)
        return PolicyDecision(
            disposition=default, action_class="unmatched" if action_class == "unmatched" else action_class,
            tool_name=name,
            reason=f"no policy entry for class '{action_class}' — default_disposition ({default})",
        )
    reason = f"policy class '{action_class}' → {tier} (LG-RM-08)"

    # deny is terminal — no privileged mapping, grant, or budget changes it.
    if tier == "deny":
        return PolicyDecision(
            disposition="deny", action_class=action_class, tool_name=name, reason=reason,
        )

    # LG-PI-09: validate the concrete payload at the last shared dispatch
    # boundary. This closes the direct dataflow where injected tool output is
    # copied into a command, URL, or external-send argument in the next call.
    if action_class in {
        "network.egress", "external_send", "shell.non_destructive",
        "shell.destructive", "browser.unlisted_or_action",
    }:
        try:
            import json
            from tools.injection_defense import validate_output_sink
            sink_check = validate_output_sink(
                json.dumps(function_args or {}, ensure_ascii=False),
                sink=action_class,
            )
            if sink_check.blocked:
                return PolicyDecision(
                    disposition="hitl_approve", action_class=action_class,
                    tool_name=name, origin="injection",
                    reason=(
                        "tool payload contains indirect-injection markers "
                        f"({sink_check.matched}) — routed to HITL (LG-PI-09)"
                    ),
                )
        except Exception:
            logger.warning("output-sink validation failed — routing to HITL", exc_info=True)
            return PolicyDecision(
                disposition="hitl_approve", action_class=action_class,
                tool_name=name, origin="injection",
                reason="output-sink validation unavailable — failing closed",
            )

    # LG-PI-06 (P2.3): if this session has observed indirect-injection content,
    # escalate the dangerous side-effect classes (egress/exec/external send) to
    # hitl_approve so injected content cannot auto-trigger them. Reads/analysis
    # are untouched — the agent keeps working; only the side effect pauses.
    try:
        from tools.injection_defense import (
            injection_taint_reason,
            should_escalate_for_injection,
        )
        if should_escalate_for_injection(action_class, session_id=session_id):
            if _TIER_ORDER.index("hitl_approve") > _TIER_ORDER.index(tier):
                return PolicyDecision(
                    disposition="hitl_approve", action_class=action_class,
                    tool_name=name, origin="injection",
                    reason=(
                        "session tainted by observed indirect-injection content "
                        f"({injection_taint_reason(session_id=session_id)}) — side-effect action "
                        "routed to HITL, not auto-triggered (LG-PI-06)"
                    ),
                )
    except Exception:
        logger.warning("injection taint check failed (non-blocking)", exc_info=True)

    # LG-DP-10 (P2.4): once CUI is exposed in the session, egress/external-send
    # classes escalate to HITL so CUI cannot be freely exfiltrated. Local exec
    # and reads are unaffected (capability). P2.5 refines this to a
    # destination-precise allow/deny via data_protection.dlp_egress_decision.
    try:
        from agent.data_protection import session_cui_tainted
        if action_class in ("network.egress", "external_send") and session_cui_tainted(session_id=session_id):
            if _TIER_ORDER.index("hitl_approve") > _TIER_ORDER.index(tier):
                return PolicyDecision(
                    disposition="hitl_approve", action_class=action_class,
                    tool_name=name, origin="cui_taint",
                    reason=(
                        "CUI exposed in this session — egress routed to HITL "
                        "so CUI is not freely exfiltrated (LG-DP-10)"
                    ),
                )
    except Exception:
        logger.warning("CUI taint check failed (non-blocking)", exc_info=True)

    # Privileged force-up (LG-AZ-06): members never resolve below hitl_approve.
    priv = policy.get("privileged_functions") or {}
    if action_class in _as_set(priv.get("members")):
        forced = str(priv.get("force_disposition") or "hitl_approve").strip().lower()
        if forced not in _TIER_ORDER:
            forced = "hitl_approve"
        if _TIER_ORDER.index(forced) > _TIER_ORDER.index(tier):
            tier = forced
            reason = f"privileged function '{action_class}' forced to {tier} (LG-AZ-06)"

    # Zero-standing-privilege / JIT (LG-AZ-07): default-off capabilities need an
    # active approval-backed grant; with one, the gated call proceeds recorded.
    zsp = policy.get("zero_standing_privilege") or {}
    if zsp.get("enabled", True) and action_class in _as_set(zsp.get("default_off_capabilities")):
        grant = _active_grant(action_class, session_id=session_id)
        if grant is not None:
            tier = "detect_log"
            reason = (
                f"JIT grant active for '{action_class}' "
                f"(approver={grant.get('approver')}) — proceed + full record (LG-AZ-07)"
            )
        elif _TIER_ORDER.index("hitl_approve") > _TIER_ORDER.index(tier):
            tier = "hitl_approve"
            reason = f"default-off capability '{action_class}' has no active JIT grant (LG-AZ-07)"

    # Mutating-call budgets (LG-AZ-10) + runaway/consumption caps (LG-AZ-12):
    # consumed only by calls that will actually proceed, and only mutating ones.
    if tier in ("allow", "detect_log") and _is_mutating(name, function_args):
        budget = ((policy.get("budgets") or {}).get("max_mutating_calls")) or {}
        on_exceed = str(budget.get("on_exceed") or "hitl_approve").strip().lower()
        if on_exceed not in _TIER_ORDER:
            on_exceed = "hitl_approve"
        try:
            per_turn = int(budget.get("per_turn") or 0)
            per_session = int(budget.get("per_session") or 0)
        except Exception:
            per_turn = per_session = 0
        session = _pdp_session(session_id)
        if per_session and session["session_mutating"] >= per_session:
            return PolicyDecision(
                disposition=on_exceed, action_class=action_class, tool_name=name,
                origin="budget",
                reason=(
                    f"per-session mutating budget exhausted "
                    f"({per_session}) — pausing for approval (LG-AZ-12)"
                ),
            )
        if per_turn and session["turn_mutating"] >= per_turn:
            return PolicyDecision(
                disposition=on_exceed, action_class=action_class, tool_name=name,
                origin="budget",
                reason=(
                    f"per-turn mutating budget exhausted "
                    f"({per_turn}) — pausing for approval (LG-AZ-10)"
                ),
            )
        session["turn_mutating"] += 1
        session["session_mutating"] += 1

    return PolicyDecision(
        disposition=tier, action_class=action_class, tool_name=name, reason=reason,
    )


def _is_mutating(function_name: str, function_args: Optional[Dict[str, Any]]) -> bool:
    """True when the call mutates state (reads never consume budget — LG-AZ-10)."""
    try:
        from agent.governance_audit_hooks import classify_risk
        return "mutating" in classify_risk(function_name, function_args)
    except Exception:
        return True   # unknown risk → count it (conservative)


# --------------------------------------------------------------------------- #
# Chokepoint enforcement (LG-AZ-01) — invoked from the dispatch seams
# --------------------------------------------------------------------------- #

def _hitl_delegated_to_backend(action_class: str) -> bool:
    """True when the class's HITL gate is the EXISTING backend approval flow.

    Marked per-entry in the policy (``hitl_delegated_to_backend: true``) for
    classes whose backend already prompts an authenticated approver (e.g.
    shell.destructive → tools/approval.py). The PDP must not double-block
    those — capability preservation. Default false → the PDP gates.
    """
    policy = _load_risk_policy()
    if not isinstance(policy, dict):
        return False
    for entry in policy.get("action_classes") or []:
        if isinstance(entry, dict) and str(entry.get("class") or "").strip() == action_class:
            return bool(entry.get("hitl_delegated_to_backend"))
    return False


def _emit_pdp_ledger_event(decision: PolicyDecision, function_args: Optional[Dict[str, Any]]) -> None:
    """Record a blocking PDP verdict as ``policy.violation`` (LG-AZ-06/AU-02)."""
    try:
        from agent.governance_audit_hooks import _enabled_ledger, classify_risk
        ledger = _enabled_ledger()
        if ledger is None:
            return
        ledger.emit(
            "policy.violation",
            action=f"tool.{decision.tool_name}",
            decision="deny" if decision.disposition == "deny" else "halt",
            parameters=dict(function_args or {}),
            risk_scope=set(classify_risk(decision.tool_name, function_args)),
            resource={"type": "tool", "name": decision.tool_name},
            source_module="tools/tool_policy.py",
            outcome={
                "action_class": decision.action_class,
                "disposition": decision.disposition,
                "origin": decision.origin,
                "reason": decision.reason,
            },
        )
    except Exception:
        # Observer safety: the PDP verdict stands regardless; the ledger's own
        # fail-closed contract (LG-AU-09) is enforced by predispatch_gate.
        logger.warning("PDP ledger emit failed (non-blocking)", exc_info=True)


def pdp_gate(
    function_name: str,
    function_args: Optional[Dict[str, Any]] = None,
    *,
    session_id: Optional[str] = None,
):
    """Enforce the PDP verdict at a dispatch seam.

    Returns None when the call may proceed (allow / detect_log, low-side, or a
    HITL class whose approval gate is the existing backend flow). Returns a
    blocking ``ToolGuardrailDecision`` for deny (fail-closed) and for
    hitl_approve with no bound approver path (deny_on_no_approver — LG-HO-06).
    Never raises.
    """
    try:
        decision = evaluate_call(function_name, function_args, session_id=session_id)
        if decision.allows_execution:
            return None
        if (
            decision.disposition == "hitl_approve"
            and decision.origin == "class"
            and _hitl_delegated_to_backend(decision.action_class)
        ):
            return None   # existing backend approval flow is the HITL gate
        _emit_pdp_ledger_event(decision, function_args)
        from agent.tool_guardrails import ToolGuardrailDecision
        if decision.disposition == "deny":
            return ToolGuardrailDecision(
                action="block", code="pdp_deny", tool_name=decision.tool_name,
                message=(
                    f"Blocked by tool-risk policy: {decision.reason} "
                    "(deny is terminal — no toggle or grant re-enables it)"
                ),
            )
        return ToolGuardrailDecision(
            action="block", code="pdp_approval_required", tool_name=decision.tool_name,
            message=(
                f"Approval required by tool-risk policy: {decision.reason}. "
                "Routed to HITL; without an authenticated approver this is "
                "denied fail-closed (LG-HO-06)."
            ),
        )
    except Exception:
        logger.error("pdp_gate internal error — failing closed", exc_info=True)
        try:
            from agent.tool_guardrails import ToolGuardrailDecision
            return ToolGuardrailDecision(
                action="block", code="pdp_error",
                tool_name=(function_name or "").strip(),
                message="Tool-risk PDP errored — failing closed (fail_closed=true)",
            )
        except Exception:
            return None
