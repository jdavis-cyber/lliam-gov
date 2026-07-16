"""tools/mcp_allowlist.py — Lliam-GOV MCP & skill supply-chain vetting (P3.3).

ADDITIVE OVERLAY MODULE (PATH-FREEZE). Vets the MCP servers and skills the agent
loads, layered over the existing mcp_tool / managed_tool_gateway load path.
It renames nothing.

  * LG-SC-07 — deny-by-default: an MCP server not in policy/mcp-allowlist.yaml
    `approved_servers[]` is rejected (no auto-trust of a discovered server).
  * LG-SC-04 — block shell-egress / OS-persistence command shapes + known IOCs
    on a server's command/args.
  * LG-SC-05 — least-privilege scope: every server must declare tools.include[];
    default-deny write — a write tool outside the approved server's scope is
    rejected.
  * LG-SC-08 — HTTP/StreamableHTTP transports must require TLS.
  * LG-SC-03/09 — a third-party skill is refused execution unless it has clean
    provenance (skill attestation) under security.require_signed_skills;
    composes with tools/skill_provenance.py + tools/skills_ast_audit.py.

Capability preservation: complete no-op unless strict posture AND the relevant
enforce flag is set — low-side/dev MCP loading and skill execution are
untouched. Never raises into the load path.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lliam_cli.env_compat import getenv_compat

logger = logging.getLogger("hermes.governance.mcp_allowlist")

_POLICY_FILENAME = "mcp-allowlist.yaml"

# Shell-egress / OS-persistence IOC shapes on a server's command/args (LG-SC-04).
# Narrow, high-signal — mirrors the mcp_security _IOC_SUBSTRINGS intent.
_IOC_PATTERNS = [
    re.compile(r"\bcurl\b.*\|\s*(sh|bash)\b", re.I),
    re.compile(r"\bwget\b.*\|\s*(sh|bash)\b", re.I),
    re.compile(r">>?\s*~?/?\.(bashrc|zshrc|profile|bash_profile)\b", re.I),
    re.compile(r"\bcrontab\b", re.I),
    re.compile(r"/etc/(sudoers|cron|rc\.local)", re.I),
    re.compile(r"\bsystemctl\b.*\b(enable|start)\b", re.I),
    re.compile(r"\bnc\b\s+-|\bncat\b|\b/dev/tcp/", re.I),
]

# Tool-name shapes considered "write" for the default-deny-write check.
_WRITE_TOOL_HINTS = ("write", "edit", "create", "move", "delete", "put", "update", "patch", "remove")

_POLICY_CACHE: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}


@dataclass(frozen=True)
class MCPDecision:
    allowed: bool
    server: str = ""
    reason: str = ""


@dataclass(frozen=True)
class SkillDecision:
    allowed: bool
    skill: str = ""
    reason: str = ""


def reset_mcp_allowlist_cache() -> None:
    _POLICY_CACHE.clear()


def _is_strict() -> bool:
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr
        return _pr.is_strict(_cfg.load_config())
    except Exception:
        logger.warning("mcp-allowlist posture resolution failed; enforcing", exc_info=True)
        return True


def _security_cfg() -> Dict[str, Any]:
    try:
        from lliam_cli import config as _cfg
        return _cfg.load_config().get("security") or {}
    except Exception:
        return {}


def mcp_enforcement_enabled() -> bool:
    return _is_strict() and bool(_security_cfg().get("mcp_allowlist_enforce"))


def _candidate_paths() -> List[Path]:
    paths: List[Path] = []
    configured = str(_security_cfg().get("mcp_allowlist_path") or "").strip()
    if configured:
        p = Path(configured).expanduser()
        paths.append(p)
        home = getenv_compat("HOME")
        if not p.is_absolute() and home:
            paths.append(Path(home).expanduser() / configured)
    home = getenv_compat("HOME")
    if home:
        paths.append(Path(home).expanduser() / _POLICY_FILENAME)
    paths.append(Path(__file__).resolve().parent.parent / "policy" / _POLICY_FILENAME)
    return paths


def _load_policy() -> Dict[str, Any]:
    path = None
    for p in _candidate_paths():
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
        logger.error("mcp-allowlist: could not parse %s — failing closed", path, exc_info=True)
        return {"__load_error__": True}


def _approved_entry(policy: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    for entry in policy.get("approved_servers") or []:
        if isinstance(entry, dict) and str(entry.get("name") or "").strip() == (name or "").strip():
            return entry
    return None


def _has_ioc(command: str, args: Any) -> Optional[str]:
    blob = " ".join([str(command or "")] + [str(a) for a in (args or [])])
    for rx in _IOC_PATTERNS:
        if rx.search(blob):
            return rx.pattern
    return None


def _is_write_tool(tool: str) -> bool:
    t = (tool or "").lower()
    return any(h in t for h in _WRITE_TOOL_HINTS)


def check_mcp_server(name: str, live_entry: Dict[str, Any]) -> MCPDecision:
    """Vet one MCP server against the allowlist (LG-SC-04/05/07/08).

    ``live_entry`` is the runtime ``mcp_servers.<name>`` config. Low-side or
    enforcement off → allow (no-op).
    """
    if not mcp_enforcement_enabled():
        return MCPDecision(allowed=True, server=name, reason="not enforced (low-side / flag off)")

    policy = _load_policy()
    if policy.get("__load_error__"):
        return MCPDecision(allowed=False, server=name, reason="mcp allowlist unparseable — failing closed")
    pol = policy.get("policy") or {}

    # LG-SC-04 — IOC / shell-egress / persistence shapes (always-on).
    ioc = _has_ioc(live_entry.get("command"), live_entry.get("args"))
    if ioc:
        return MCPDecision(allowed=False, server=name,
                           reason=f"server command matches a shell-egress/persistence IOC shape (LG-SC-04)")

    if live_entry.get("command") and live_entry.get("url"):
        return MCPDecision(allowed=False, server=name,
                           reason=f"server '{name}' cannot declare both command and URL transports (LG-SC-07/08)")
    env = live_entry.get("env") or {}
    if isinstance(env, dict) and any(str(k).upper() == "PATH" for k in env):
        return MCPDecision(allowed=False, server=name,
                           reason=f"server '{name}' cannot override executable search PATH (LG-SC-07)")

    # LG-SC-07 — deny-by-default for unlisted servers.
    entry = _approved_entry(policy, name)
    if entry is None:
        if pol.get("allow_unlisted_servers"):
            return MCPDecision(allowed=True, server=name, reason="unlisted but allow_unlisted_servers set")
        return MCPDecision(allowed=False, server=name,
                           reason=f"server '{name}' not in the approved MCP allowlist (LG-SC-07)")

    tools = live_entry.get("tools") or {}
    include = [str(t).strip() for t in (tools.get("include") or [])]

    # LG-SC-05 — least-privilege: explicit include required.
    if pol.get("require_explicit_include", True) and not include:
        return MCPDecision(allowed=False, server=name,
                           reason=f"server '{name}' declares no tools.include[] (least-privilege required, LG-SC-05)")

    # LG-SC-05 — default-deny write: a write tool must be within the approved
    # server's allow_write + write_tools scope.
    scope = entry.get("scope") or {}
    approved_include = {str(t).strip() for t in (scope.get("include") or [])}
    unapproved_tools = sorted(set(include) - approved_include)
    if unapproved_tools:
        return MCPDecision(allowed=False, server=name,
                           reason=(f"server '{name}' includes tools outside approved scope: "
                                   f"{unapproved_tools} (LG-SC-05)"))
    allow_write = bool(scope.get("allow_write"))
    approved_write_tools = {str(t).strip() for t in (scope.get("write_tools") or [])}
    for t in include:
        if _is_write_tool(t):
            if not allow_write or t not in approved_write_tools:
                return MCPDecision(allowed=False, server=name,
                                   reason=(f"server '{name}' includes write tool '{t}' outside its approved "
                                       "write scope (default-deny-write, LG-SC-05)"))

    for capability in ("resources", "prompts"):
        if bool(tools.get(capability)) and not bool(scope.get(capability)):
            return MCPDecision(allowed=False, server=name,
                               reason=(f"server '{name}' enables {capability} outside its approved "
                                       "capability scope (LG-SC-05)"))

    # LG-SC-08 — TLS required on HTTP transports.
    live_url = str(live_entry.get("url") or "").strip()
    live_transport = str(live_entry.get("transport") or "").strip().lower()
    if not live_transport:
        live_transport = "streamable_http" if live_url else "stdio"
    transport = live_transport
    if transport in ("streamable_http", "sse", "http"):
        url = live_url.lower()
        if not url.startswith("https://") or live_entry.get("ssl_verify") is False:
            return MCPDecision(allowed=False, server=name,
                               reason=(f"HTTP MCP transport for '{name}' must use TLS/https with certificate "
                                       "verification enabled (LG-SC-08)"))

    # Bind the approved name to the concrete runtime identity.  A matching
    # label alone is not provenance: command/args or URL/transport drift is a
    # same-name substitution and must fail closed.
    approved_transport = str(entry.get("transport") or "").strip().lower()
    if approved_transport and live_transport != approved_transport:
        return MCPDecision(allowed=False, server=name,
                           reason=f"server '{name}' transport drifted from approved identity (LG-SC-07)")
    if live_transport == "stdio":
        if str(live_entry.get("command") or "").strip() != str(entry.get("command") or "").strip():
            return MCPDecision(allowed=False, server=name,
                               reason=f"server '{name}' command does not match approved identity (LG-SC-07)")
        if list(live_entry.get("args") or []) != list(entry.get("args") or []):
            return MCPDecision(allowed=False, server=name,
                               reason=f"server '{name}' arguments do not match approved identity (LG-SC-07)")
    elif live_url != str(entry.get("url") or "").strip():
        return MCPDecision(allowed=False, server=name,
                           reason=f"server '{name}' URL does not match approved identity (LG-SC-07)")

    approved_auth = entry.get("auth") or {}
    live_auth = live_entry.get("auth") or {}
    approved_auth_mode = str(
        approved_auth.get("mode") if isinstance(approved_auth, dict) else approved_auth
    ).strip().lower()
    live_auth_mode = str(
        live_auth.get("mode") if isinstance(live_auth, dict) else live_auth
    ).strip().lower() or "none"
    if approved_auth_mode and live_auth_mode != approved_auth_mode:
        return MCPDecision(allowed=False, server=name,
                           reason=f"server '{name}' auth mode does not match approved identity (LG-SC-07)")

    live_headers = live_entry.get("headers") or {}
    allowed_headers = {
        str(h).strip().lower()
        for h in ((entry.get("http_controls") or {}).get("allowed_headers") or [])
    }
    if isinstance(live_headers, dict):
        extra_headers = sorted(
            str(h) for h in live_headers if str(h).strip().lower() not in allowed_headers
        )
        if extra_headers:
            return MCPDecision(allowed=False, server=name,
                               reason=(f"server '{name}' declares unapproved HTTP headers: "
                                       f"{extra_headers} (LG-SC-07)"))

    return MCPDecision(allowed=True, server=name, reason=f"server '{name}' approved and within scope")


# --------------------------------------------------------------------------- #
# LG-SC-03/09 — skill attestation before execution
# --------------------------------------------------------------------------- #

def _provenance_clean(skill_name: str, skill_dir: Path) -> bool:
    """True when a skill has a clean provenance/attestation record.

    Built-ins and skills with a recorded clean origin pass; a third-party skill
    with no provenance record does not. Best-effort; reuses the existing
    provenance surface where present.
    """
    try:
        from tools.skill_provenance import has_clean_provenance  # type: ignore
        return bool(has_clean_provenance(skill_name, str(skill_dir)))
    except Exception:
        # No provenance oracle available for this skill → treat as unattested.
        return False


def skill_attestation_ok(skill_name: str, skill_dir: Path) -> SkillDecision:
    """LG-SC-03/09: refuse an unsigned/unvetted third-party skill.

    No-op (allowed) unless strict posture AND security.require_signed_skills.
    A skill without clean provenance is refused; the existing tool_policy AST +
    allowlist gate (P0.3) remains the complementary check.
    """
    if not (_is_strict() and _security_cfg().get("require_signed_skills")):
        return SkillDecision(allowed=True, skill=skill_name, reason="not enforced (low-side / flag off)")
    if _provenance_clean(skill_name, Path(skill_dir)):
        return SkillDecision(allowed=True, skill=skill_name, reason="clean provenance / attested")
    logger.warning("LG-SC-03: skill '%s' has no clean provenance — refused for execution", skill_name)
    return SkillDecision(allowed=False, skill=skill_name,
                         reason=(f"skill '{skill_name}' has no clean provenance/signature — unvetted "
                                 "third-party skills are refused (LG-SC-03/09)"))
