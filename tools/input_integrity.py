"""tools/input_integrity.py — Lliam-GOV input-integrity & path-safety gate.

ADDITIVE OVERLAY MODULE — no existing Hermes/Lliam module, file, CLI command,
tool name, or scanner identifier is renamed, moved, or refactored. (PATH-FREEZE.)

Realizes (the P0.5 hardening — "treat untrusted content as hostile"):
  * LG-PI-03 — validate/normalize tool/MCP JSON schemas before binding; REJECT
    malformed/oversized schemas (reject-on-fail) in the strict profile, instead of
    only sanitize-and-coerce. Wired additively right after the EXISTING
    tools/schema_sanitizer.sanitize_tool_schemas() call at model_tools.py:526.
  * LG-MC-01 — validate/sanitize content BEFORE it enters persistent memory using
    the EXISTING tools/threat_patterns strict scan; block/placeholder/log per policy.
  * LG-AZ-05 — expose the EXISTING tools/path_security path-traversal validation as
    the strict-profile enforcement point for file/skill/cron ops (no caller renamed).
  * LG-PI-01/02/05/07/08 — reads the input-trust policy and the overlay security.*
    keys that bind the always-on sanitizer (message_sanitization), the tirith
    fail-closed posture, the smart-approval guard hardening, and inbound screening.

Capability preservation:
  * Every gate is a NO-OP unless security.posture == strict. Low-side untouched.
  * Schema reject is conservative — only structurally invalid or oversized tool
    schemas are dropped (well-formed core tools always pass). It NEVER rejects a
    tool merely for being third-party; it rejects only objective malformation.
  * Memory scanning defaults to the policy mode; a benign note that merely quotes
    injection-like text can be set to placeholder/log rather than block.

Never raises into the host path: a policy/scan fault logs and falls back to the
shipped behavior (sanitize-and-coerce) rather than dropping legitimate tools.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hermes.governance.input_integrity")

_POLICY_FILENAME = "input-trust-policy.yaml"
_DEFAULT_MAX_SCHEMA_BYTES = 65536

_POLICY_CACHE: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}
_SCHEMA_REJECT_LOGGED: set = set()


# --------------------------------------------------------------------------- #
# Posture + config/policy resolution
# --------------------------------------------------------------------------- #

def _is_strict() -> bool:
    try:
        from hermes_cli import config as _cfg
        from hermes_cli import posture_resolver as _pr
        return _pr.is_strict(_cfg.load_config())
    except Exception:
        return False


def _security_cfg() -> Dict[str, Any]:
    try:
        from hermes_cli import config as _cfg
        return (_cfg.load_config().get("security") or {})
    except Exception:
        return {}


def _candidate_policy_paths() -> List[Path]:
    paths: List[Path] = []
    env = os.environ.get("HERMES_INPUT_POLICY")
    if env and env.strip():
        paths.append(Path(env).expanduser())
    home = os.environ.get("HERMES_HOME")
    if home:
        paths.append(Path(home).expanduser() / "policy" / _POLICY_FILENAME)
    overlay = os.environ.get("HERMES_CONFIG")
    if overlay:
        paths.append(Path(overlay).expanduser().parent / "policy" / _POLICY_FILENAME)
    paths.append(Path(__file__).resolve().parent.parent / "policy" / _POLICY_FILENAME)
    return paths


def load_input_policy() -> Dict[str, Any]:
    """Parse policy/input-trust-policy.yaml (cached on mtime). {} if absent."""
    for path in _candidate_policy_paths():
        try:
            if not path.is_file():
                continue
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
            continue
    return {}


# --------------------------------------------------------------------------- #
# LG-PI-03 — tool/MCP schema validation (reject-on-fail)
# --------------------------------------------------------------------------- #

def schema_validation_cfg() -> Tuple[str, int]:
    """Return (mode, max_schema_bytes). mode ∈ {reject, coerce}."""
    sv = _security_cfg().get("schema_validation") or {}
    mode = str(sv.get("mode") or "coerce").strip().lower()
    try:
        max_bytes = int(sv.get("max_schema_bytes") or _DEFAULT_MAX_SCHEMA_BYTES)
    except (TypeError, ValueError):
        max_bytes = _DEFAULT_MAX_SCHEMA_BYTES
    return mode, max_bytes


def _tool_schema_defect(tool: Any, max_bytes: int) -> Optional[str]:
    """Return a defect reason if the (already-sanitized) tool schema is malformed,
    else None. Conservative — only objective structural/size faults."""
    if not isinstance(tool, dict):
        return "tool entry is not an object"
    fn = tool.get("function")
    if not isinstance(fn, dict):
        return "missing 'function' object"
    name = fn.get("name")
    if not isinstance(name, str) or not name.strip():
        return "missing/empty function name"
    params = fn.get("parameters")
    if params is not None and not isinstance(params, dict):
        return "'parameters' is not an object"
    try:
        size = len(json.dumps(fn, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return "schema is not JSON-serializable"
    if size > max_bytes:
        return f"schema too large ({size} > {max_bytes} bytes)"
    return None


def validate_tool_schemas(tools: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str]]]:
    """LG-PI-03: reject malformed/oversized tool schemas before binding.

    Returns (kept_tools, rejected) where rejected is [(tool_name, reason)].
    No-op (returns tools unchanged, rejected=[]) unless strict posture AND
    schema_validation.mode == reject. Never raises.
    """
    if not tools:
        return tools, []
    try:
        if not _is_strict():
            return tools, []
        mode, max_bytes = schema_validation_cfg()
        if mode != "reject":
            return tools, []
        kept: List[Dict[str, Any]] = []
        rejected: List[Tuple[str, str]] = []
        for tool in tools:
            defect = _tool_schema_defect(tool, max_bytes)
            if defect is None:
                kept.append(tool)
                continue
            try:
                nm = str((tool.get("function") or {}).get("name") or "<unnamed>")
            except Exception:
                nm = "<unparseable>"
            rejected.append((nm, defect))
            sig = f"{nm}:{defect}"
            if sig not in _SCHEMA_REJECT_LOGGED:
                _SCHEMA_REJECT_LOGGED.add(sig)
                logger.warning(
                    "LG-PI-03: REJECTED tool schema '%s' before binding — %s "
                    "(reject mode, strict posture)", nm, defect)
        if rejected:
            logger.info("LG-PI-03 schema validation: %d kept, %d rejected.",
                        len(kept), len(rejected))
        return kept, rejected
    except Exception:  # pragma: no cover - never brick the model call
        logger.warning("input_integrity.validate_tool_schemas failed; "
                       "leaving schemas as sanitized", exc_info=True)
        return tools, []


# --------------------------------------------------------------------------- #
# LG-MC-01 — memory-poisoning defense (scan before persistent write)
# --------------------------------------------------------------------------- #

def memory_defense_cfg() -> Tuple[bool, str, str]:
    """Return (enabled, mode, scope). mode ∈ {block, placeholder, log}."""
    mc = _security_cfg().get("memory_poisoning_defense") or {}
    enabled = bool(mc.get("enabled"))
    mode = str(mc.get("mode") or "log").strip().lower()
    scope = str(mc.get("scope") or "strict").strip().lower()
    return enabled, mode, scope


def scan_memory_content(text: str) -> Dict[str, Any]:
    """LG-MC-01: scan content destined for persistent memory using the EXISTING
    strict threat scan. Returns {decision, mode, matched}.

    decision ∈ {allow, block, placeholder, log}. No-op (allow) unless strict
    posture AND memory_poisoning_defense.enabled.
    """
    result = {"decision": "allow", "mode": None, "matched": None}
    try:
        if not text or not _is_strict():
            return result
        enabled, mode, scope = memory_defense_cfg()
        if not enabled:
            return result
        from tools.threat_patterns import first_threat_message
        matched = first_threat_message(text, scope=scope or "strict")
        result["mode"] = mode
        if matched:
            result["matched"] = matched
            result["decision"] = mode if mode in {"block", "placeholder", "log"} else "block"
            logger.warning("LG-MC-01: memory-poisoning pattern on write — %s "
                           "(mode=%s)", matched, mode)
    except Exception:  # pragma: no cover
        logger.warning("input_integrity.scan_memory_content failed; allowing", exc_info=True)
    return result


# --------------------------------------------------------------------------- #
# LG-AZ-05 — path-traversal validation (existing path_security, strict profile)
# --------------------------------------------------------------------------- #

def path_traversal_enabled() -> bool:
    if not _is_strict():
        return False
    ptv = _security_cfg().get("path_traversal_validation") or {}
    # default ON under strict even if the key is absent (fail-safe direction)
    return bool(ptv.get("enabled", True))


def validate_path_within(path: str, root: str) -> Optional[str]:
    """LG-AZ-05: thin wrapper over the EXISTING tools/path_security mechanism.
    Returns an error string if *path* escapes *root*, else None."""
    try:
        from tools.path_security import validate_within_dir, has_traversal_component
        if has_traversal_component(str(path)):
            # still resolve to be sure (a '..' may be benign after resolution)
            pass
        return validate_within_dir(Path(path), Path(root))
    except Exception as e:  # pragma: no cover
        return f"path validation error: {e}"
