"""Agent NPE (non-person entity) instance identity (LG-IA-02, P1.4).

NEW ADDITIVE module (PATH-FREEZE honored): binds each agent runtime instance
to a distinct, reproducible identity derived from what actually governs its
behavior — its code, its resolved config/posture, its resolved tool/skill
manifest, and its serving model. A changed model, a flipped guardrail, or a
swapped skill yields a DIFFERENT ``instance_id``, which is itself recorded
(via the audit ledger's ``actor`` field and a ``config.load`` / ``agent.
lifecycle`` event) — so every audit record is attributable to a specific
*code + config + toolset + model* binding, not merely "the agent".

    instance_id = sha256( code_hash · config_hash · toolset_hash · model_hash )

Each input is best-effort and independently fail-safe: an input that cannot
be resolved contributes a stable ``"unknown:<name>"`` marker rather than
raising, so identity derivation never breaks a run (LG-IA-02 is
Detective/Directive — it labels, it does not gate). The result is cached per
(provider, model) for the process.

Config record: ``docs/governance/agent_identity.yaml`` documents the binding
inputs, the algorithm, and the review-by date (the assessor evidence for
LG-IA-02).

Privacy: ``config_hash`` is computed over the canonical config with
PATTERN-MATCHING secrets redacted via the Phase-0 force-path (40+ vendor key
prefixes, auth headers, JWTs, connstrings). Only the one-way digest is ever
persisted — never a config value — so no credential is embedded. Residual
(same class as the P1.1 ``content_hash``, deferred to HMAC in the remediation
pass): a CUSTOM low-entropy secret that matches no redaction pattern is
hashed into the whole-config digest; recovering it would require brute-forcing
against the entire rest of the config, strictly weaker than a per-value oracle.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger(__name__)

IDENTITY_SCHEMA = "lg-ia/1"

# Governance-CORE source files whose bytes define "the code" for identity
# purposes. A change to any flips code_hash (and thus instance_id), so a
# modified governance-core module is a DIFFERENT instance. This is a CHANGE
# SIGNAL over the governance core — NOT whole-tree code integrity: the agent
# cannot reach these files to tamper them (agent/file_safety.py write-deny +
# the CI path-freeze/governance gates are the actual tamper-EVIDENCE controls;
# see docs/governance/agent_identity.yaml). Deliberately excludes churny non-
# governance files (model_tools.py, config.py) so ordinary product edits don't
# reset every agent's identity, which would make the signal useless.
_CODE_SURFACE = (
    "agent/governance_audit.py",
    "agent/governance_audit_hooks.py",
    "agent/agent_identity.py",
    "agent/secret_scope.py",
    "agent/file_safety.py",
    "agent/redact.py",            # LG-AU-05/DP-03 redaction boundary
    "agent/tool_guardrails.py",   # ToolGuardrailDecision — the block seam
    "tools/tool_policy.py",       # LG-SC/AZ tool + skill policy gate
    "tools/input_integrity.py",   # LG-PI input-integrity gate
    "lliam_cli/posture_resolver.py",
    "lliam_cli/security_audit_startup.py",
)

_lock = threading.Lock()
# code_hash is process-stable (source can't change mid-run); memoized once.
_code_hash_memo: Optional[str] = None
# toolset_hash is EXPENSIVE (~100ms — get_tool_definitions); memoized on a cheap
# key of (registry generation, enabled scope, disabled scope) so a tool/skill or
# MCP change invalidates it but the hot path does not recompute per dispatch.
_toolset_memo: dict[tuple, str] = {}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _hash_bytes(*chunks: bytes) -> str:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
        h.update(b"\x00")  # domain separator between fields
    return h.hexdigest()


def _code_hash() -> str:
    global _code_hash_memo
    if _code_hash_memo is not None:
        return _code_hash_memo
    root = _repo_root()
    h = hashlib.sha256()
    for rel in _CODE_SURFACE:
        try:
            h.update(rel.encode("utf-8"))
            h.update((root / rel).read_bytes())
            h.update(b"\x00")
        except Exception:
            h.update(f"unknown:{rel}".encode("utf-8"))
            h.update(b"\x00")
    _code_hash_memo = h.hexdigest()
    return _code_hash_memo


def _config_hash(config: Optional[dict]) -> str:
    """sha256 of the REDACTED canonical config (secrets stripped)."""
    try:
        if config is None:
            from lliam_cli import config as _cfg
            config = _cfg.load_config()
        from agent.governance_audit import _redact_value, _jsonify

        redacted = _redact_value(_jsonify(config))
        canon = json.dumps(
            redacted, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(canon).hexdigest()
    except Exception as e:
        _log.debug("config_hash unavailable: %s", e)
        return "unknown:config"


def _scope_key(scope: Any) -> Any:
    if scope is None:
        return None
    try:
        return tuple(sorted(scope))
    except Exception:
        return str(scope)


def _registry_generation() -> int:
    try:
        from tools.registry import registry as _registry
        return int(getattr(_registry, "_generation", 0))
    except Exception:
        return 0


def _toolset_hash(agent: Any = None, *, enabled: Any = None, disabled: Any = None) -> str:
    """sha256 over the sorted resolved tool/skill name manifest for a scope.

    Memoized on (registry generation, enabled scope, disabled scope) — the
    call is ~100ms (``get_tool_definitions``), so the per-dispatch hot path
    must not recompute it, but a tool/skill/MCP change bumps the registry
    generation and invalidates the memo (so a swapped skill DOES flip the
    hash — the staleness the P1.4 review flagged).
    """
    if enabled is None and disabled is None and agent is not None:
        enabled = getattr(agent, "enabled_toolsets", None)
        disabled = getattr(agent, "disabled_toolsets", None)
    memo_key = (_registry_generation(), _scope_key(enabled), _scope_key(disabled))
    with _lock:
        cached = _toolset_memo.get(memo_key)
    if cached is not None:
        return cached
    try:
        import model_tools

        defs = model_tools.get_tool_definitions(
            enabled_toolsets=enabled,
            disabled_toolsets=disabled,
            quiet_mode=True,
        ) or []
        names = sorted(
            d["function"]["name"]
            for d in defs
            if isinstance(d, dict) and "function" in d
        )
    except Exception as e:
        _log.debug("toolset manifest unavailable: %s", e)
        return "unknown:toolset"
    manifest = json.dumps(names, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(manifest).hexdigest()
    with _lock:
        _toolset_memo[memo_key] = digest
    return digest


def _model_manifest(agent: Any = None, *, provider: Optional[str] = None,
                    model: Optional[str] = None) -> dict:
    if agent is not None:
        provider = provider or (getattr(agent, "provider", None) or None)
        model = model or (getattr(agent, "model", None) or None)
    model_hash = hashlib.sha256(
        f"{provider}|{model}".encode("utf-8")
    ).hexdigest()
    return {"provider": provider, "model": model, "model_hash": f"sha256:{model_hash}"}


def compute_instance_identity(
    agent: Any = None,
    *,
    config: Optional[dict] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    enabled_toolsets: Any = None,
    disabled_toolsets: Any = None,
    use_cache: bool = True,
) -> dict:
    """Return the agent NPE identity record for the current binding (LG-IA-02).

    Shape (all hashes hex, sha256-prefixed where they name a digest):

        {
          "schema": "lg-ia/1",
          "type": "npe",
          "instance_id": "sha256:…",
          "code_hash": "sha256:…",
          "config_hash": "sha256:…",
          "toolset_hash": "sha256:…",
          "model": {"provider": …, "model": …, "model_hash": "sha256:…"},
        }

    Freshness: ``code_hash`` is process-stable (memoized once), ``toolset_hash``
    is memoized on the tool-registry generation (a swapped skill/MCP flips it),
    and ``config_hash`` is recomputed every call — so a mid-process config or
    toolset change is reflected in a NEW ``instance_id`` (the P1.4-review cache-
    staleness fix). ``use_cache`` gates only the expensive toolset memo.
    """
    if agent is not None:
        provider = provider if provider is not None else getattr(agent, "provider", None)
        model = model if model is not None else getattr(agent, "model", None)
        if enabled_toolsets is None:
            enabled_toolsets = getattr(agent, "enabled_toolsets", None)
        if disabled_toolsets is None:
            disabled_toolsets = getattr(agent, "disabled_toolsets", None)

    code = _code_hash()
    cfg = _config_hash(config)
    if use_cache:
        tools = _toolset_hash(enabled=enabled_toolsets, disabled=disabled_toolsets)
    else:
        # Bypass the memo for a fully-fresh compute (tests / differentiation).
        tools = _toolset_hash_uncached(enabled_toolsets, disabled_toolsets)
    model_manifest = _model_manifest(agent, provider=provider, model=model)
    instance = _hash_bytes(
        code.encode(), cfg.encode(), tools.encode(),
        model_manifest["model_hash"].encode(),
    )
    return {
        "schema": IDENTITY_SCHEMA,
        "type": "npe",
        "instance_id": f"sha256:{instance}",
        "code_hash": f"sha256:{code}",
        "config_hash": f"sha256:{cfg}",
        "toolset_hash": f"sha256:{tools}",
        "model": model_manifest,
    }


def _toolset_hash_uncached(enabled: Any, disabled: Any) -> str:
    try:
        import model_tools

        defs = model_tools.get_tool_definitions(
            enabled_toolsets=enabled, disabled_toolsets=disabled, quiet_mode=True,
        ) or []
        names = sorted(
            d["function"]["name"] for d in defs
            if isinstance(d, dict) and "function" in d
        )
    except Exception:
        return "unknown:toolset"
    return hashlib.sha256(
        json.dumps(names, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def reset_identity_cache() -> None:
    """Clear the per-process identity memos (tests / post-config-reload)."""
    global _code_hash_memo
    with _lock:
        _toolset_memo.clear()
        _code_hash_memo = None
