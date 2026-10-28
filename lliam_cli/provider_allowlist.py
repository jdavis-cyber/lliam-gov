"""lliam_cli/provider_allowlist.py — Lliam-GOV approved-provider allowlist (P3.1).

ADDITIVE OVERLAY MODULE (PATH-FREEZE). Enforces the CUI inference-provider
allowlist (policy/provider-allowlist.yaml) identically on EVERY routing path
that can egress CUI to a model — primary, fallback, MoA, auxiliary, delegation.
It renames nothing: the existing provider resolvers (runtime_provider.py,
fallback_config.py, moa_config.py, config.py auxiliary/delegation) invoke
``validate_provider`` at their resolution points.

Realizes:
  * LG-MP-01 — deny-by-default allowlist of vetted US / FedRAMP / local
    endpoints; fail-closed reject of everything else.
  * LG-MP-02 — the SAME validation on all five routing paths (no silent
    non-US route); matches both the provider slug AND the base_url host so a
    right-slug/wrong-endpoint route (e.g. bedrock → commercial us-east-1) is
    rejected.
  * LG-MP-03 — for CUI, require data_residency ∈ {us, local}, no_train, and
    TLS (reject plaintext base_urls).
  * LG-MP-04 — high-sensitivity clamps to local providers; an approved cloud
    provider routes to HITL (``approve``) rather than auto-allow.

Capability preservation: complete no-op unless strict posture AND
``security.provider_allowlist_enforce`` is true — low-side/dev routing is
untouched, and multi-provider routing WITHIN the allowlist stays fully
available. Never raises into the resolution path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lliam_cli.env_compat import getenv_compat

logger = logging.getLogger("hermes.governance.provider_allowlist")

_POLICY_FILENAME = "provider-allowlist.yaml"
_PATHS = ("primary", "fallback", "moa", "auxiliary", "delegation")

# (mtime_ns, size, data) cache keyed on path.
_POLICY_CACHE: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}


@dataclass(frozen=True)
class ProviderDecision:
    disposition: str          # allow | approve | deny
    provider: str = ""
    host: str = ""
    path: str = ""
    reason: str = ""


def reset_provider_allowlist_cache() -> None:
    _POLICY_CACHE.clear()


def _security_cfg() -> Dict[str, Any]:
    try:
        from lliam_cli import config as _cfg
        return _cfg.load_config().get("security") or {}
    except Exception:
        return {}


def enforcement_enabled(config: Optional[Dict[str, Any]] = None) -> bool:
    """Enforce strict + flag, or fail closed if config cannot be read."""
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr
        cfg = _cfg.load_config() if config is None else config
        return _pr.is_strict(cfg) and bool(
            (cfg.get("security") or {}).get("provider_allowlist_enforce")
        )
    except Exception:
        logger.warning("provider-allowlist configuration unavailable; enforcing", exc_info=True)
        return True


def _candidate_paths() -> List[Path]:
    paths: List[Path] = []
    configured = str(_security_cfg().get("provider_allowlist_path") or "").strip()
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
        logger.error("provider-allowlist: could not parse %s — failing closed", path, exc_info=True)
        return {"__load_error__": True}


def _host_of(base_url: str) -> str:
    try:
        from utils import base_url_hostname
        return base_url_hostname(base_url) or ""
    except Exception:
        return ""


def _find_provider(policy: Dict[str, Any], provider: str) -> Optional[Dict[str, Any]]:
    slug = (provider or "").strip().lower()
    for entry in policy.get("providers") or []:
        if isinstance(entry, dict) and str(entry.get("id") or "").strip().lower() == slug:
            return entry
    return None


def _path_enforced(policy: Dict[str, Any], path: str) -> bool:
    paths = ((policy.get("enforcement") or {}).get("paths")) or {}
    entry = paths.get(path)
    if not isinstance(entry, dict):
        return True   # unknown path → enforce (fail-safe)
    return bool(entry.get("enforce", True))


def validate_provider(
    provider: str,
    base_url: str,
    *,
    path: str = "primary",
    cui: bool = False,
    high_sensitivity: bool = False,
) -> ProviderDecision:
    """Validate a provider/base_url for a routing path (LG-MP-01..04).

    Low-side or enforcement disabled → allow (no-op). Strict + enforce:
    deny-by-default; the provider must be on the allowlist AND its base_url host
    must be an approved host for that provider; for CUI, residency/no_train/TLS
    are required; high-sensitivity clamps non-local approved providers to HITL.
    """
    try:
        from lliam_cli import config as _cfg
        config = _cfg.load_config()
    except Exception:
        return ProviderDecision(
            disposition="deny", provider=provider, path=path,
            reason="provider configuration unavailable — failing closed",
        )
    if not enforcement_enabled(config):
        return ProviderDecision(disposition="allow", provider=provider, path=path,
                                reason="enforcement disabled (low-side / flag off)")

    policy = _load_policy()
    if policy.get("__load_error__"):
        return ProviderDecision(disposition="deny", provider=provider, path=path,
                                reason="provider allowlist unparseable — failing closed")
    if not _path_enforced(policy, path):
        return ProviderDecision(disposition="allow", provider=provider, path=path,
                                reason=f"path '{path}' not enforced by policy")

    slug = (provider or "").strip().lower()
    if not slug:
        return ProviderDecision(disposition="deny", provider=provider, path=path,
                                reason="blank provider — fail-closed to an approved provider (LG-MP-02)")

    entry = _find_provider(policy, slug)
    if entry is None:
        return ProviderDecision(disposition="deny", provider=slug, path=path,
                                reason=f"provider '{slug}' not on the approved allowlist (LG-MP-01)")

    # Host match — closes the right-slug/wrong-endpoint bypass (LG-MP-02).
    host = _host_of(base_url)
    approved_hosts = [str(h).strip().lower() for h in (entry.get("base_url_hosts") or [])]
    if approved_hosts and not host:
        return ProviderDecision(disposition="deny", provider=slug, host=host, path=path,
                                reason=(f"blank or invalid base_url for provider '{slug}' — "
                                        "cannot verify approved endpoint (LG-MP-02)"))
    if approved_hosts and host not in approved_hosts:
        return ProviderDecision(disposition="deny", provider=slug, host=host, path=path,
                                reason=(f"base_url host '{host}' not approved for provider "
                                        f"'{slug}' (approved: {approved_hosts}) — LG-MP-02"))

    if cui:
        # LG-MP-01: the endpoint must be CUI-eligible.
        if not entry.get("cui_eligible", False):
            return ProviderDecision(disposition="deny", provider=slug, host=host, path=path,
                                    reason=f"provider '{slug}' is not CUI-eligible (LG-MP-01)")
        # LG-MP-03: residency + no_train + TLS.
        req = ((policy.get("enforcement") or {}).get("require_for_cui")) or {}
        residency = str(entry.get("data_residency") or "").strip().lower()
        allowed_residency = {"us", "local"}
        if req.get("data_residency") and residency not in allowed_residency:
            return ProviderDecision(disposition="deny", provider=slug, host=host, path=path,
                                    reason=f"data_residency '{residency}' not US/local for CUI (LG-MP-03)")
        if req.get("no_train") and not entry.get("no_train", False):
            return ProviderDecision(disposition="deny", provider=slug, host=host, path=path,
                                    reason=f"provider '{slug}' lacks no_train terms for CUI (LG-MP-03)")
        if req.get("tls_required", True) and residency != "local":
            if not (base_url or "").strip().lower().startswith("https://"):
                return ProviderDecision(disposition="deny", provider=slug, host=host, path=path,
                                        reason="CUI route requires TLS (https) base_url (LG-MP-03/DP-06)")

        # LG-MP-04: high-sensitivity clamp to local providers.
        if high_sensitivity:
            hs = ((policy.get("enforcement") or {}).get("high_sensitivity")) or {}
            if hs.get("local_only", True) and str(entry.get("provider_class") or "").lower() != "local":
                return ProviderDecision(disposition="approve", provider=slug, host=host, path=path,
                                        reason=("high-sensitivity CUI prefers local inference; approved "
                                                "cloud provider requires HITL (LG-MP-04)"))

    return ProviderDecision(disposition="allow", provider=slug, host=host, path=path,
                            reason=f"provider '{slug}' approved for path '{path}' (LG-MP-01/02)")
