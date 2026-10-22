"""tools/egress_policy.py — Lliam-GOV deny-by-default egress allowlist (P2.5).

ADDITIVE OVERLAY MODULE (PATH-FREEZE). Layers destination-allowlist semantics
OVER the existing SSRF guard (tools/url_safety.py) and website policy
(tools/website_policy.py) for CUI egress. Realizes:

  * LG-NE-01 — deny-by-default egress: only hosts on the allowlist may be
    reached; everything else is denied (or routed to HITL as a new-domain add).
  * LG-NE-02 — unconditional SSRF/private-IP/metadata floor: reuses
    url_safety.is_always_blocked_url() as the runtime authority. NO allowlist
    entry and no toggle can override it (deny wins on conflict).
  * LG-NE-03 — website allow/deny in allowlist mode on web/browser tools,
    matched per-surface.
  * LG-NE-06 — air-gap / deny_all profile: all egress denied, local-only.

Consumes ``security.egress.*`` from the gov overlay + ``policy/egress-allowlist
.yaml`` (the policy of record). Complete no-op on low-side postures (the shipped
blocklist path is unchanged); on strict posture it is deny-by-default and
fail-closed. Never raises into the egress path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from lliam_cli.env_compat import getenv_compat

logger = logging.getLogger("hermes.governance.egress_policy")

_POLICY_FILENAME = "egress-allowlist.yaml"

# (mtime_ns, size, data) cache keyed on path.
_POLICY_CACHE: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}


@dataclass(frozen=True)
class EgressDecision:
    disposition: str          # allow | detect_log | hitl_approve | deny
    host: str = ""
    reason: str = ""


def reset_egress_cache() -> None:
    _POLICY_CACHE.clear()


def _strict_status() -> Tuple[bool, bool]:
    """Return ``(strict, config_error)`` so posture faults cannot fail open."""
    from lliam_cli import posture_resolver as _pr
    return _pr.strict_status()


def _is_strict() -> bool:
    strict, config_error = _strict_status()
    return strict or config_error


def _egress_cfg() -> Dict[str, Any]:
    try:
        from lliam_cli import config as _cfg
        sec = (_cfg.load_config().get("security") or {})
        block = sec.get("egress") or {}
        return block if isinstance(block, dict) else {}
    except Exception:
        return {}


def _candidate_policy_paths() -> List[Path]:
    paths: List[Path] = []
    configured = str(_egress_cfg().get("policy_path") or "").strip()
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
    for p in _candidate_policy_paths():
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
        logger.error("egress_policy: could not parse %s — failing closed", path, exc_info=True)
        return {"__load_error__": True}


def _host_matches(host: str, rule: str) -> bool:
    """Reuse website_policy host-match semantics (exact / parent / *. wildcard)."""
    try:
        from tools.website_policy import _match_host_against_rule
        return _match_host_against_rule(host, rule)
    except Exception:
        h, r = (host or "").lower().lstrip("."), (rule or "").lower().lstrip("*.").lstrip(".")
        return bool(r) and (h == r or h.endswith("." + r))


def _is_ip_literal(host: str) -> bool:
    import ipaddress
    h = (host or "").strip().strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _extract_host(url: str) -> str:
    try:
        from tools.website_policy import _extract_host_from_urlish
        return _extract_host_from_urlish(url) or ""
    except Exception:
        return ""


def check_egress(
    url: str,
    *,
    surface: str = "web",
    session_id: Optional[str] = None,
) -> EgressDecision:
    """Decide whether egress to ``url`` on ``surface`` is permitted.

    Order of authority:
      1. low-side posture → allow (no-op; shipped behavior).
      2. air-gap (egress.mode == deny_all) → deny without DNS/network work.
      3. SSRF/private/metadata floor (url_safety) → deny UNCONDITIONALLY.
      4. allowlisted host for this surface → allow.
      5. otherwise → new_domain_disposition (default deny; fail-closed).
    """
    strict, posture_error = _strict_status()
    if posture_error:
        return EgressDecision(
            disposition="deny",
            reason="security posture unavailable — egress failing closed",
        )
    if not strict:
        return EgressDecision(disposition="allow", reason="low-side (posture not strict)")

    host = _extract_host(url)
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()

    cfg = _egress_cfg()
    mode = str(cfg.get("mode") or "allowlist").strip().lower()
    if mode == "deny_all":
        return EgressDecision(
            disposition="deny", host=host,
            reason="air-gap profile: all egress denied (deny_all — LG-NE-06)",
        )

    # 2. Unconditional SSRF/private/metadata floor — code is the authority.
    #    is_always_blocked_url covers the metadata/link-local sentinel set
    #    (incl. hosts that RESOLVE to it). For a literal-IP host we also run
    #    the full is_safe_url check (catches private/loopback ranges without
    #    needing DNS). For ordinary hostnames we do NOT let a DNS-resolution
    #    failure preempt the allowlist decision here — the existing web-tool
    #    path's is_safe_url + the squid enclave enforce at connection time
    #    (LG-NE-05); this layer's job is the destination allowlist.
    try:
        from tools.url_safety import is_always_blocked_url, is_safe_url
        if is_always_blocked_url(url):
            return EgressDecision(
                disposition="deny", host=host,
                reason="metadata/link-local destination — unconditional block (LG-NE-02)",
            )
        if _is_ip_literal(host) and not is_safe_url(url):
            return EgressDecision(
                disposition="deny", host=host,
                reason="private/unsafe destination — unconditional block (LG-NE-02)",
            )
    except Exception:
        return EgressDecision(
            disposition="deny", host=host,
            reason="egress safety check unavailable — failing closed",
        )

    policy = _load_policy()
    if policy.get("__load_error__"):
        return EgressDecision(
            disposition="deny", host=host,
            reason="egress allowlist unparseable — failing closed",
        )

    # TLS is a property of the complete URL, not the host. Enforce the policy
    # record before host matching so an allowlisted domain cannot downgrade to
    # cleartext HTTP.
    unconditional = policy.get("unconditional_denies") or {}
    allowed_schemes = {
        str(item).strip().lower()
        for item in unconditional.get("allowed_schemes") or ["https"]
    }
    if scheme not in allowed_schemes:
        return EgressDecision(
            disposition="deny", host=host,
            reason=(
                f"URL scheme '{scheme or 'missing'}' is not permitted; "
                f"allowed schemes: {sorted(allowed_schemes)} (LG-DP-06)"
            ),
        )

    # 4. Allowlist match, scoped to the surface (LG-NE-01/03).
    for entry in policy.get("approved_destinations") or []:
        if not isinstance(entry, dict):
            continue
        rule = str(entry.get("host") or "").strip()
        if not rule or not _host_matches(host, rule):
            continue
        # Resolve allowlisted names too. Hostname approval must never override
        # the private-address/SSRF floor after DNS resolution.
        try:
            from tools.url_safety import is_safe_url
            if not is_safe_url(url):
                return EgressDecision(
                    disposition="deny", host=host,
                    reason="allowlisted host resolved to an unsafe destination (LG-NE-02)",
                )
        except Exception:
            return EgressDecision(
                disposition="deny", host=host,
                reason="egress DNS safety check unavailable — failing closed",
            )
        surfaces = entry.get("surfaces") or []
        if surface and surfaces and surface not in surfaces:
            return EgressDecision(
                disposition="deny", host=host,
                reason=(
                    f"host '{host}' is allowlisted but not for surface "
                    f"'{surface}' (allowed: {list(surfaces)}) — LG-NE-03"
                ),
            )
        ceiling = str(entry.get("classification_ceiling") or "PUBLIC").upper()
        try:
            from agent.data_protection import session_cui_tainted
            cui_tainted = session_cui_tainted(session_id=session_id)
        except Exception:
            return EgressDecision(
                disposition="deny", host=host,
                reason="classification state unavailable — egress failing closed",
            )
        if cui_tainted and not ceiling.startswith("CUI"):
            return EgressDecision(
                disposition="deny", host=host,
                reason=(
                    f"destination classification ceiling '{ceiling}' does not "
                    "permit CUI-tainted egress (LG-DP-10)"
                ),
            )
        return EgressDecision(
            disposition="allow", host=host,
            reason=f"host '{host}' on egress allowlist for surface '{surface}' (LG-NE-01)",
        )

    # 5. Not allowlisted → deny-by-default, or route a new domain to HITL.
    disp = str(cfg.get("new_domain_disposition") or "deny").strip().lower()
    if disp == "hitl_approve":
        return EgressDecision(
            disposition="hitl_approve", host=host,
            reason=(
                f"host '{host}' not on the egress allowlist — new-domain add "
                "routed to an approver (LG-NE-01)"
            ),
        )
    return EgressDecision(
        disposition="deny", host=host,
        reason=(
            f"host '{host}' not on the egress allowlist — deny-by-default, "
            "fail-closed (LG-NE-01)"
        ),
    )
