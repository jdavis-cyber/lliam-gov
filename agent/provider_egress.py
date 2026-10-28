"""agent/provider_egress.py — provider-surface egress gate for every inference transport.

One request-boundary check shared by the OpenAI-compatible client path
(``chat_completion_helpers._enforce_provider_egress``) and the transports that
do their own HTTP — Bedrock via boto3, Claude-on-Bedrock via the Anthropic SDK —
so no inference path that carries conversation data off the workstation skips
the app-layer allowlist.

Two checks, both evaluated before the network call:

  1. ``tools.egress_policy.check_egress(url, surface="provider")`` — the
     deny-by-default destination allowlist, SSRF floor and CUI-taint ceiling.
     Anything other than ``allow`` (deny, hitl_approve, detect_log) blocks the
     request; there is no approver loop at the provider boundary.
  2. Under strict posture with ``security.egress.proxy_required`` set, an
     allowed remote destination must also be routed through the egress proxy
     (``HTTPS_PROXY``, not bypassed by ``NO_PROXY``). Third-party SDKs are only
     connection-level enforced by the squid enclave; running them without it
     leaves the app-layer check as the sole control.

Low-side postures are a no-op (check_egress allows, the proxy rule needs strict).
"""

from __future__ import annotations

import urllib.request
from typing import Any, Optional
from urllib.parse import urlparse

_TRUTHY = {"1", "true", "yes", "on"}


def _strict_and_proxy_required() -> tuple[bool, bool]:
    """Return ``(strict, proxy_required)``; raise PermissionError if unknown."""
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr

        cfg = _cfg.load_config()
        strict = _pr.is_strict(cfg)
        sec = cfg.get("security") or {}
        egress = (sec.get("egress") or {}) if isinstance(sec, dict) else {}
        raw = egress.get("proxy_required", False) if isinstance(egress, dict) else False
    except Exception as exc:
        raise PermissionError(
            "Provider request blocked: security posture unavailable — egress failing closed"
        ) from exc
    required = raw is True or str(raw).strip().lower() in _TRUTHY
    return strict, required


def _routed_through_proxy(host: str) -> bool:
    """True when HTTPS traffic to ``host`` would use the environment proxy."""
    proxies = urllib.request.getproxies_environment()
    if not (proxies.get("https") or proxies.get("all")):
        return False
    try:
        return not urllib.request.proxy_bypass_environment(host, proxies)
    except Exception:
        return False


def enforce_provider_egress_url(url: str, *, session_id: Optional[str] = None) -> None:
    """Raise PermissionError unless a provider request to ``url`` may proceed.

    ``url`` must be the endpoint the transport will actually connect to. An
    empty/unknown URL is passed through to check_egress, which fails closed on
    strict posture (no scheme) and allows on low-side.
    """
    from tools.egress_policy import check_egress

    decision = check_egress(url or "", surface="provider", session_id=session_id)
    if decision.disposition != "allow":
        raise PermissionError(f"Provider request blocked by egress policy: {decision.reason}")

    strict, proxy_required = _strict_and_proxy_required()
    if not (strict and proxy_required):
        return
    host = decision.host or (urlparse(url or "").hostname or "")
    if not _routed_through_proxy(host):
        raise PermissionError(
            "Provider request blocked by egress policy: security.egress.proxy_required "
            f"is set but HTTPS_PROXY is unset or NO_PROXY bypasses '{host}' — the "
            "squid egress enclave is required for provider traffic (LG-NE-04/05)"
        )


def client_endpoint_url(client: Any) -> str:
    """Best-effort endpoint of an SDK client, or "" when it cannot be determined.

    boto3/botocore clients expose the resolved endpoint (region, FIPS,
    ``endpoint_url`` override, ``AWS_ENDPOINT_URL*``) as ``client.meta.endpoint_url``;
    Anthropic/OpenAI SDK clients expose ``client.base_url`` (an ``httpx.URL``).
    """
    meta = getattr(client, "meta", None)
    endpoint = getattr(meta, "endpoint_url", None) if meta is not None else None
    if isinstance(endpoint, str) and "://" in endpoint:
        return endpoint
    base = getattr(client, "base_url", None)
    url_types: tuple = (str,)
    try:
        import httpx

        url_types = (str, httpx.URL)
    except ImportError:  # pragma: no cover — httpx ships with the provider SDKs
        pass
    if isinstance(base, url_types) and "://" in str(base):
        return str(base)
    return ""


def enforce_client_egress(client: Any, *, session_id: Optional[str] = None) -> None:
    """Apply :func:`enforce_provider_egress_url` to the endpoint ``client`` will use."""
    enforce_provider_egress_url(client_endpoint_url(client), session_id=session_id)
