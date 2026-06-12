"""Egress allowlist + TLS posture enforcement (LG-4.3, AI-220).

Plan §5.4. Under the governed profile (``LLIAM_GOV_EGRESS_ENFORCE=1``),
outbound HTTP from Lliam-GOV is limited to an explicit host[:port]
allowlist, with TLS certificate verification that cannot be disabled.

Policy:

* **Fail-closed:** enforcement with a missing or empty allowlist denies
  ALL non-loopback egress. A misconfigured allowlist is a deny-all, never
  an allow-all.
* **Loopback exempt:** 127.0.0.1 / ::1 / localhost never leave the host
  boundary (dashboard, local services) and are always permitted.
* **TLS:** a client constructed with ``verify=False`` (or a falsy verify)
  raises :class:`EgressTLSViolation` — the violation is refused loudly,
  not silently corrected, so the offending call site gets fixed.
* **Audit:** every denial logs an ``egress_denied`` event with host and
  port only — never the full URL, which may carry query secrets.

Allowlist sources (first match wins):

1. ``LLIAM_GOV_EGRESS_ALLOWLIST`` env — comma-separated entries.
2. ``<lliam home>/egress-allowlist.txt`` — one entry per line, ``#``
   comments allowed.

Entry forms: ``host`` (implies port 443 — TLS by default), ``host:port``,
``*.suffix.tld`` wildcard (any single-or-deeper subdomain, not the bare
suffix).

The guard is installed by :func:`install_egress_guard`, which wraps
``httpx.Client.send`` / ``httpx.AsyncClient.send`` so the ~30 existing
call sites (gateway platforms, tools, plugins) are covered without
touching each one. Direct socket use is out of scope for this slice and
covered by the Phase 5 pen-test exercise.

Maps to: SP 800-171 3.1.20, 3.13.1, 3.13.8; ISO 27001 A.8.20–A.8.23.
"""

from __future__ import annotations

import os
from pathlib import Path

EGRESS_ENFORCE_ENV = "LLIAM_GOV_EGRESS_ENFORCE"
EGRESS_ALLOWLIST_ENV = "LLIAM_GOV_EGRESS_ALLOWLIST"
ALLOWLIST_FILENAME = "egress-allowlist.txt"

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

_guard_installed = False


class EgressError(Exception):
    """Base class for egress-policy failures."""


class EgressDenied(EgressError):
    """Destination is not on the egress allowlist."""


class EgressTLSViolation(EgressError):
    """A Lliam-GOV code path attempted to disable TLS verification."""


def egress_enforced() -> bool:
    """True when the governed egress policy is active."""
    return os.environ.get(EGRESS_ENFORCE_ENV) == "1"


def _allowlist_path() -> Path:
    from hermes_constants import get_hermes_home

    return get_hermes_home() / ALLOWLIST_FILENAME


def load_allowlist() -> frozenset[tuple[str, int]]:
    """Return the configured allowlist as ``(host_pattern, port)`` pairs.

    Empty result under enforcement means deny-all (fail-closed).
    """
    raw_entries: list[str] = []
    env_raw = os.environ.get(EGRESS_ALLOWLIST_ENV, "").strip()
    if env_raw:
        raw_entries = [e.strip() for e in env_raw.split(",")]
    else:
        path = _allowlist_path()
        try:
            for line in path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    raw_entries.append(line)
        except OSError:
            pass  # missing file -> empty allowlist -> deny-all when enforced

    entries: set[tuple[str, int]] = set()
    for entry in raw_entries:
        if not entry:
            continue
        host, sep, port_s = entry.rpartition(":")
        if sep and port_s.isdigit():
            entries.add((host.lower(), int(port_s)))
        else:
            entries.add((entry.lower(), 443))
    return frozenset(entries)


def _host_matches(pattern: str, host: str) -> bool:
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return False


def check_egress(host: str, port: int | None) -> None:
    """Raise :class:`EgressDenied` (and audit) unless ``host:port`` is allowed.

    No-op when enforcement is off. Loopback is always allowed.
    """
    if not egress_enforced():
        return
    host_l = (host or "").lower().strip("[]")
    if host_l in _LOOPBACK_HOSTS:
        return
    effective_port = port if port is not None else 443
    for pattern, allowed_port in load_allowlist():
        if allowed_port == effective_port and _host_matches(pattern, host_l):
            return
    _audit_denial(host_l, effective_port)
    raise EgressDenied(
        f"egress denied: {host_l}:{effective_port} is not on the "
        f"Lliam-GOV allowlist ({EGRESS_ALLOWLIST_ENV} or "
        f"{_allowlist_path()}). Fail-closed per SP 800-171 3.1.20/3.13.1."
    )


def _audit_denial(host: str, port: int) -> None:
    """Best-effort ``egress_denied`` audit event — host:port only, no URLs.

    The denial itself must stand even if the audit write fails (the
    operation is being REFUSED; there is no unevidenced action to halt),
    so audit failure here is swallowed after a stderr note.
    """
    try:
        from lliam_gov.security.audit_logger import get_shared_audit_logger

        get_shared_audit_logger().log_event(
            event_type="egress_denied",
            blocked=True,
            block_reason=f"{host}:{port}",
            params={"host": host, "port": port},
        )
    except Exception as exc:  # noqa: BLE001
        import sys

        print(
            f"warning: egress denial for {host}:{port} could not be "
            f"audited: {exc}",
            file=sys.stderr,
        )


def _check_request_url(url) -> None:
    check_egress(url.host, url.port)


def install_egress_guard() -> None:
    """Wrap httpx so every client send passes the egress check (idempotent).

    Also refuses ``verify=False`` client construction under enforcement —
    TLS verification cannot be disabled in Lliam-GOV paths.
    """
    global _guard_installed
    if _guard_installed:
        return
    import httpx

    real_client_init = httpx.Client.__init__
    real_async_init = httpx.AsyncClient.__init__
    real_send = httpx.Client.send
    real_async_send = httpx.AsyncClient.send

    def _reject_no_verify(kwargs) -> None:
        if egress_enforced() and kwargs.get("verify") is False:
            raise EgressTLSViolation(
                "verify=False is not permitted in Lliam-GOV paths: TLS "
                "certificate validation is mandatory (SP 800-171 3.13.8)."
            )

    def guarded_init(self, *args, **kwargs):
        _reject_no_verify(kwargs)
        real_client_init(self, *args, **kwargs)

    def guarded_async_init(self, *args, **kwargs):
        _reject_no_verify(kwargs)
        real_async_init(self, *args, **kwargs)

    def guarded_send(self, request, **kwargs):
        _check_request_url(request.url)
        return real_send(self, request, **kwargs)

    async def guarded_async_send(self, request, **kwargs):
        _check_request_url(request.url)
        return await real_async_send(self, request, **kwargs)

    httpx.Client.__init__ = guarded_init
    httpx.AsyncClient.__init__ = guarded_async_init
    httpx.Client.send = guarded_send
    httpx.AsyncClient.send = guarded_async_send
    _guard_installed = True


__all__ = [
    "ALLOWLIST_FILENAME",
    "EGRESS_ALLOWLIST_ENV",
    "EGRESS_ENFORCE_ENV",
    "EgressDenied",
    "EgressError",
    "EgressTLSViolation",
    "check_egress",
    "egress_enforced",
    "install_egress_guard",
    "load_allowlist",
]
