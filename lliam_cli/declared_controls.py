"""Fail-closed checks for security controls the governance overlay declares.

``cli-config.gov.yaml`` turns on several ``security.*`` / ``delegation.*``
switches. Each one is enforced on its own runtime path:

* ``delegation.max_spawn_depth`` — ``tools/delegate_tool.py`` (in-process and,
  via ``agent/delegation_depth.py``, across spawned processes).
* ``security.cert_pinning`` — ``agent/ssl_guard.py`` (installed at agent init).
* ``security.require_mfa`` — the dashboard bind gate
  (``lliam_cli/web_server.start_server`` → :func:`dashboard_mfa_refusal`).
* ``security.device_auth`` — the ``computer_use`` handler
  (``tools/computer_use/tool.py`` → :func:`computer_use_device_refusal`).
* ``security.spend_ceiling`` — the model-call loop
  (``lliam_cli/model_cost_guard.py``).

This module holds the decisions that are not tied to one client, plus
:func:`enforce_declared_controls_at_startup`, a one-shot configuration check
that raises under strict posture when a declared control is configured in a
way that cannot be enforced.

NOTE: ``enforce_declared_controls_at_startup`` is not yet called from a
startup sequence. It should be added to ``enforce_startup_posture`` in
``lliam_cli/startup_posture.py`` once that module (PR #116) merges. Until
then each control still fails closed on its own runtime path.
"""

from __future__ import annotations

import logging
import socket
from typing import Any, Iterable, List, Optional

logger = logging.getLogger("hermes.governance.declared_controls")


class DeclaredControlError(RuntimeError):
    """A declared security control cannot be enforced under strict posture."""


def _load(config: Optional[dict]) -> dict:
    if isinstance(config, dict) and config:
        return config
    try:
        from lliam_cli.config import load_config

        return load_config()
    except Exception:
        return config or {}


def _is_strict(config: Optional[dict]) -> bool:
    try:
        from lliam_cli import posture_resolver as _pr

        return bool(_pr.is_strict(config))
    except Exception:
        return True


def _security(config: dict) -> dict:
    sec = config.get("security") if isinstance(config, dict) else None
    return sec if isinstance(sec, dict) else {}


# --------------------------------------------------------------------------- #
# security.require_mfa
# --------------------------------------------------------------------------- #

def dashboard_mfa_refusal(
    host: str,
    *,
    providers: Optional[Iterable[Any]] = None,
    config: Optional[dict] = None,
) -> Optional[str]:
    """Why a network-bound dashboard must not start without MFA, or None.

    Applies only under strict posture with ``security.require_mfa`` on, and
    only to session (interactive login) providers: every one of them must
    declare ``enforces_mfa``. A password-only or non-MFA OAuth provider would
    otherwise be a login path that skips the second factor. Token-only
    machine credentials (``supports_session = False``) are not operator
    logins and are not counted.
    """
    cfg = _load(config)
    if not (_is_strict(cfg) and _security(cfg).get("require_mfa")):
        return None
    if providers is None:
        from lliam_cli.dashboard_auth import list_session_providers

        providers = list_session_providers()
    session_providers = [p for p in providers if getattr(p, "supports_session", True)]
    weak = [
        str(getattr(p, "name", "") or type(p).__name__)
        for p in session_providers
        if getattr(p, "enforces_mfa", False) is not True
    ]
    if not weak:
        return None
    return (
        f"Refusing to bind dashboard to {host}: security.require_mfa is on under "
        f"strict posture, but these login providers do not enforce multi-factor "
        f"authentication: {', '.join(sorted(weak))}. Configure the self-hosted "
        f"OIDC provider against an MFA-enforcing identity provider "
        f"(dashboard.oauth.self_hosted; require_mfa is applied automatically "
        f"under strict posture) and remove the other login providers, or bind "
        f"to 127.0.0.1."
    )


# --------------------------------------------------------------------------- #
# security.device_auth
# --------------------------------------------------------------------------- #

def _host_identities() -> set:
    names = set()
    for fn in (socket.gethostname, socket.getfqdn):
        try:
            value = fn()
        except Exception:
            continue
        if value:
            names.add(str(value).strip().rstrip(".").lower())
    return names


def computer_use_device_refusal(
    config: Optional[dict] = None,
    *,
    hostnames: Optional[Iterable[str]] = None,
) -> Optional[str]:
    """Why ``computer_use`` must not drive this host, or None.

    Under strict posture desktop control runs only on a host listed in
    ``security.device_auth.computer_use_enrolled_hosts`` (matched against the
    host name and FQDN). An empty list — the shipped overlay — refuses every
    host. Low-side posture: always None.
    """
    cfg = _load(config)
    if not _is_strict(cfg):
        return None
    block = _security(cfg).get("device_auth")
    enrolled_raw = block.get("computer_use_enrolled_hosts") if isinstance(block, dict) else None
    if enrolled_raw is not None and not isinstance(enrolled_raw, (list, tuple)):
        return (
            "computer_use refused: security.device_auth.computer_use_enrolled_hosts "
            "must be a list of host names (failing closed under strict posture)."
        )
    enrolled = {
        str(h).strip().rstrip(".").lower() for h in (enrolled_raw or []) if str(h).strip()
    }
    names = (
        {str(h).strip().rstrip(".").lower() for h in hostnames if str(h).strip()}
        if hostnames is not None
        else _host_identities()
    )
    if enrolled and names & enrolled:
        return None
    shown = ", ".join(sorted(names)) or "unknown"
    return (
        f"computer_use refused: this host ({shown}) is not enrolled in "
        f"security.device_auth.computer_use_enrolled_hosts. Desktop control "
        f"under strict posture runs only on enrolled hosts."
    )


# --------------------------------------------------------------------------- #
# One-shot startup configuration check
# --------------------------------------------------------------------------- #

def declared_control_findings(config: Optional[dict] = None) -> List[str]:
    """Configuration problems that make a declared control unenforceable."""
    cfg = _load(config)
    findings: List[str] = []

    try:
        from agent.ssl_guard import CertPinningConfigError, load_pin_policy

        try:
            load_pin_policy(cfg)
        except CertPinningConfigError as exc:
            findings.append(str(exc))
    except Exception as exc:  # pragma: no cover - import failure
        findings.append(f"security.cert_pinning could not be evaluated: {exc}")

    deleg = cfg.get("delegation") if isinstance(cfg, dict) else None
    if isinstance(deleg, dict) and "max_spawn_depth" in deleg:
        val = deleg.get("max_spawn_depth")
        if isinstance(val, bool) or not isinstance(val, int) or val < 1:
            findings.append(
                f"delegation.max_spawn_depth={val!r} is not an integer >= 1"
            )

    try:
        from lliam_cli.model_cost_guard import SpendCeilingConfigError, load_spend_ceiling

        try:
            load_spend_ceiling(cfg)
        except SpendCeilingConfigError as exc:
            findings.append(str(exc))
    except Exception as exc:  # pragma: no cover - import failure
        findings.append(f"security.spend_ceiling could not be evaluated: {exc}")

    return findings


def enforce_declared_controls_at_startup(config: Optional[dict] = None) -> Optional[List[str]]:
    """Raise :class:`DeclaredControlError` under strict posture on any finding.

    Low-side posture: findings are logged and returned. Returns None when
    there is nothing to report. See the module NOTE about wiring this into
    ``enforce_startup_posture`` after PR #116.
    """
    cfg = _load(config)
    findings = declared_control_findings(cfg)
    if not findings:
        return None
    if _is_strict(cfg):
        for f in findings:
            logger.critical("[declared-controls] BLOCKING: %s", f)
        raise DeclaredControlError("; ".join(findings))
    for f in findings:
        logger.warning("[declared-controls] (advisory, not strict) %s", f)
    return findings


__all__ = [
    "DeclaredControlError",
    "computer_use_device_refusal",
    "dashboard_mfa_refusal",
    "declared_control_findings",
    "enforce_declared_controls_at_startup",
]
