"""Authenticated OS principal binding + production root refusal (LG-4.1, AI-218).

Plan §5.3/§5.5. Every audit event must be attributable to an AUTHENTICATED
principal — the account the operating system has already authenticated — not
to spoofable environment variables. On POSIX the principal is resolved from
the effective uid via the password database; ``USER``/``LOGNAME`` are used
only as a last-resort fallback on platforms without ``os.geteuid`` and are
marked as such in the ``method`` field so evidence reviewers can tell the
difference.

Production root refusal: under the governed production profile
(``LLIAM_GOV_PROFILE=production``) running as root fails closed with a
structured error. Root would bypass the home-ownership ACL semantics
(SP 800-171 3.3.9) and make every audit event attributable to an account
that any privileged process can assume — an attribution model auditors
reject. Development hosts are unaffected (refusal only in production).

Maps to: SP 800-171 3.1.1, 3.1.2; ISO/IEC 27001 A.8.5.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

PRODUCTION_PROFILE_ENV = "LLIAM_GOV_PROFILE"
PRODUCTION_PROFILE_VALUE = "production"


class PrincipalError(Exception):
    """Base class for principal-binding failures."""


class ProductionRootRefused(PrincipalError):
    """Lliam-GOV refuses to run as root under the production profile."""


@dataclass(frozen=True)
class Principal:
    """The authenticated OS principal bound to this process."""

    username: str
    uid: int | None
    method: str  # "os_euid" (authenticated) or "env_fallback" (non-POSIX)


def production_mode() -> bool:
    """True when the governed production profile is active."""
    return (
        os.environ.get(PRODUCTION_PROFILE_ENV, "").strip().lower()
        == PRODUCTION_PROFILE_VALUE
    )


def get_principal() -> Principal:
    """Resolve the current principal from the OS, not the environment.

    POSIX: effective uid → password database (authenticated identity).
    Non-POSIX fallback: ``USER``/``LOGNAME`` env, flagged ``env_fallback``.
    """
    if hasattr(os, "geteuid"):
        euid = os.geteuid()
        try:
            import pwd

            username = pwd.getpwuid(euid).pw_name
        except (ImportError, KeyError):
            username = f"uid:{euid}"
        return Principal(username=username, uid=euid, method="os_euid")
    username = os.getenv("USER") or os.getenv("LOGNAME") or "unknown"
    return Principal(username=username, uid=None, method="env_fallback")


def require_principal() -> Principal:
    """Return the bound principal, refusing root under production.

    Call at security choke points (shared audit logger, shared key manager)
    so no governed operation can run with an unattributable identity.
    """
    principal = get_principal()
    if production_mode() and principal.uid == 0:
        raise ProductionRootRefused(
            "Lliam-GOV refuses to run as root under LLIAM_GOV_PROFILE="
            "production: root execution breaks principal attribution and "
            "bypasses the home-ownership ACL (SP 800-171 3.1.1/3.1.2, "
            "3.3.9; ISO 27001 A.8.5). Run as the operator account."
        )
    return principal


__all__ = [
    "PRODUCTION_PROFILE_ENV",
    "PRODUCTION_PROFILE_VALUE",
    "Principal",
    "PrincipalError",
    "ProductionRootRefused",
    "get_principal",
    "production_mode",
    "require_principal",
]
