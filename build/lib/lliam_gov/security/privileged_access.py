"""Privileged-user gate for audit/key management CLIs (SP 800-171 3.3.9).

3.3.9 — "Limit management of audit logging functionality to a subset of
privileged users." The Lliam-GOV operator identity anchor is OWNERSHIP OF THE
LLIAM HOME: the home directory (and the audit chain, key-rotation state, and
credential store inside it) is created 0700, so its owning uid is the one
account the OS already trusts with that data. The gate denies any other
effective uid — including root, which does not own the home and gets no
special case (consistent with the LG-4.1 production root-refusal direction).

``LLIAM_GOV_PRIVILEGED_USERS`` (comma-separated usernames) optionally NARROWS
the set further — when set, the invoking username must also appear in the
list. It can never widen access: a listed user who does not own the home is
still denied.

Fail-closed posture: a missing home directory, an unreadable stat, or a
non-POSIX platform (no ``os.geteuid``) all deny rather than allow.

Denials are NOT written to the audit chain: a caller who fails this gate is
exactly the caller who must not be able to append to (or force errors into)
the chain. The denial goes to stderr at the CLI layer; granted operations are
evidenced by the commands' own audit events (``key_rotation`` etc.).

Maps to: SP 800-171 3.3.9; ISO/IEC 27001 A.8.2 (privileged access rights).
"""

from __future__ import annotations

import os

PRIVILEGED_USERS_ENV = "LLIAM_GOV_PRIVILEGED_USERS"


class PrivilegedAccessError(Exception):
    """The invoking user may not manage audit logging / key material."""


def _current_username(euid: int) -> str | None:
    try:
        import pwd

        return pwd.getpwuid(euid).pw_name
    except (ImportError, KeyError):
        return None


def require_privileged_user(operation: str) -> None:
    """Raise :class:`PrivilegedAccessError` unless the caller is privileged.

    Args:
        operation: Human-readable operation name for the denial message
            (e.g. ``"audit export-aep"``, ``"rotate-key"``).
    """
    if not hasattr(os, "geteuid"):
        raise PrivilegedAccessError(
            f"{operation} refused: privileged-user check is unsupported on "
            "this platform (no POSIX uid); fail-closed per SP 800-171 3.3.9."
        )

    from hermes_constants import get_hermes_home

    home = get_hermes_home()
    try:
        owner_uid = os.stat(home).st_uid
    except OSError as exc:
        raise PrivilegedAccessError(
            f"{operation} refused: cannot determine the Lliam home owner "
            f"({home}: {exc}); fail-closed per SP 800-171 3.3.9."
        ) from exc

    euid = os.geteuid()
    if euid != owner_uid:
        raise PrivilegedAccessError(
            f"{operation} refused: effective uid {euid} does not own the "
            f"Lliam home {home} (owner uid {owner_uid}). Audit and key "
            "management are limited to the operator account "
            "(SP 800-171 3.3.9)."
        )

    allowlist_raw = os.environ.get(PRIVILEGED_USERS_ENV, "").strip()
    if allowlist_raw:
        allowed = {u.strip() for u in allowlist_raw.split(",") if u.strip()}
        username = _current_username(euid)
        if username is None or username not in allowed:
            raise PrivilegedAccessError(
                f"{operation} refused: user {username or euid!r} is not in "
                f"{PRIVILEGED_USERS_ENV}. Audit and key management are "
                "limited to listed privileged users (SP 800-171 3.3.9)."
            )


__all__ = [
    "PRIVILEGED_USERS_ENV",
    "PrivilegedAccessError",
    "require_privileged_user",
]
