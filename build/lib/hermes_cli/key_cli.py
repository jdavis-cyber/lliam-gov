"""Key-management CLI for Lliam-GOV (``lliam-gov rotate-key``).

Plan §5.1, LG-3.8 / AI-216. Rotates the Keychain-anchored encryption key and
atomically re-encrypts the managed persisted-state files under the new key, then
records a ``key_rotation`` event in the §5.2 hash-chained audit log.

Runtime prerequisites are validated before any key material changes:

* The §5.1 FIPS hard gate (:func:`runtime_guard.fips_check`) — a non-FIPS
  production backend fails closed (dev opts out with ``LLIAM_GOV_ALLOW_NON_FIPS=1``).
* State encryption must be enabled (``LLIAM_GOV_ENCRYPT_STATE=1``) — re-keying a
  plaintext store is a no-op that would silently imply protection it doesn't
  provide, so the command refuses and tells the operator how to enable it.

Maps to: SP 800-171 3.5.10, 3.13.16 (key management for CUI-at-rest);
ISO/IEC 27001 A.8.24; ISO/IEC 42001 A.4.3.
"""

from __future__ import annotations

import argparse
import sys


def cmd_rotate_key(args: argparse.Namespace) -> int:
    """Dispatch ``lliam-gov rotate-key``."""
    from lliam_gov.security.audit_logger import (
        AuditLoggerError,
        get_shared_audit_logger,
    )
    from lliam_gov.security.encrypted_file import rekey_files
    from lliam_gov.security.runtime_guard import FipsNotAvailable, fips_check
    from lliam_gov.security.state_codec import (
        managed_state_paths,
        state_encryption_enabled,
    )

    # Prereq 0: privileged user (SP 800-171 3.3.9) — key rotation manages
    # the material protecting the audit chain, so the same ACL applies.
    from lliam_gov.security.privileged_access import (
        PrivilegedAccessError,
        require_privileged_user,
    )

    try:
        require_privileged_user("rotate-key")
    except PrivilegedAccessError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    # Prereq 1: FIPS backend (fail-closed on non-FIPS production host).
    try:
        fips_check()
    except FipsNotAvailable as exc:
        print(f"rotate-key refused: {exc}", file=sys.stderr)
        return 1

    # Prereq 2: encryption must be enabled, else there's nothing to re-key.
    if not state_encryption_enabled():
        print(
            "rotate-key refused: state encryption is disabled. Set "
            "LLIAM_GOV_ENCRYPT_STATE=1 (production profile) before rotating.",
            file=sys.stderr,
        )
        return 1

    paths = managed_state_paths()
    try:
        rekeyed = rekey_files(paths)
    except Exception as exc:  # noqa: BLE001 — surface any re-key failure to the operator
        print(f"rotate-key failed: {exc}", file=sys.stderr)
        return 1

    # Record the rotation in the tamper-evident audit chain. A rotation that
    # cannot be audited is reported as a non-zero partial success: the key WAS
    # rotated, but the evidence record is missing — the operator must know.
    try:
        get_shared_audit_logger().log_event(
            event_type="key_rotation",
            params={"rekeyed_count": len(rekeyed)},
        )
    except AuditLoggerError as exc:
        print(
            f"rotate-key: key rotated and {len(rekeyed)} file(s) re-encrypted, "
            f"but the audit record FAILED: {exc}",
            file=sys.stderr,
        )
        return 1

    plural = "" if len(rekeyed) == 1 else "s"
    print(f"Rotated encryption key; re-encrypted {len(rekeyed)} file{plural}.")
    return 0


def register_rotate_key_parser(subparsers) -> None:
    """Register the ``rotate-key`` command on the top-level subparsers."""
    parser = subparsers.add_parser(
        "rotate-key",
        help="Rotate the encryption key and re-encrypt managed state at rest",
        description=(
            "Generate fresh Keychain-anchored key material and atomically "
            "re-encrypt managed persisted-state files (credential store) under "
            "the new key. Records a key_rotation audit event. Requires a FIPS "
            "backend and LLIAM_GOV_ENCRYPT_STATE=1."
        ),
    )
    parser.set_defaults(func=cmd_rotate_key)


__all__ = ["cmd_rotate_key", "register_rotate_key_parser"]
