"""Runtime guard — workspace, umask, Keychain, and FIPS posture (LG-4.4).

Plan §5.5. Phase 3 shipped the FIPS hard gate; Phase 4 (AI-221) completes
the operator-facing guard:

* ``workspace_check`` — the Lliam home must be owned by the invoking
  principal and not group/world accessible (mode 0700). Fail-closed.
* ``umask_check`` — enforces ``umask 0077`` at startup so every file the
  runtime creates outside the hardened writers is still private.
* ``keychain_check`` — probes that key material is reachable (Keychain
  readable + KeyManager init) before production tool dispatch.
* ``sync_path_warning`` — warns (does not fail) when the home sits under
  a cloud-sync directory (iCloud/Dropbox/OneDrive/Google Drive), which
  would replicate ciphertext + audit chains off the governed host.
* ``production_posture_check`` — composite startup gate for the
  production profile: principal/root refusal, FIPS, encrypt-state,
  workspace, umask, Keychain.

Maps to: SP 800-171 3.1.1/3.4.6/3.13.16; ISO 27001 A.8.2/A.8.20.
"""

from __future__ import annotations

import os


class RuntimeGuardError(Exception):
    """Raised when a runtime probe fails closed."""


class FipsNotAvailable(RuntimeGuardError):
    """The OpenSSL backend in use is not FIPS-validated.

    Per plan §5.1 / §11.6 this is a hard requirement for any DoD/CUI use
    of Lliam-GOV. Operators provision a FIPS-mode OpenSSL per the
    Phase 4 install guide; until then the override below lets the suite
    and pre-deployment development run without a real FIPS build.
    """


#: Environment override for development hosts that lack a FIPS-OpenSSL
#: build. **Never set this on the production Katmai MacBook.** When set
#: to ``"1"`` :func:`fips_check` returns without raising; otherwise the
#: function fails closed on a non-FIPS backend.
DEV_OVERRIDE_ENV = "LLIAM_GOV_ALLOW_NON_FIPS"


def fips_check() -> None:
    """Probe the OpenSSL backend and fail closed on non-FIPS.

    Resolution order:

    1. If :data:`DEV_OVERRIDE_ENV` is ``"1"`` in the environment, return
       silently — development hosts opt in to running on a stock OpenSSL.
    2. Ask OpenSSL via the ``cryptography`` backend whether FIPS mode is
       enabled. Return on success.
    3. Otherwise raise :class:`FipsNotAvailable` — agent code that calls
       this at startup must propagate the failure so dispatch is refused.

    The full operator-facing guard (the workspace mode / umask / Keychain
    checks per §5.5) lands in Phase 4. This function is the minimum
    needed to satisfy §5.1's FIPS hard gate without sprawling Phase 3.
    """
    if os.environ.get(DEV_OVERRIDE_ENV) == "1":
        return

    try:
        # The cryptography package exposes the OpenSSL FIPS state via
        # the deprecated-but-still-supported backend object. We import
        # lazily so importing this module never imports OpenSSL.
        from cryptography.hazmat.backends.openssl.backend import backend
    except ImportError as exc:  # pragma: no cover — packaging regression
        raise FipsNotAvailable(
            f"cryptography OpenSSL backend not importable: {exc}"
        ) from exc

    fips_enabled = getattr(backend, "_fips_enabled", False)
    if not fips_enabled:
        raise FipsNotAvailable(
            "OpenSSL backend is not in FIPS mode. Provision a FIPS-validated "
            "OpenSSL per the Phase 4 install guide, or set "
            f"{DEV_OVERRIDE_ENV}=1 for a non-production host."
        )


class WorkspaceNotHardened(RuntimeGuardError):
    """The Lliam home is missing, not owned by the principal, or too open."""


class UmaskTooPermissive(RuntimeGuardError):
    """The process umask leaks group/world permissions."""


class KeychainUnavailable(RuntimeGuardError):
    """Key material is not reachable; protected operations must refuse."""


#: Directory-name fragments that indicate a cloud-synced location.
_SYNC_PATH_MARKERS = (
    "Mobile Documents",  # iCloud Drive
    "com~apple~CloudDocs",
    "Dropbox",
    "OneDrive",
    "Google Drive",
    "GoogleDrive",
)

_REQUIRED_UMASK = 0o077


def workspace_check(home: "os.PathLike[str] | str | None" = None) -> None:
    """Fail closed unless the Lliam home is owned by the caller, mode 0700.

    A group/world-accessible home exposes the audit chain, key-rotation
    state, and credential store metadata even when file contents are
    encrypted; a home owned by another uid breaks the 3.3.9 ACL anchor.
    """
    if not hasattr(os, "geteuid"):
        raise WorkspaceNotHardened(
            "workspace check unsupported on this platform (no POSIX uid); "
            "fail-closed."
        )
    from hermes_constants import get_hermes_home

    path = os.fspath(home) if home is not None else str(get_hermes_home())
    try:
        st = os.stat(path)
    except OSError as exc:
        raise WorkspaceNotHardened(
            f"Lliam home {path} is not statable: {exc}; fail-closed."
        ) from exc
    if st.st_uid != os.geteuid():
        raise WorkspaceNotHardened(
            f"Lliam home {path} is owned by uid {st.st_uid}, not the "
            f"invoking principal (uid {os.geteuid()})."
        )
    if st.st_mode & 0o077:
        raise WorkspaceNotHardened(
            f"Lliam home {path} mode {oct(st.st_mode & 0o777)} grants "
            "group/world access; required mode is 0700. "
            f"Fix: chmod 700 {path}"
        )


def umask_check(*, enforce: bool = True) -> int:
    """Verify (and by default enforce) ``umask 0077``.

    Returns the umask now in effect. With ``enforce=False`` a permissive
    umask raises instead of being corrected — used by posture probes that
    must report rather than mutate.
    """
    current = os.umask(_REQUIRED_UMASK)
    if (current & _REQUIRED_UMASK) == _REQUIRED_UMASK:
        # Already at least as strict; restore the caller's value.
        os.umask(current)
        return current
    if enforce:
        # OR with the existing mask: tighten group/world, never loosen
        # any owner bits the operator masked deliberately.
        tightened = current | _REQUIRED_UMASK
        os.umask(tightened)
        return tightened
    os.umask(current)
    raise UmaskTooPermissive(
        f"process umask {oct(current)} leaks group/world permissions; "
        "required umask is 0077."
    )


def keychain_check() -> None:
    """Probe that key material is reachable before protected dispatch.

    Initializes (or reuses) the shared KeyManager and performs an
    encrypt/decrypt round-trip so a wedged Keychain fails here, at
    startup, instead of mid-operation.
    """
    try:
        from lliam_gov.security.encrypted_file import get_shared_key_manager

        km = get_shared_key_manager()
        if km.decrypt(km.encrypt(b"probe")) != b"probe":  # pragma: no cover
            raise KeychainUnavailable("key round-trip returned wrong bytes")
    except KeychainUnavailable:
        raise
    except Exception as exc:
        raise KeychainUnavailable(
            f"Keychain/key-manager probe failed: {exc}; protected "
            "operations must refuse (fail-closed)."
        ) from exc


def sync_path_warning(home: "os.PathLike[str] | str | None" = None) -> str | None:
    """Return a warning string when the home is under a cloud-sync path.

    Warning, not refusal: sync exposure is an operator decision, but it
    must be visible (audit chains and ciphertext replicating to a cloud
    provider leave the governed boundary).
    """
    from hermes_constants import get_hermes_home

    path = os.fspath(home) if home is not None else str(get_hermes_home())
    for marker in _SYNC_PATH_MARKERS:
        if marker in path:
            return (
                f"Lliam home {path} appears to be inside a cloud-synced "
                f"directory ({marker}); audit chains and ciphertext will "
                "replicate off this host."
            )
    return None


def production_posture_check() -> list[str]:
    """Composite startup gate for the governed production profile.

    Order matters: identity first (root refusal), then crypto posture,
    then filesystem posture. Raises the first hard failure; returns the
    list of non-fatal warnings (sync path) on success.
    """
    from lliam_gov.security.principal import require_principal
    from lliam_gov.security.state_codec import state_encryption_enabled

    require_principal()
    fips_check()
    if not state_encryption_enabled():
        raise RuntimeGuardError(
            "production posture requires LLIAM_GOV_ENCRYPT_STATE=1; "
            "persisted state would be plaintext at rest."
        )
    workspace_check()
    umask_check(enforce=True)
    keychain_check()
    warnings = []
    warning = sync_path_warning()
    if warning is not None:
        warnings.append(warning)
    return warnings


__all__ = [
    "fips_check",
    "FipsNotAvailable",
    "RuntimeGuardError",
    "DEV_OVERRIDE_ENV",
    "WorkspaceNotHardened",
    "UmaskTooPermissive",
    "KeychainUnavailable",
    "workspace_check",
    "umask_check",
    "keychain_check",
    "sync_path_warning",
    "production_posture_check",
]
