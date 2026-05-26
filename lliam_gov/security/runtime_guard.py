"""Runtime safety probes (Phase 3 stub — full guard lands in Phase 4).

Plan §5.5 specifies a full runtime guard (workspace mode 0700, umask
0077, Keychain probe, etc.); that's Phase 4 work per the control matrix.
Phase 3 only needs the §5.1 FIPS hard requirement satisfied — the rest
of the file is intentionally empty until then.
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


__all__ = ["fips_check", "FipsNotAvailable", "RuntimeGuardError", "DEV_OVERRIDE_ENV"]
