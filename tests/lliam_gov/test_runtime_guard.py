"""Tests for ``lliam_gov.security.runtime_guard.fips_check``.

Phase 3 stub of §5.5. Confirms the FIPS hard gate fails closed on a
stock OpenSSL build and that the documented dev override is honored.
"""

from __future__ import annotations

import pytest

from lliam_gov.security.runtime_guard import (
    DEV_OVERRIDE_ENV,
    FipsNotAvailable,
    fips_check,
)


def test_fips_check_fails_closed_on_stock_openssl(monkeypatch: pytest.MonkeyPatch) -> None:
    # The Mac Mini and Katmai dev hosts run stock OpenSSL — the probe
    # must refuse without the override.
    monkeypatch.delenv(DEV_OVERRIDE_ENV, raising=False)
    with pytest.raises(FipsNotAvailable):
        fips_check()


def test_dev_override_lets_check_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DEV_OVERRIDE_ENV, "1")
    fips_check()  # must not raise


def test_dev_override_other_values_still_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    # Defense-in-depth: only the literal "1" disables the gate so a
    # truthy-looking env value like "0" or "false" doesn't accidentally
    # open it.
    monkeypatch.setenv(DEV_OVERRIDE_ENV, "0")
    with pytest.raises(FipsNotAvailable):
        fips_check()


def test_fips_check_honors_simulated_fips_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulate a FIPS-mode OpenSSL by patching the backend's flag — this
    # is the path the Katmai MacBook will take after the Phase 4 install
    # guide provisions FIPS-OpenSSL.
    monkeypatch.delenv(DEV_OVERRIDE_ENV, raising=False)
    from cryptography.hazmat.backends.openssl.backend import backend

    monkeypatch.setattr(backend, "_fips_enabled", True, raising=False)
    fips_check()  # must not raise
