"""Preventive SSL CA certificate checks for Lliam-GOV.

This module catches broken CA bundle paths before OpenAI/httpx turns them into
opaque ``FileNotFoundError: [Errno 2] No such file or directory`` failures.
"""

from __future__ import annotations

import logging
import os
from lliam_cli.env_compat import getenv_compat
import ssl
from pathlib import Path

from agent.errors import SSLConfigurationError

logger = logging.getLogger(__name__)

_CA_BUNDLE_ENV_VARS = (
    "HERMES_CA_BUNDLE",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)

_SKIP_VALUES = {"1", "true", "yes", "on"}


def _skip_ssl_guard_enabled() -> bool:
    return getenv_compat("SKIP_SSL_GUARD", "").strip().lower() in _SKIP_VALUES


def _repair_hint() -> str:
    return (
        "Repair: python -m pip install --force-reinstall certifi openai httpx\n"
        "If you configured a custom corporate CA bundle, fix or unset the "
        "broken CA bundle environment variable."
    )


def _ssl_err(message: str) -> SSLConfigurationError:
    """Create a consistent, user-actionable SSL configuration error."""
    return SSLConfigurationError(f"{message}\n{_repair_hint()}")


def _validate_bundle_path(label: str, value: str, *, require_substantial: bool = False) -> None:
    path = Path(value).expanduser()
    if not path.exists():
        raise _ssl_err(f"{label} points to a missing CA bundle: {value}")
    if not path.is_file():
        raise _ssl_err(f"{label} does not point to a CA bundle file: {value}")
    if require_substantial and path.stat().st_size < 1024:
        raise _ssl_err(f"{label} at {value} appears corrupted (too small)")
    try:
        ctx = ssl.create_default_context(cafile=str(path))
    except Exception as exc:
        raise _ssl_err(f"{label} CA bundle at {value} cannot be loaded: {exc}") from exc
    if not ctx.get_ca_certs():
        raise _ssl_err(f"{label} CA bundle at {value} did not load any certificates")


def verify_ca_bundle() -> None:
    """Verify configured and bundled CA certificates are present and loadable.

    Raises:
        SSLConfigurationError: If an explicit CA-bundle environment variable
            points at a bad path, or if certifi's bundled ``cacert.pem`` is
            missing/corrupt.
    """
    if _skip_ssl_guard_enabled():
        logger.debug("SSL CA bundle guard skipped via HERMES_SKIP_SSL_GUARD")
        return

    for env_var in _CA_BUNDLE_ENV_VARS:
        value = os.getenv(env_var)
        if value:
            _validate_bundle_path(env_var, value)

    try:
        import certifi
    except Exception as exc:
        raise _ssl_err(f"certifi is not importable: {exc}") from exc

    ca_bundle = str(certifi.where())
    _validate_bundle_path("certifi", ca_bundle, require_substantial=True)


def verify_ca_bundle_with_fallback() -> None:
    """Backward-compatible wrapper for older call sites.

    The old PR name mentioned a platform fallback, but allowing startup with a
    broken certifi bundle still leaves httpx/OpenAI and requests call sites
    failing later. Keep the wrapper name but enforce the same check.
    """
    verify_ca_bundle()


# ---------------------------------------------------------------------------
# SPKI certificate pinning (security.cert_pinning)
# ---------------------------------------------------------------------------
#
# ``verify_ca_bundle`` only checks that the trust store loads; any CA in it can
# still vouch for a provider endpoint. When ``security.cert_pinning.enabled``
# is true, the TLS handshake for every pinned host must also present a leaf
# certificate whose SubjectPublicKeyInfo hashes to a configured pin::
#
#     security:
#       cert_pinning:
#         enabled: true
#         pins:
#           bedrock-runtime.us-gov-west-1.amazonaws.com:
#             - "sha256/<base64 of sha256(DER SubjectPublicKeyInfo)>"
#             - "sha256/<backup pin>"
#
# A host key of ``*.example.com`` matches exactly one extra label. Hosts with
# no pins are not affected. The check runs after normal chain/hostname
# verification (it never replaces it) and is installed process-wide by
# swapping ``ssl.SSLContext.sslsocket_class`` / ``sslobject_class``, so it
# covers httpx/OpenAI/Anthropic (sync and async) and urllib3/botocore without
# per-client wiring. Only the leaf certificate is pinned (Python 3.11 exposes
# no verified chain), so pins must be rotated with the endpoint's key.
#
# Enabled with no pins: under strict posture this is a configuration error
# (raised by ``load_pin_policy`` / ``ensure_cert_pinning``), so the config
# cannot claim pinning that is not happening. Low-side it logs and stays off.

import base64
import binascii
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Mapping, Optional

_PIN_PREFIX = "sha256/"


class CertPinningConfigError(SSLConfigurationError):
    """security.cert_pinning is enabled but unusable (no or malformed pins)."""


class CertificatePinError(ssl.SSLCertVerificationError):
    """A pinned host presented a certificate whose SPKI matches no pin."""


@dataclass(frozen=True)
class PinPolicy:
    """Resolved pin set: lower-cased host -> frozenset of base64 SHA-256 pins."""

    enabled: bool = False
    pins: Mapping[str, FrozenSet[str]] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return bool(self.enabled and self.pins)

    def pins_for(self, host: Optional[str]) -> Optional[FrozenSet[str]]:
        if not host:
            return None
        h = host.strip().rstrip(".").lower()
        found = self.pins.get(h)
        if found:
            return found
        if "." in h:
            wildcard = "*." + h.split(".", 1)[1]
            return self.pins.get(wildcard) or None
        return None


def spki_sha256_b64(cert_der: bytes) -> str:
    """Base64 SHA-256 of a DER certificate's SubjectPublicKeyInfo (HPKP form)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def _normalise_pin(raw: Any, host: str) -> str:
    text = str(raw or "").strip()
    if text.lower().startswith(_PIN_PREFIX):
        text = text[len(_PIN_PREFIX):]
    try:
        digest = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CertPinningConfigError(
            f"security.cert_pinning.pins[{host!r}]: {raw!r} is not base64 ({exc})"
        ) from exc
    if len(digest) != 32:
        raise CertPinningConfigError(
            f"security.cert_pinning.pins[{host!r}]: {raw!r} is not a SHA-256 "
            f"digest (decoded {len(digest)} bytes, expected 32)"
        )
    return base64.b64encode(digest).decode("ascii")


def _posture_is_strict(config: Optional[dict]) -> bool:
    try:
        from lliam_cli import posture_resolver as _pr

        return bool(_pr.is_strict(config))
    except Exception:
        return True  # unresolvable posture: treat as strict (fail closed)


def load_pin_policy(config: Optional[dict] = None) -> PinPolicy:
    """Resolve ``security.cert_pinning`` into a :class:`PinPolicy`.

    ``config`` defaults to the merged (overlay-aware) ``load_config()``.
    Raises :class:`CertPinningConfigError` for malformed pins, and — under
    strict posture — when pinning is enabled with no pins.
    """
    if config is None:
        from lliam_cli.config import load_config

        config = load_config()
    sec = config.get("security") if isinstance(config, dict) else None
    block = sec.get("cert_pinning") if isinstance(sec, dict) else None
    if not isinstance(block, dict) or not block.get("enabled"):
        return PinPolicy(enabled=False)

    raw_pins = block.get("pins") or {}
    if not isinstance(raw_pins, dict):
        raise CertPinningConfigError(
            "security.cert_pinning.pins must map host -> list of sha256 pins"
        )
    pins: Dict[str, FrozenSet[str]] = {}
    for host, values in raw_pins.items():
        h = str(host or "").strip().rstrip(".").lower()
        if not h:
            raise CertPinningConfigError("security.cert_pinning.pins has an empty host key")
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, (list, tuple)) or not values:
            raise CertPinningConfigError(
                f"security.cert_pinning.pins[{host!r}] must be a non-empty list of pins"
            )
        pins[h] = frozenset(_normalise_pin(v, h) for v in values)

    if not pins:
        message = (
            "security.cert_pinning.enabled is true but no pins are configured "
            "(security.cert_pinning.pins is empty), so nothing would be pinned."
        )
        if _posture_is_strict(config):
            raise CertPinningConfigError(
                message + " Refusing to start under strict posture: provision "
                "per-endpoint SPKI pins or set enabled: false."
            )
        logger.warning("%s Pinning stays off (advisory, not strict).", message)
        return PinPolicy(enabled=False)
    return PinPolicy(enabled=True, pins=pins)


def verify_peer_pin(host: Optional[str], cert_der: Optional[bytes], policy: PinPolicy) -> None:
    """Raise :class:`CertificatePinError` when a pinned host's SPKI is not pinned."""
    pins = policy.pins_for(host) if policy.enabled else None
    if not pins:
        return
    if not cert_der:
        raise CertificatePinError(
            f"certificate pinning: {host} presented no peer certificate"
        )
    try:
        actual = spki_sha256_b64(cert_der)
    except Exception as exc:
        raise CertificatePinError(
            f"certificate pinning: could not parse the certificate for {host}: {exc}"
        ) from exc
    if actual not in pins:
        raise CertificatePinError(
            f"certificate pinning: SPKI pin mismatch for {host} "
            f"(presented sha256/{actual}; expected one of "
            f"{', '.join('sha256/' + p for p in sorted(pins))})"
        )


_PIN_LOCK = threading.Lock()
_ACTIVE_POLICY: Optional[PinPolicy] = None
_ORIGINAL_SSL_CLASSES: Optional[tuple] = None


def _check_handshake(conn: Any) -> None:
    policy = _ACTIVE_POLICY
    if policy is None or not policy.active:
        return
    host = getattr(conn, "server_hostname", None)
    if not policy.pins_for(host):
        return
    verify_peer_pin(host, conn.getpeercert(binary_form=True), policy)


class _PinnedSSLSocket(ssl.SSLSocket):
    def do_handshake(self, *args, **kwargs):
        result = super().do_handshake(*args, **kwargs)
        _check_handshake(self)
        return result


class _PinnedSSLObject(ssl.SSLObject):
    def do_handshake(self):
        result = super().do_handshake()
        _check_handshake(self)
        return result


def install_cert_pinning(policy: PinPolicy) -> None:
    """Activate ``policy`` process-wide (idempotent). An inactive policy uninstalls."""
    global _ACTIVE_POLICY, _ORIGINAL_SSL_CLASSES
    with _PIN_LOCK:
        if not policy.active:
            _ACTIVE_POLICY = None
            if _ORIGINAL_SSL_CLASSES is not None:
                ssl.SSLContext.sslsocket_class, ssl.SSLContext.sslobject_class = _ORIGINAL_SSL_CLASSES
                _ORIGINAL_SSL_CLASSES = None
            return
        if _ORIGINAL_SSL_CLASSES is None:
            _ORIGINAL_SSL_CLASSES = (ssl.SSLContext.sslsocket_class, ssl.SSLContext.sslobject_class)
            ssl.SSLContext.sslsocket_class = _PinnedSSLSocket
            ssl.SSLContext.sslobject_class = _PinnedSSLObject
        _ACTIVE_POLICY = policy
    logger.info("certificate pinning active for %d host(s)", len(policy.pins))


def uninstall_cert_pinning() -> None:
    install_cert_pinning(PinPolicy(enabled=False))


def ensure_cert_pinning(config: Optional[dict] = None) -> PinPolicy:
    """Load ``security.cert_pinning`` and install it. Called at agent init.

    Raises :class:`CertPinningConfigError` on a strict-posture configuration
    error. A config that cannot be loaded at all leaves pinning unchanged.
    """
    try:
        policy = load_pin_policy(config)
    except CertPinningConfigError:
        raise
    except Exception:
        logger.warning("certificate pinning: config could not be read", exc_info=True)
        return _ACTIVE_POLICY or PinPolicy(enabled=False)
    install_cert_pinning(policy)
    return policy
