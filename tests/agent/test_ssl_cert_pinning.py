"""SPKI certificate pinning (security.cert_pinning) — agent/ssl_guard.py.

Uses a locally generated self-signed certificate and a loopback TLS server to
prove the process-wide handshake hook accepts a matching pin and rejects a
mismatched one, for plain ``ssl`` sockets (urllib3/botocore path), httpx sync
and httpx async (SSLObject / memory-BIO path).
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agent import ssl_guard as sg

HOST = "localhost"


def _make_cert(tmp_path, name="server"):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / f"{name}.pem"
    key_path = tmp_path / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pin = base64.b64encode(hashlib.sha256(spki).digest()).decode()
    return cert_path, key_path, cert.public_bytes(serialization.Encoding.DER), pin


class _TLSServer:
    """Loopback HTTPS server answering every request with 200 OK."""

    def __init__(self, cert_path, key_path):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_path, key_path)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                raw, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with self.ctx.wrap_socket(raw, server_side=True) as conn:
                    conn.settimeout(2)
                    try:
                        conn.recv(65536)
                    except Exception:
                        pass
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    )
            except Exception:
                pass

    def close(self):
        self._stop = True
        self.thread.join(timeout=2)
        self.sock.close()


@pytest.fixture
def tls(tmp_path):
    cert_path, key_path, der, pin = _make_cert(tmp_path)
    server = _TLSServer(str(cert_path), str(key_path))
    _, _, _, other_pin = _make_cert(tmp_path, name="other")
    yield {"cert": str(cert_path), "der": der, "pin": pin, "other_pin": other_pin, "port": server.port}
    server.close()


@pytest.fixture(autouse=True)
def _uninstall():
    sg.uninstall_cert_pinning()
    yield
    sg.uninstall_cert_pinning()


def _client_ctx(cert):
    ctx = ssl.create_default_context(cafile=cert)
    return ctx


def _policy(host_pins):
    return sg.load_pin_policy(
        {"security": {"cert_pinning": {"enabled": True, "pins": host_pins}}}
    )


def _connect(tls):
    ctx = _client_ctx(tls["cert"])
    with socket.create_connection(("127.0.0.1", tls["port"]), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=HOST) as conn:
            return conn.version()


# --------------------------------------------------------------------------- #
# Pin computation + policy loading
# --------------------------------------------------------------------------- #

def test_spki_hash_matches_independent_computation(tls):
    assert sg.spki_sha256_b64(tls["der"]) == tls["pin"]


def test_verify_peer_pin_match_and_mismatch(tls):
    policy = _policy({HOST: [f"sha256/{tls['pin']}"]})
    sg.verify_peer_pin(HOST, tls["der"], policy)
    wrong = _policy({HOST: [tls["other_pin"]]})
    with pytest.raises(sg.CertificatePinError, match="pin mismatch"):
        sg.verify_peer_pin(HOST, tls["der"], wrong)


def test_unpinned_host_is_not_checked(tls):
    policy = _policy({"other.example": [tls["other_pin"]]})
    sg.verify_peer_pin(HOST, tls["der"], policy)


def test_wildcard_host_matches_one_label(tls):
    policy = _policy({"*.example.com": [tls["pin"]]})
    assert policy.pins_for("api.example.com")
    assert policy.pins_for("a.b.example.com") is None


def test_disabled_policy_is_inactive():
    policy = sg.load_pin_policy({"security": {"cert_pinning": {"enabled": False, "pins": {}}}})
    assert policy.active is False


def test_enabled_without_pins_is_a_strict_config_error():
    cfg = {"security": {"posture": "strict", "cert_pinning": {"enabled": True, "pins": {}}}}
    with pytest.raises(sg.CertPinningConfigError, match="no pins"):
        sg.load_pin_policy(cfg)
    with pytest.raises(sg.CertPinningConfigError):
        sg.ensure_cert_pinning(cfg)


def test_enabled_without_pins_is_advisory_low_side():
    cfg = {"security": {"cert_pinning": {"enabled": True}}}
    assert sg.load_pin_policy(cfg).active is False


@pytest.mark.parametrize("bad", ["not base64!", base64.b64encode(b"short").decode()])
def test_malformed_pin_is_a_config_error(bad):
    with pytest.raises(sg.CertPinningConfigError):
        _policy({HOST: [bad]})


def test_shipped_overlay_shape_loads_under_strict():
    """enabled: false + pins: {} (the gov overlay) is not an error."""
    cfg = {"security": {"posture": "strict", "cert_pinning": {"enabled": False, "pins": {}}}}
    assert sg.ensure_cert_pinning(cfg).active is False


# --------------------------------------------------------------------------- #
# Live handshake enforcement
# --------------------------------------------------------------------------- #

def test_handshake_with_matching_pin_succeeds(tls):
    sg.install_cert_pinning(_policy({HOST: [tls["pin"]]}))
    assert _connect(tls)


def test_handshake_with_mismatched_pin_is_refused(tls):
    sg.install_cert_pinning(_policy({HOST: [tls["other_pin"]]}))
    with pytest.raises(sg.CertificatePinError, match="pin mismatch"):
        _connect(tls)


def test_uninstall_restores_unpinned_behaviour(tls):
    sg.install_cert_pinning(_policy({HOST: [tls["other_pin"]]}))
    sg.uninstall_cert_pinning()
    assert _connect(tls)
    assert ssl.SSLContext.sslsocket_class is ssl.SSLSocket


def test_httpx_sync_client_enforces_pin(tls):
    httpx = pytest.importorskip("httpx")
    url = f"https://{HOST}:{tls['port']}/"
    sg.install_cert_pinning(_policy({HOST: [tls["pin"]]}))
    with httpx.Client(verify=_client_ctx(tls["cert"]), trust_env=False) as client:
        assert client.get(url).status_code == 200
    sg.install_cert_pinning(_policy({HOST: [tls["other_pin"]]}))
    with httpx.Client(verify=_client_ctx(tls["cert"]), trust_env=False) as client:
        with pytest.raises(httpx.ConnectError, match="pin mismatch"):
            client.get(url)


def test_httpx_async_client_enforces_pin(tls):
    httpx = pytest.importorskip("httpx")
    url = f"https://{HOST}:{tls['port']}/"

    async def _get():
        async with httpx.AsyncClient(verify=_client_ctx(tls["cert"]), trust_env=False) as client:
            return (await client.get(url)).status_code

    sg.install_cert_pinning(_policy({HOST: [tls["pin"]]}))
    assert asyncio.run(_get()) == 200
    sg.install_cert_pinning(_policy({HOST: [tls["other_pin"]]}))
    with pytest.raises(httpx.ConnectError, match="pin mismatch"):
        asyncio.run(_get())
