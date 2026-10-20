"""security.require_mfa for the self-hosted OIDC dashboard provider.

With require_mfa on, every ID token must carry an RFC 8176 ``amr`` value that
shows a multi-factor login; otherwise login fails and an existing session is
dropped. The provider then advertises ``enforces_mfa`` to the dashboard gate.
"""

from __future__ import annotations

import time
from typing import Any, Dict
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import plugins.dashboard_auth.self_hosted as oidc_plugin
from lliam_cli.dashboard_auth import InvalidCodeError

_ISSUER = "https://auth.example.com/application/o/hermes"
_CLIENT_ID = "hermes-dashboard"
_DISCOVERY_DOC = {
    "issuer": _ISSUER,
    "authorization_endpoint": f"{_ISSUER}/authorize",
    "token_endpoint": f"{_ISSUER}/token",
    "jwks_uri": f"{_ISSUER}/jwks",
}


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _token(key, **extra: Any) -> str:
    now = int(time.time())
    claims: Dict[str, Any] = {
        "iss": _ISSUER, "aud": _CLIENT_ID, "sub": "usr_abc",
        "iat": now, "exp": now + 900, "email": "a@example.com",
    }
    claims.update(extra)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "k1"})


def _provider(key, **kwargs):
    p = oidc_plugin.SelfHostedOIDCProvider(issuer=_ISSUER, client_id=_CLIENT_ID, **kwargs)
    p._discovery = dict(_DISCOVERY_DOC)
    p._discovery_fetched_at = time.time()
    signing = MagicMock()
    signing.key = key.public_key()
    client = MagicMock()
    client.get_signing_key_from_jwt.return_value = signing
    p._jwks_client = client
    return p


def test_default_provider_does_not_claim_mfa(key):
    p = _provider(key)
    assert p.enforces_mfa is False
    assert p.verify_session(access_token=_token(key)) is not None


def test_require_mfa_sets_enforces_mfa(key):
    assert _provider(key, require_mfa=True).enforces_mfa is True


@pytest.mark.parametrize("amr", [["pwd", "otp"], ["mfa"], "mfa", ["hwk", "user"]])
def test_mfa_amr_accepted(key, amr):
    p = _provider(key, require_mfa=True)
    assert p.verify_session(access_token=_token(key, amr=amr)) is not None


@pytest.mark.parametrize("amr", [None, [], ["pwd"], "pwd"])
def test_session_without_mfa_amr_is_dropped(key, amr):
    p = _provider(key, require_mfa=True)
    extra = {} if amr is None else {"amr": amr}
    assert p.verify_session(access_token=_token(key, **extra)) is None


def test_login_without_mfa_is_refused(key):
    p = _provider(key, require_mfa=True)
    with pytest.raises(InvalidCodeError, match="multi-factor login required"):
        p._verify_id_token(_token(key, amr=["pwd"]))


def test_custom_amr_values(key):
    p = _provider(key, require_mfa=True, mfa_amr_values=("swk",))
    assert p.verify_session(access_token=_token(key, amr=["swk"])) is not None
    assert p.verify_session(access_token=_token(key, amr=["otp"])) is None


def _register(monkeypatch, cfg):
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: cfg)
    for var in ("HERMES_DASHBOARD_OIDC_ISSUER", "HERMES_DASHBOARD_OIDC_CLIENT_ID",
                "HERMES_DASHBOARD_OIDC_REQUIRE_MFA"):
        monkeypatch.delenv(var, raising=False)
    ctx = MagicMock()
    oidc_plugin.register(ctx)
    return ctx.register_dashboard_auth_provider.call_args[0][0]


_OIDC_BLOCK = {"dashboard": {"oauth": {"self_hosted": {"issuer": _ISSUER, "client_id": _CLIENT_ID}}}}


def test_register_forces_mfa_under_strict_require_mfa(monkeypatch):
    cfg = dict(_OIDC_BLOCK, security={"posture": "strict", "require_mfa": True})
    assert _register(monkeypatch, cfg).enforces_mfa is True


def test_register_low_side_leaves_mfa_off(monkeypatch):
    cfg = dict(_OIDC_BLOCK, security={"require_mfa": True})
    assert _register(monkeypatch, cfg).enforces_mfa is False


def test_register_honours_explicit_require_mfa(monkeypatch):
    cfg = {"dashboard": {"oauth": {"self_hosted": {
        "issuer": _ISSUER, "client_id": _CLIENT_ID, "require_mfa": True}}}}
    assert _register(monkeypatch, cfg).enforces_mfa is True
