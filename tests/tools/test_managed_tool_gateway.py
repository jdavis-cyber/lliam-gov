import os
import json
from datetime import datetime, timedelta, timezone
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[2] / "tools" / "managed_tool_gateway.py"
MODULE_SPEC = spec_from_file_location("managed_tool_gateway_test_module", MODULE_PATH)
assert MODULE_SPEC and MODULE_SPEC.loader
managed_tool_gateway = module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = managed_tool_gateway
MODULE_SPEC.loader.exec_module(managed_tool_gateway)
resolve_managed_tool_gateway = managed_tool_gateway.resolve_managed_tool_gateway


def test_resolve_managed_tool_gateway_derives_vendor_origin_from_shared_domain():
    with patch.dict(
        os.environ,
        {
            "TOOL_GATEWAY_DOMAIN": "nousresearch.com",
        },
        clear=False,
    ), patch.object(managed_tool_gateway, "managed_nous_tools_enabled", return_value=True):
        result = resolve_managed_tool_gateway(
            "firecrawl",
            token_reader=lambda: "nous-token",
        )

    assert result is not None
    assert result.gateway_origin == "https://firecrawl-gateway.nousresearch.com"
    assert result.nous_user_token == "nous-token"
    assert result.managed_mode is True


def test_resolve_managed_tool_gateway_uses_vendor_specific_override():
    with patch.dict(
        os.environ,
        {
            "BROWSER_USE_GATEWAY_URL": "http://browser-use-gateway.localhost:3009/",
        },
        clear=False,
    ), patch.object(managed_tool_gateway, "managed_nous_tools_enabled", return_value=True):
        result = resolve_managed_tool_gateway(
            "browser-use",
            token_reader=lambda: "nous-token",
        )

    assert result is not None
    assert result.gateway_origin == "http://browser-use-gateway.localhost:3009"


def test_resolve_managed_tool_gateway_is_inactive_without_nous_token():
    with patch.dict(
        os.environ,
        {
            "TOOL_GATEWAY_DOMAIN": "nousresearch.com",
        },
        clear=False,
    ), patch.object(managed_tool_gateway, "managed_nous_tools_enabled", return_value=True):
        result = resolve_managed_tool_gateway(
            "firecrawl",
            token_reader=lambda: None,
        )

    assert result is None


def test_resolve_managed_tool_gateway_is_disabled_without_subscription():
    with patch.dict(os.environ, {"TOOL_GATEWAY_DOMAIN": "nousresearch.com"}, clear=False), \
         patch.object(managed_tool_gateway, "managed_nous_tools_enabled", return_value=False):
        result = resolve_managed_tool_gateway(
            "firecrawl",
            token_reader=lambda: "nous-token",
        )

    assert result is None


def test_read_nous_access_token_refreshes_expiring_cached_token(tmp_path, monkeypatch):
    monkeypatch.delenv("TOOL_GATEWAY_USER_TOKEN", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
    (tmp_path / "auth.json").write_text(json.dumps({
        "providers": {
            "nous": {
                "access_token": "stale-token",
                "refresh_token": "refresh-token",
                "expires_at": expires_at,
            }
        }
    }))
    monkeypatch.setattr(
        "hermes_cli.auth.resolve_nous_access_token",
        lambda refresh_skew_seconds=120: "fresh-token",
    )

    assert managed_tool_gateway.read_nous_access_token() == "fresh-token"


def test_read_nous_provider_state_decrypts_encrypted_auth_store(tmp_path, monkeypatch):
    """LG-3.7 / AI-215 P2: _read_nous_provider_state must route through
    state_codec.decode_state_bytes so an encrypted auth.json (LLIAM_GOV_ENCRYPT_STATE=1)
    still resolves Nous provider state. Without this, the probe silently reports
    "no Nous credentials" on the encrypted profile."""
    from lliam_gov.security.key_manager import KeyManager
    from lliam_gov.security.state_codec import encode_state_bytes

    class _FakeKeyring:
        def __init__(self):
            self._store = {}
        def get_password(self, s, a):
            return self._store.get((s, a))
        def set_password(self, s, a, v):
            self._store[(s, a)] = v
        def delete_password(self, s, a):
            self._store.pop((s, a), None)

    km = KeyManager(service="mtg-test", backend=_FakeKeyring())
    km.init()

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("LLIAM_GOV_ENCRYPT_STATE", "1")
    import lliam_gov.security.state_codec as state_codec
    monkeypatch.setattr(state_codec, "_shared_km", lambda: km)

    plaintext = json.dumps({
        "providers": {
            "nous": {"access_token": "nous-encrypted-token"},
        },
    }).encode("utf-8")
    ciphertext = encode_state_bytes(plaintext)
    assert ciphertext != plaintext
    (tmp_path / "auth.json").write_bytes(ciphertext)

    state = managed_tool_gateway._read_nous_provider_state()
    assert state == {"access_token": "nous-encrypted-token"}
