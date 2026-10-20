"""JER-75 — Bedrock provider egress is enforced on the boto3 endpoint.

``agent/bedrock_adapter.py`` talks to AWS through boto3, not the OpenAI client,
so the provider egress allowlist has to be applied to the endpoint botocore
actually resolved (region, ``endpoint_url`` / ``AWS_ENDPOINT_URL*`` override)
before any request is sent. Low-side postures are unaffected.
"""

from __future__ import annotations

import textwrap
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

GOV_WEST = "https://bedrock-runtime.us-gov-west-1.amazonaws.com"
COMMERCIAL = "https://bedrock-runtime.us-east-1.amazonaws.com"

_POLICY = textwrap.dedent(
    """
    metadata:
      default_disposition: deny
    approved_destinations:
      - {host: "bedrock-runtime.us-gov-west-1.amazonaws.com", surfaces: [provider],
         classification_ceiling: "CUI//SP-PRIV"}
      - {host: "public-only.provider.test", surfaces: [provider],
         classification_ceiling: "PUBLIC"}
      - {host: "api.github.com", surfaces: [web]}
    """
)

_CONVERSE_OK = {
    "output": {"message": {"role": "assistant", "content": [{"text": "ok"}]}},
    "stopReason": "end_turn",
    "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
}


def _set_config(monkeypatch, tmp_path, *, posture="strict", **egress):
    policy = tmp_path / "egress-allowlist.yaml"
    policy.write_text(_POLICY, encoding="utf-8")
    cfg = {"security": {"posture": posture, "allow_private_urls": False,
                        "egress": {"mode": "allowlist", "policy_path": str(policy),
                                   "fail_closed": True, **egress}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import tools.egress_policy as ep

    ep.reset_egress_cache()
    return cfg


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    # Deterministic botocore endpoint resolution: no user AWS config, no
    # endpoint overrides, no proxies leaking in from the developer shell.
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "aws-creds"))
    for name in ("AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_BEDROCK_RUNTIME",
                 "AWS_ENDPOINT_URL_BEDROCK", "AWS_USE_FIPS_ENDPOINT",
                 "AWS_USE_DUALSTACK_ENDPOINT", "AWS_PROFILE",
                 "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
                 "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    # Allowlisted hostnames are DNS-checked against the SSRF floor; keep the
    # tests offline. The floor itself is covered in tests/tools.
    monkeypatch.setattr("tools.url_safety.is_safe_url", lambda url, *a, **kw: True)
    ba.reset_client_cache()
    ba.reset_discovery_cache()
    yield
    ba.reset_client_cache()
    ba.reset_discovery_cache()
    import tools.egress_policy as ep

    ep.reset_egress_cache()


def _fake_boto3(endpoint_url):
    """A boto3 stand-in whose clients report ``endpoint_url`` and record calls."""
    created = []

    def _client(service, region_name=None, **kw):
        client = MagicMock(name=f"{service}:{region_name}")
        client.meta.endpoint_url = endpoint_url
        client.converse.return_value = _CONVERSE_OK
        client.list_foundation_models.return_value = {"modelSummaries": []}
        client.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
        created.append(client)
        return client

    return SimpleNamespace(client=_client, __version__="1.42.0"), created


def _real_runtime_client(region):
    """Build the adapter's cached client with real boto3 and stub its methods."""
    import agent.bedrock_adapter as ba

    client = ba._get_bedrock_runtime_client(region)
    client.converse = MagicMock(return_value=_CONVERSE_OK)
    client.converse_stream = MagicMock()
    return client


# ---------------------------------------------------------------------------
# Adapter entry points (call_converse / call_converse_stream)
# ---------------------------------------------------------------------------

def test_converse_to_commercial_region_denied_before_request(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path)
    fake, created = _fake_boto3(COMMERCIAL)
    monkeypatch.setattr(ba, "_require_boto3", lambda: fake)

    with pytest.raises(PermissionError, match="not on the egress allowlist"):
        ba.call_converse(region="us-east-1", model="m", messages=[{"role": "user", "content": "x"}])
    assert created and not created[0].converse.called


def test_converse_stream_to_commercial_region_denied_before_request(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path)
    fake, created = _fake_boto3(COMMERCIAL)
    monkeypatch.setattr(ba, "_require_boto3", lambda: fake)

    with pytest.raises(PermissionError):
        ba.call_converse_stream(region="us-east-1", model="m", messages=[{"role": "user", "content": "x"}])
    assert not created[0].converse_stream.called
    assert not created[0].converse.called


def test_govcloud_region_allowed_with_real_boto3_endpoint(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path)
    client = _real_runtime_client("us-gov-west-1")
    assert client.meta.endpoint_url == GOV_WEST

    result = ba.call_converse(region="us-gov-west-1", model="m",
                              messages=[{"role": "user", "content": "x"}])
    client.converse.assert_called_once()
    assert result.choices[0].message.content == "ok"


def test_endpoint_url_override_is_what_gets_checked(monkeypatch, tmp_path):
    """An AWS_ENDPOINT_URL_* override is caught even when the region is GovCloud."""
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path)
    monkeypatch.setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "https://bedrock.exfil.test")
    client = _real_runtime_client("us-gov-west-1")
    assert client.meta.endpoint_url == "https://bedrock.exfil.test"

    with pytest.raises(PermissionError, match="bedrock.exfil.test"):
        ba.call_converse(region="us-gov-west-1", model="m",
                         messages=[{"role": "user", "content": "x"}])
    client.converse.assert_not_called()


def test_commercial_region_resolved_by_real_boto3_denied(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path)
    client = _real_runtime_client("us-east-1")

    with pytest.raises(PermissionError, match="bedrock-runtime.us-east-1.amazonaws.com"):
        ba.call_converse_stream(region="us-east-1", model="m",
                                messages=[{"role": "user", "content": "x"}])
    client.converse_stream.assert_not_called()


def test_unknown_endpoint_fails_closed_on_strict(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path)
    fake, created = _fake_boto3(None)
    monkeypatch.setattr(ba, "_require_boto3", lambda: fake)

    with pytest.raises(PermissionError):
        ba.call_converse(region="us-gov-west-1", model="m", messages=[])
    assert not created[0].converse.called


def test_low_side_posture_unaffected(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path, posture="standard", proxy_required=True)
    fake, created = _fake_boto3(COMMERCIAL)
    monkeypatch.setattr(ba, "_require_boto3", lambda: fake)

    result = ba.call_converse(region="us-east-1", model="m",
                              messages=[{"role": "user", "content": "x"}])
    created[0].converse.assert_called_once()
    assert result.choices[0].message.content == "ok"


def test_session_cui_taint_reaches_the_bedrock_gate(monkeypatch, tmp_path):
    """session_id is plumbed through so the CUI ceiling applies to Bedrock too."""
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "agent.data_protection.session_cui_tainted",
        lambda *, session_id=None: session_id == "tainted",
    )
    fake, created = _fake_boto3("https://public-only.provider.test")
    monkeypatch.setattr(ba, "_require_boto3", lambda: fake)

    ba.call_converse(region="r", model="m", messages=[], session_id="clean")
    assert created[0].converse.call_count == 1
    with pytest.raises(PermissionError, match="CUI"):
        ba.call_converse(region="r", model="m", messages=[], session_id="tainted")
    assert created[0].converse.call_count == 1


def test_model_discovery_skipped_for_non_allowlisted_control_plane(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path)
    fake, created = _fake_boto3("https://bedrock.us-gov-west-1.amazonaws.com")
    monkeypatch.setattr(ba, "_require_boto3", lambda: fake)

    assert ba.discover_bedrock_models("us-gov-west-1") == []
    assert not created[0].list_foundation_models.called


# ---------------------------------------------------------------------------
# Strict posture: squid enclave required (security.egress.proxy_required)
# ---------------------------------------------------------------------------

def test_proxy_required_denies_without_https_proxy(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path, proxy_required=True)
    fake, created = _fake_boto3(GOV_WEST)
    monkeypatch.setattr(ba, "_require_boto3", lambda: fake)

    with pytest.raises(PermissionError, match="HTTPS_PROXY"):
        ba.call_converse(region="us-gov-west-1", model="m", messages=[])
    assert not created[0].converse.called


def test_proxy_required_denies_when_no_proxy_bypasses_host(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path, proxy_required=True)
    monkeypatch.setenv("HTTPS_PROXY", "http://egress-proxy:3128")
    monkeypatch.setenv("NO_PROXY", "localhost,.amazonaws.com")
    fake, created = _fake_boto3(GOV_WEST)
    monkeypatch.setattr(ba, "_require_boto3", lambda: fake)

    with pytest.raises(PermissionError, match="NO_PROXY"):
        ba.call_converse(region="us-gov-west-1", model="m", messages=[])
    assert not created[0].converse.called


def test_proxy_required_allows_when_proxied(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    _set_config(monkeypatch, tmp_path, proxy_required=True)
    monkeypatch.setenv("HTTPS_PROXY", "http://egress-proxy:3128")
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1,egress-proxy")
    fake, created = _fake_boto3(GOV_WEST)
    monkeypatch.setattr(ba, "_require_boto3", lambda: fake)

    ba.call_converse(region="us-gov-west-1", model="m", messages=[])
    created[0].converse.assert_called_once()


# ---------------------------------------------------------------------------
# Agent request boundary (chat_completion_helpers)
# ---------------------------------------------------------------------------

def _bedrock_agent(base_url=GOV_WEST):
    from run_agent import AIAgent

    agent = AIAgent(
        api_key="test-key",
        base_url="https://openrouter.ai/api/v1",
        model="anthropic.claude-3-sonnet-20240229-v1:0",
        quiet_mode=True,
        skip_context_files=True,
        skip_memory=True,
    )
    agent.api_mode = "bedrock_converse"
    agent.base_url = base_url
    agent._anthropic_base_url = None
    agent._interrupt_requested = False
    return agent


@pytest.mark.parametrize("streaming", [False, True])
def test_agent_bedrock_region_mismatch_denied(monkeypatch, tmp_path, streaming):
    """Configured base_url is GovCloud but the request region is commercial:
    the boto3 endpoint check must still deny before converse()."""
    import agent.bedrock_adapter as ba

    agent = _bedrock_agent()
    _set_config(monkeypatch, tmp_path)
    fake, created = _fake_boto3(COMMERCIAL)
    monkeypatch.setattr(ba, "_require_boto3", lambda: fake)

    kwargs = {"modelId": agent.model, "messages": [], "__bedrock_region__": "us-east-1",
              "__bedrock_converse__": True}
    call = agent._interruptible_streaming_api_call if streaming else agent._interruptible_api_call
    with pytest.raises(PermissionError, match="us-east-1"):
        call(kwargs)
    assert not created[0].converse.called
    assert not created[0].converse_stream.called


def test_agent_bedrock_govcloud_request_allowed(monkeypatch, tmp_path):
    import agent.bedrock_adapter as ba

    agent = _bedrock_agent()
    _set_config(monkeypatch, tmp_path)
    fake, created = _fake_boto3(GOV_WEST)
    monkeypatch.setattr(ba, "_require_boto3", lambda: fake)

    response = agent._interruptible_api_call(
        {"modelId": agent.model, "messages": [], "__bedrock_region__": "us-gov-west-1",
         "__bedrock_converse__": True}
    )
    created[0].converse.assert_called_once()
    assert response.choices[0].message.content == "ok"


def test_anthropic_bedrock_live_client_endpoint_checked(monkeypatch, tmp_path):
    """Claude-on-Bedrock (AnthropicBedrock SDK): the live client's base_url is
    checked, not only the configured _anthropic_base_url."""
    import httpx
    from agent.chat_completion_helpers import _enforce_provider_egress

    _set_config(monkeypatch, tmp_path)
    agent = SimpleNamespace(
        api_mode="anthropic_messages",
        _anthropic_base_url=GOV_WEST,
        _anthropic_client=SimpleNamespace(base_url=httpx.URL(COMMERCIAL)),
        base_url=GOV_WEST,
        client=None,
        session_id="s",
    )
    with pytest.raises(PermissionError, match="us-east-1"):
        _enforce_provider_egress(agent)

    agent._anthropic_client = SimpleNamespace(base_url=httpx.URL(GOV_WEST))
    _enforce_provider_egress(agent)  # allowed


@pytest.mark.parametrize(
    "region, allowed",
    [("us-gov-west-1", True), ("us-east-1", False)],
)
def test_auxiliary_bedrock_client_checked_on_real_endpoint(monkeypatch, tmp_path, region, allowed):
    """Auxiliary Claude-on-Bedrock clients are checked on the AnthropicBedrock
    endpoint, not only the synthetic base_url handed to validate_provider."""
    from agent import auxiliary_client as aux

    _set_config(monkeypatch, tmp_path)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setattr("agent.bedrock_adapter.has_aws_credentials", lambda *a, **kw: True)
    monkeypatch.setattr("agent.bedrock_adapter.resolve_bedrock_region", lambda *a, **kw: region)

    client, model = aux.resolve_provider_client("bedrock", "anthropic.claude-haiku-4-5-20251001-v1:0")
    assert (client is not None) is allowed


def test_max_iterations_summary_is_egress_gated(monkeypatch, tmp_path):
    """The iteration-limit summary calls the transport clients directly; it must
    not send the history to a destination the provider boundary would deny."""
    from agent.chat_completion_helpers import handle_max_iterations

    agent = _bedrock_agent(base_url="https://api.not-allowlisted.test/v1")
    agent.api_mode = "chat_completions"
    _set_config(monkeypatch, tmp_path)
    primary = MagicMock()
    monkeypatch.setattr(agent, "_ensure_primary_openai_client", lambda *a, **kw: primary, raising=False)

    text = handle_max_iterations(agent, [{"role": "user", "content": "hi"}], 3)
    assert "blocked by egress policy" in text
    assert not primary.chat.completions.create.called
