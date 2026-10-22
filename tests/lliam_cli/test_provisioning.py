"""JER-78 — shipped template values never verify or reach Bedrock as if real.

lliam_cli/provisioning.py names the template shapes (REPLACE / PLACEHOLDER /
RECOMPUTE / ``<slot>`` / ``${ENV}`` ...). Under strict posture the Bedrock
guardrail binding refuses a template, partial, or DRAFT value with a
"not provisioned" reason at both consumers (runtime resolution and agent
init); non-strict keeps the previous pass-through behaviour.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from lliam_cli import provisioning as prov


# ---------------------------------------------------------------------------
# 1. Template detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    None, "", "   ", "null",
    "REPLACE-WITH-PROVISIONED-SIGNATURE",
    "sha256:PLACEHOLDER-recompute-at-build",
    "<bedrock-guardrail-id>",
    "AWS-GOVCLOUD-ATO-<id> / BAA-<id>",
    "${LLIAM_GOV_SIGNING_KEY}",
    "UNPROVISIONED: skill not present",
    "EXAMPLE-KEY",
    "changeme",
])
def test_template_values_are_unprovisioned(value):
    assert prov.is_unprovisioned(value) is True


@pytest.mark.parametrize("value", [
    "a" * 64,
    "sha256:" + "0123456789abcdef" * 4,
    "abc123def456",
    "7",
])
def test_real_shaped_values_are_provisioned(value):
    assert prov.is_unprovisioned(value) is False


def test_strict_posture_fails_closed_when_config_unreadable(monkeypatch):
    def _boom(*a, **kw):
        raise RuntimeError("config unreadable")

    monkeypatch.setattr("lliam_cli.config.load_config", _boom)
    assert prov.strict_posture() is True


def test_strict_posture_reads_passed_config():
    assert prov.strict_posture({"security": {"posture": "strict"}}) is True
    assert prov.strict_posture({"security": {}}) is False


# ---------------------------------------------------------------------------
# 2. Bedrock guardrail binding
# ---------------------------------------------------------------------------

_SHIPPED = {"guardrail_identifier": "<bedrock-guardrail-id>", "guardrail_version": "DRAFT"}


def test_no_guardrail_configured_is_none_in_any_posture():
    for strict in (True, False):
        assert prov.bedrock_guardrail_config({}, strict=strict) is None
        assert prov.bedrock_guardrail_config(
            {"guardrail_identifier": "", "guardrail_version": ""}, strict=strict) is None


@pytest.mark.parametrize("guardrail, field", [
    (_SHIPPED, "bedrock.guardrail.guardrail_identifier"),
    ({"guardrail_identifier": "${BEDROCK_GUARDRAIL_ID}", "guardrail_version": "3"},
     "bedrock.guardrail.guardrail_identifier"),
    ({"guardrail_identifier": "abc123def456", "guardrail_version": "DRAFT"},
     "bedrock.guardrail.guardrail_version"),
    ({"guardrail_identifier": "abc123def456", "guardrail_version": ""},
     "bedrock.guardrail.guardrail_version"),
    ({"guardrail_identifier": "", "guardrail_version": "2"},
     "bedrock.guardrail.guardrail_identifier"),
])
def test_strict_refuses_unprovisioned_guardrail(guardrail, field):
    with pytest.raises(prov.UnprovisionedValueError, match="not provisioned") as exc:
        prov.bedrock_guardrail_config(guardrail, strict=True)
    assert exc.value.field == field


def test_strict_accepts_published_guardrail():
    cfg = prov.bedrock_guardrail_config(
        {"guardrail_identifier": "abc123def456", "guardrail_version": "4",
         "stream_processing_mode": "async", "trace": "disabled"},
        strict=True,
    )
    assert cfg == {"guardrailIdentifier": "abc123def456", "guardrailVersion": "4",
                   "streamProcessingMode": "async", "trace": "disabled"}


def test_non_strict_keeps_pass_through_behaviour():
    # Capability preservation: low-side is unchanged (Bedrock itself rejects a bad id).
    assert prov.bedrock_guardrail_config(_SHIPPED, strict=False) == {
        "guardrailIdentifier": "<bedrock-guardrail-id>", "guardrailVersion": "DRAFT"}
    assert prov.bedrock_guardrail_config(
        {"guardrail_identifier": "abc123def456", "guardrail_version": ""}, strict=False) is None


# ---------------------------------------------------------------------------
# 3. Consumers — runtime resolution and agent init
# ---------------------------------------------------------------------------

def _patch_bedrock_runtime(monkeypatch, cfg):
    import agent.bedrock_adapter as ba
    import lliam_cli.runtime_provider as rp

    monkeypatch.setattr(rp, "resolve_provider", lambda *a, **k: "bedrock")
    monkeypatch.setattr(rp, "_get_model_config", lambda: {"default": "amazon.nova-pro-v1:0"})
    monkeypatch.setattr(rp, "load_config", lambda: cfg)
    monkeypatch.setattr(ba, "has_aws_credentials", lambda: True)
    monkeypatch.setattr(ba, "resolve_aws_auth_env_var", lambda: "AWS_PROFILE")
    monkeypatch.setattr(ba, "resolve_bedrock_region", lambda: "us-gov-west-1")
    return rp


def test_runtime_resolution_refuses_shipped_guardrail_under_strict(monkeypatch):
    from lliam_cli.auth import AuthError

    rp = _patch_bedrock_runtime(monkeypatch, {
        "security": {"posture": "strict"}, "bedrock": {"guardrail": dict(_SHIPPED)}})
    with pytest.raises(AuthError) as exc:
        rp._resolve_runtime_provider_unchecked(requested="bedrock")
    assert exc.value.code == "guardrail_not_provisioned"
    assert "not provisioned" in str(exc.value)


def test_runtime_resolution_binds_published_guardrail_under_strict(monkeypatch):
    rp = _patch_bedrock_runtime(monkeypatch, {
        "security": {"posture": "strict"},
        "bedrock": {"guardrail": {"guardrail_identifier": "abc123def456",
                                  "guardrail_version": "4"}}})
    runtime = rp._resolve_runtime_provider_unchecked(requested="bedrock")
    assert runtime["guardrail_config"] == {
        "guardrailIdentifier": "abc123def456", "guardrailVersion": "4"}


def _bedrock_agent(cfg):
    from run_agent import AIAgent

    with (
        patch("run_agent.get_tool_definitions", return_value=[]),
        patch("run_agent.check_toolset_requirements", return_value={}),
        patch("lliam_cli.config.load_config", return_value=cfg),
    ):
        return AIAgent(
            model="amazon.nova-pro-v1:0",
            provider="bedrock",
            api_mode="bedrock_converse",
            base_url="https://bedrock-runtime.us-gov-west-1.amazonaws.com",
            api_key="aws-sdk",
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
        )


def test_agent_init_refuses_shipped_guardrail_under_strict(monkeypatch):
    monkeypatch.setattr(prov, "strict_posture", lambda config=None: True)
    with pytest.raises(prov.UnprovisionedValueError, match="not provisioned"):
        _bedrock_agent({"bedrock": {"guardrail": dict(_SHIPPED)}})


def test_agent_init_binds_published_guardrail_under_strict(monkeypatch):
    monkeypatch.setattr(prov, "strict_posture", lambda config=None: True)
    agent = _bedrock_agent({"bedrock": {"guardrail": {
        "guardrail_identifier": "abc123def456", "guardrail_version": "4"}}})
    assert agent._bedrock_guardrail_config == {
        "guardrailIdentifier": "abc123def456", "guardrailVersion": "4"}
