"""P3.2 — Model integrity: cards, attestation, safe-serialization (LG-MP-05/06/07/08).

NEW agent/attestation.py governs model provenance and load-time integrity:
  * LG-MP-05 — a model must have a card (docs/governance/model-cards/model-cards.yaml)
    before it is CUI-eligible (security.require_model_card).
  * LG-MP-06 — a signed manifest (HMAC over the canonical body by a trusted
    signer) is verified at startup and before high-impact actions; mismatch
    blocks (security.trusted_signers).
  * LG-MP-07 — load-time safe-serialization guard: allow safetensors/gguf,
    DENY unsafe formats (.pt/.bin without weights_only) (security.safe_serialization_only).
No-op on low-side postures (capability preserving).
"""

from __future__ import annotations

import textwrap

import pytest


_CARDS = textwrap.dedent(
    """
    models:
      - id: "lmstudio/llama-3.1-8b-instruct"
        architecture: "llama-3.1"
        context_window: 128000
        acceptable_contexts: ["coding", "analysis"]
        cui_eligible: true
      - id: "bedrock/anthropic.claude-3-5-sonnet"
        architecture: "claude-3.5"
        context_window: 200000
        acceptable_contexts: ["coding", "analysis", "cui"]
        cui_eligible: true
    """
)


@pytest.fixture
def strict_att(tmp_path, monkeypatch):
    cards = tmp_path / "model-cards.yaml"
    cards.write_text(_CARDS, encoding="utf-8")
    cfg = {"security": {
        "posture": "strict",
        "require_model_card": True,
        "safe_serialization_only": True,
        "model_hash_verify": True,
        "model_cards_path": str(cards),
        "trusted_signers": {"lliam-gov-signer": "s3cr3t-signing-key-001"},
    }}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import agent.attestation as att

    att.reset_attestation_cache()
    yield att
    att.reset_attestation_cache()


# ---------------------------------------------------------------------------
# 1. LG-MP-05 — model card required for CUI eligibility
# ---------------------------------------------------------------------------

def test_carded_model_is_cui_eligible(strict_att):
    assert strict_att.model_cui_eligible("lmstudio/llama-3.1-8b-instruct") is True


def test_uncarded_model_refused_for_cui(strict_att):
    d = strict_att.model_cui_eligible("lmstudio/mystery-uncarded-model")
    assert d is False


def test_low_side_never_requires_card(monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    import agent.attestation as att

    att.reset_attestation_cache()
    assert att.model_cui_eligible("anything/uncarded") is True  # no-op low-side
    att.reset_attestation_cache()


# ---------------------------------------------------------------------------
# 2. LG-MP-07 — safe-serialization guard
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("artifact", [
    "model.safetensors", "weights.gguf", "/models/llama.safetensors",
])
def test_safe_formats_allowed(strict_att, artifact):
    d = strict_att.check_serialization(artifact)
    assert d.allowed is True


@pytest.mark.parametrize("artifact", [
    "model.pt", "weights.bin", "archive.pkl", "checkpoint.ckpt",
])
def test_unsafe_formats_denied(strict_att, artifact):
    d = strict_att.check_serialization(artifact)
    assert d.allowed is False
    assert "safe" in d.reason.lower() or "format" in d.reason.lower()


def test_pt_with_weights_only_flag_allowed(strict_att):
    d = strict_att.check_serialization("model.pt", weights_only=True)
    assert d.allowed is True


def test_low_side_allows_any_format(monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    import agent.attestation as att

    att.reset_attestation_cache()
    assert att.check_serialization("archive.pkl").allowed is True  # no-op
    att.reset_attestation_cache()


# ---------------------------------------------------------------------------
# 3. LG-MP-06 — signed manifest + attestation
# ---------------------------------------------------------------------------

def _signed_manifest(att, body, signer="lliam-gov-signer", key="s3cr3t-signing-key-001"):
    sig = att.compute_signature(body, key)
    return {"signer": signer, "signature": sig, **body}


def test_valid_manifest_signature_verifies(strict_att):
    body = {"models": {"primary": "lmstudio/llama-3.1-8b-instruct@v1"},
            "skill_hashes": {"pdf": "abc123"}}
    manifest = _signed_manifest(strict_att, body)
    assert strict_att.verify_manifest(manifest).valid is True


def test_tampered_manifest_fails(strict_att):
    body = {"models": {"primary": "lmstudio/llama-3.1-8b-instruct@v1"}}
    manifest = _signed_manifest(strict_att, body)
    manifest["models"]["primary"] = "evil/backdoor@v9"   # tamper after signing
    assert strict_att.verify_manifest(manifest).valid is False


def test_untrusted_signer_fails(strict_att):
    body = {"models": {"primary": "x@v1"}}
    manifest = _signed_manifest(strict_att, body, signer="rogue", key="whatever")
    assert strict_att.verify_manifest(manifest).valid is False


def test_high_impact_blocked_on_attestation_mismatch(strict_att):
    body = {"models": {"primary": "lmstudio/llama-3.1-8b-instruct@v1"}}
    good = _signed_manifest(strict_att, body)
    # Runtime reports a different model than the signed manifest → block.
    decision = strict_att.attest_high_impact(
        "terminal", manifest=good, runtime_model="evil/backdoor@v9")
    assert decision is not None and decision.should_halt


def test_high_impact_allowed_when_attestation_matches(strict_att):
    body = {"models": {"primary": "lmstudio/llama-3.1-8b-instruct@v1"}}
    good = _signed_manifest(strict_att, body)
    decision = strict_att.attest_high_impact(
        "terminal", manifest=good, runtime_model="lmstudio/llama-3.1-8b-instruct@v1")
    assert decision is None


def test_low_side_attestation_never_blocks(monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    import agent.attestation as att

    att.reset_attestation_cache()
    decision = att.attest_high_impact("terminal", manifest={}, runtime_model="anything")
    assert decision is None  # no-op low-side
    att.reset_attestation_cache()
