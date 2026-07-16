"""P3.2 — model-integrity startup gate (LG-MP-05/06).

Fail-closed at startup under strict posture when: (a) the signed manifest's
signature is invalid / untrusted (LG-MP-06), or (b) the configured primary
model lacks a model card while require_model_card is set (LG-MP-05). Advisory
when non-strict. Mirrors the P3.1 provider-allowlist gate.
"""

from __future__ import annotations

import textwrap

import pytest

import agent.attestation as att
import lliam_cli.security_audit_startup as sas


_CARDS = textwrap.dedent(
    """
    models:
      - id: "lmstudio/llama-3.1-8b-instruct"
        cui_eligible: true
    """
)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    att.reset_attestation_cache()
    monkeypatch.setattr(sas, "_MODEL_INTEGRITY_CHECKED", False, raising=False)
    yield
    att.reset_attestation_cache()


def _write(tmp_path):
    cards = tmp_path / "model-cards.yaml"
    cards.write_text(_CARDS, encoding="utf-8")
    manifest = tmp_path / "model_manifest.yaml"
    return cards, manifest


def _signed_manifest_file(tmp_path, primary, key="k-001", signer="lliam-gov-signer"):
    _cards, manifest = _write(tmp_path)
    body = {"models": {"primary": primary}}
    sig = att.compute_signature(body, key)
    import yaml
    manifest.write_text(yaml.safe_dump({"signer": signer, "signature": sig, **body}), encoding="utf-8")
    return manifest


def _cfg(tmp_path, *, primary_model, manifest, key="k-001"):
    cards = tmp_path / "model-cards.yaml"
    cards.write_text(_CARDS, encoding="utf-8")
    return {"security": {
        "posture": "strict",
        "require_model_card": True,
        "model_cards_path": str(cards),
        "model_manifest_path": str(manifest),
        "trusted_signers": {"lliam-gov-signer": key},
        "provider_allowlist_enforce": True,
    }, "model": {"provider": "lmstudio", "model": primary_model}}


def test_valid_manifest_and_carded_model_passes(tmp_path, monkeypatch):
    manifest = _signed_manifest_file(tmp_path, "lmstudio/llama-3.1-8b-instruct")
    cfg = _cfg(tmp_path, primary_model="lmstudio/llama-3.1-8b-instruct", manifest=manifest)
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    assert sas.enforce_model_integrity_at_startup(config=cfg) is None


def test_tampered_manifest_blocks(tmp_path, monkeypatch):
    manifest = _signed_manifest_file(tmp_path, "lmstudio/llama-3.1-8b-instruct")
    # Corrupt the manifest signature.
    import yaml
    data = yaml.safe_load(manifest.read_text())
    data["signature"] = "deadbeef"
    manifest.write_text(yaml.safe_dump(data), encoding="utf-8")
    cfg = _cfg(tmp_path, primary_model="lmstudio/llama-3.1-8b-instruct", manifest=manifest)
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    with pytest.raises(sas.ModelIntegrityError, match="manifest|signature"):
        sas.enforce_model_integrity_at_startup(config=cfg)


def test_uncarded_primary_model_blocks(tmp_path, monkeypatch):
    manifest = _signed_manifest_file(tmp_path, "lmstudio/uncarded")
    cfg = _cfg(tmp_path, primary_model="lmstudio/uncarded", manifest=manifest)
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    with pytest.raises(sas.ModelIntegrityError, match="card"):
        sas.enforce_model_integrity_at_startup(config=cfg)


def test_low_side_does_not_block(tmp_path, monkeypatch):
    manifest = _signed_manifest_file(tmp_path, "lmstudio/uncarded")
    cfg = _cfg(tmp_path, primary_model="lmstudio/uncarded", manifest=manifest)
    cfg["security"]["posture"] = "permissive"
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    assert sas.enforce_model_integrity_at_startup(config=cfg) is None
