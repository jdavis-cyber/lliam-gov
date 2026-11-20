"""P3.2 — Model integrity: cards, attestation, safe-serialization (LG-MP-05/06/07/08).

NEW agent/attestation.py governs model provenance and load-time integrity:
  * LG-MP-05 — a model must have a card (policy/governed/model-cards.yaml)
    before it is CUI-eligible (security.require_model_card).
  * LG-MP-06 — a signed manifest (HMAC over the canonical body by a trusted
    signer) is verified at startup and before high-impact actions; mismatch
    blocks (security.trusted_signers).
  * LG-MP-07 — load-time safe-serialization guard: allow safetensors/gguf,
    DENY unsafe formats (.pt/.bin without weights_only) (security.safe_serialization_only).
No-op on low-side postures (capability preserving).
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest


_CARDS = textwrap.dedent(
    """
    models:
      - id: "lmstudio/llama-3.1-8b-instruct"
        serialization: safetensors
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


@pytest.mark.parametrize("key", [
    "REPLACE-WITH-PROVISIONED-SIGNING-KEY",
    "${LLIAM_GOV_SIGNING_KEY}",
    "EXAMPLE-KEY",
])
def test_placeholder_signing_keys_are_never_trusted(strict_att, monkeypatch, key):
    monkeypatch.setattr(strict_att, "_trusted_signers", lambda: {"lliam-gov-signer": key})
    body = {"models": {"primary": "lmstudio/llama-3.1-8b-instruct"}}
    manifest = _signed_manifest(strict_att, body, key=key)
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


# ---------------------------------------------------------------------------
# 4. JER-78 — shipped template signature / skill hashes never verify
# ---------------------------------------------------------------------------

_REPO_MANIFEST = Path(__file__).resolve().parents[2] / "model_manifest.yaml"


def test_shipped_repo_manifest_never_verifies_even_with_a_trusted_key(strict_att):
    import yaml

    manifest = yaml.safe_load(_REPO_MANIFEST.read_text(encoding="utf-8"))
    verdict = strict_att.verify_manifest(manifest)
    assert verdict.valid is False
    assert "not provisioned" in verdict.reason


@pytest.mark.parametrize("signature", [
    "REPLACE-WITH-PROVISIONED-SIGNATURE",
    "${LLIAM_GOV_MANIFEST_SIGNATURE}",
    "<signature>",
])
def test_template_signature_reports_not_provisioned_not_tamper(strict_att, signature):
    manifest = {"signer": "lliam-gov-signer", "signature": signature,
                "models": {"primary": "lmstudio/llama-3.1-8b-instruct"}}
    verdict = strict_att.verify_manifest(manifest)
    assert verdict.valid is False
    assert "signature not provisioned" in verdict.reason
    assert "tampered" not in verdict.reason


def test_genuinely_signed_manifest_with_template_skill_hashes_fails(strict_att):
    body = {"models": {"primary": "lmstudio/llama-3.1-8b-instruct"},
            "skill_hashes": {"pdf": "sha256:PLACEHOLDER-recompute-at-build",
                             "xlsx": "sha256:" + "ab" * 32}}
    manifest = _signed_manifest(strict_att, body)   # real HMAC over the template
    verdict = strict_att.verify_manifest(manifest)
    assert verdict.valid is False
    assert "skill hashes not provisioned for pdf" in verdict.reason


def test_non_mapping_skill_hashes_fail_closed(strict_att):
    body = {"models": {"primary": "lmstudio/llama-3.1-8b-instruct"},
            "skill_hashes": ["sha256:" + "ab" * 32]}
    verdict = strict_att.verify_manifest(_signed_manifest(strict_att, body))
    assert verdict.valid is False
    assert "not provisioned" in verdict.reason


def test_high_impact_blocked_on_template_signature(strict_att):
    manifest = {"signer": "lliam-gov-signer",
                "signature": "REPLACE-WITH-PROVISIONED-SIGNATURE",
                "models": {"primary": "lmstudio/llama-3.1-8b-instruct"}}
    decision = strict_att.attest_high_impact(
        "terminal", manifest=manifest, runtime_model="lmstudio/llama-3.1-8b-instruct")
    assert decision is not None and decision.should_halt
    assert "not provisioned" in decision.message


def test_runtime_model_switch_refused_against_shipped_manifest(strict_att, monkeypatch):
    cfg = strict_att._security_cfg()
    cfg = {"security": {**cfg, "model_manifest_path": str(_REPO_MANIFEST)}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    verdict = strict_att.runtime_model_attested("lmstudio/llama-3.1-8b-instruct")
    assert verdict.valid is False
    assert "not provisioned" in verdict.reason


def test_governed_local_transcription_refuses_unverified_model_before_install(strict_att, monkeypatch, tmp_path):
    from tools import transcription_tools as speech

    monkeypatch.setattr(speech, "_HAS_FASTER_WHISPER", False)
    monkeypatch.setattr(speech, "_try_lazy_install_stt",
                        lambda: pytest.fail("model refusal must precede optional installation"))
    result = speech._transcribe_local(str(tmp_path / "unused.wav"), "unprovisioned-alias")
    assert result["success"] is False
    assert "provisioned model directory" in result["error"]


@pytest.fixture
def whisper_bundle(strict_att, tmp_path, monkeypatch):
    import hashlib
    import struct
    import sys
    import types

    import yaml

    from tools import transcription_tools as speech

    directory = tmp_path / "whisper"
    directory.mkdir()
    weights = struct.pack("<IH12sII", 6, 12, b"WhisperSpec\0", 3, 1) + b"fixture weights"
    for name, data in {"model.bin": weights, "config.json": b"{}", "tokenizer.json": b'{"model":{}}',
                       "vocabulary.txt": b"fixture\n"}.items():
        (directory / name).write_bytes(data)
    card = {
        "path": str(directory), "id": "fixture-whisper", "provider": "faster-whisper",
        "serialization": "ctranslate2", "cui_eligible": True,
        "files": {p.name: "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()},
    }

    def write_card():
        signature = strict_att.compute_signature(card, "s3cr3t-signing-key-001")
        (tmp_path / "model-cards.yaml").write_text(yaml.safe_dump({"models": [
            {**card, "signature": signature, "signer": "lliam-gov-signer"},
        ]}), encoding="utf-8")
        strict_att.reset_attestation_cache()

    write_card()
    audio = tmp_path / "sample.wav"
    audio.write_bytes(b"fixture audio")
    runtime = types.ModuleType("faster_whisper")
    monkeypatch.setattr(runtime, "WhisperModel", lambda *a, **kw: pytest.fail("unapproved runtime load"), raising=False)
    monkeypatch.setitem(sys.modules, "faster_whisper", runtime)
    monkeypatch.setattr(speech, "_HAS_FASTER_WHISPER", True)
    monkeypatch.setattr(speech, "_try_lazy_install_stt", lambda: pytest.fail("offline STT attempted installation"))
    monkeypatch.setattr(speech, "_local_model", None)
    monkeypatch.setattr(speech, "_local_model_name", None)
    monkeypatch.setattr(speech, "_load_stt_config", lambda: {"provider": "local", "local": {"model": str(directory)}})
    return directory, card, write_card, runtime, lambda: speech.transcribe_audio(str(audio))


@pytest.mark.parametrize("fallback", ["none", "construction", "transcription"])
def test_governed_whisper_transcribes_with_only_signed_bytes(whisper_bundle, monkeypatch, fallback):
    from types import SimpleNamespace

    directory, card, _, runtime, transcribe = whisper_bundle
    devices = []

    def constructor(path, *, device, compute_type, local_files_only, files):
        assert path == str(directory) and local_files_only
        assert files == {**{f: (directory / f).read_bytes() for f in card["files"]}, "preprocessor_config.json": b"{}"}
        files.pop("tokenizer.json")
        devices.append(device)
        if device == "auto" and fallback == "construction":
            raise RuntimeError("libcublas.so.12: cannot open shared object file")

        def decode(path, **kwargs):
            if device == "auto" and fallback == "transcription":
                raise RuntimeError("libcublas.so.12: cannot open shared object file")
            return [SimpleNamespace(text=" reviewed audio ")], SimpleNamespace(language="en", duration=0.2)

        return SimpleNamespace(transcribe=decode)

    monkeypatch.setattr(runtime, "WhisperModel", constructor)
    assert transcribe() == {"success": True, "transcript": "reviewed audio", "provider": "local"}
    assert transcribe()["success"]
    assert devices == (["auto"] if fallback == "none" else ["auto", "cpu"])
    (directory / "model.bin").write_bytes(b"updated fixture")
    assert not transcribe()["success"]


@pytest.mark.parametrize("field,value", [
    ("provider", "other"), ("serialization", "gguf"), ("cui_eligible", False),
])
def test_governed_whisper_requires_a_backend_specific_approval(whisper_bundle, field, value):
    _, card, sign, _, transcribe = whisper_bundle
    card[field] = value
    sign()
    assert "does not approve" in transcribe()["error"]


@pytest.mark.parametrize("filename", ["weights.pt", "../config.json"])
def test_governed_whisper_rejects_unsafe_inventory_names(whisper_bundle, filename):
    _, card, sign, _, transcribe = whisper_bundle
    card["files"][filename] = card["files"]["model.bin"]
    sign()
    assert "Invalid signed" in transcribe()["error"]


def test_governed_whisper_requires_offline_tokenizer(whisper_bundle):
    directory, card, sign, _, transcribe = whisper_bundle
    (directory / "tokenizer.json").unlink()
    del card["files"]["tokenizer.json"]
    sign()
    assert "Invalid signed" in transcribe()["error"]


def test_governed_whisper_rejects_extra_files_and_symlinks(whisper_bundle):
    directory, _, _, _, transcribe = whisper_bundle
    extra = directory / "notes.txt"
    extra.write_text("extra", encoding="utf-8")
    assert "differs from its signed inventory" in transcribe()["error"]
    extra.unlink()
    target = directory.parent / "config.json"
    (directory / "config.json").rename(target)
    (directory / "config.json").symlink_to(target)
    assert "non-regular file" in transcribe()["error"]


def test_governed_whisper_checks_digest_and_native_binary_format(whisper_bundle):
    import hashlib

    directory, card, sign, _, transcribe = whisper_bundle
    data = b"ordinary fixture text"
    (directory / "model.bin").write_bytes(data)
    assert "signed digest" in transcribe()["error"]
    card["files"]["model.bin"] = "sha256:" + hashlib.sha256(data).hexdigest()
    sign()
    assert "Whisper model header" in transcribe()["error"]


@pytest.mark.parametrize("state", ["missing", "directory", "malformed", "blank", "null"])
def test_whisper_an_explicit_index_cannot_fall_back(whisper_bundle, strict_att, monkeypatch, state):
    directory, card, _, _, transcribe = whisper_bundle
    # The legacy home lookup contains a valid signed card for this exact directory.
    monkeypatch.setenv("LLIAM_HOME", str(directory.parent))
    selected = directory.parent / "selected.yaml"
    if state == "directory":
        selected.mkdir()
    elif state == "malformed":
        selected.write_text("models: [", encoding="utf-8")
    configured = {"blank": " ", "null": None}.get(state, str(selected))
    monkeypatch.setitem(strict_att._security_cfg(), "model_cards_path", configured)
    result = transcribe()
    assert not result["success"]
    assert "configured Whisper model-card index" in result["error"]
    if state in {"missing", "directory", "blank", "null"}:
        assert strict_att.model_card_present(card["id"])


@pytest.mark.parametrize("location", ["working_directory", "installation"])
def test_whisper_resolves_the_configured_relative_index(whisper_bundle, strict_att, monkeypatch, location):
    directory, _, _, _, _ = whisper_bundle
    install, cwd = directory.parent / "installation", directory.parent / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(strict_att, "__file__", str(install / "agent" / "attestation.py"))
    relative = Path("policy/governed/model-cards.yaml")
    selected = (cwd if location == "working_directory" else install) / relative
    selected.parent.mkdir(parents=True)
    selected.write_bytes((directory.parent / "model-cards.yaml").read_bytes())
    monkeypatch.setitem(strict_att._security_cfg(), "model_cards_path", str(relative))
    assert strict_att.provisioned_whisper(str(directory)).directory == directory


def test_governed_whisper_requires_signed_approval(whisper_bundle, strict_att):
    import yaml

    directory, card, _, _, transcribe = whisper_bundle
    (directory.parent / "model-cards.yaml").write_text(yaml.safe_dump({"models": [card]}), encoding="utf-8")
    strict_att.reset_attestation_cache()
    assert "missing signer/signature" in transcribe()["error"]


def test_governed_whisper_never_installs_missing_runtime(whisper_bundle, monkeypatch):
    from tools import transcription_tools as speech

    directory, _, _, _, _ = whisper_bundle
    monkeypatch.setattr(speech, "_HAS_FASTER_WHISPER", False)
    assert "not installed" in speech._transcribe_local("unused.wav", str(directory))["error"]


def test_governed_voice_refuses_unknown_serialization_before_loading(strict_att, monkeypatch, tmp_path):
    from tools import tts_tool

    candidate = tmp_path / "test.onnx"
    candidate.touch()
    monkeypatch.setattr(tts_tool, "_import_piper", lambda: None)
    with pytest.raises(ValueError, match="unrecognized model format"):
        tts_tool._generate_piper_tts("test", str(tmp_path / "unused.wav"), {
            "piper": {"voice": str(candidate), "voices_dir": str(tmp_path)}
        })


def test_runtime_local_model_card_requires_approved_serialization(strict_att, tmp_path):
    card = tmp_path / "model-cards.yaml"
    card.write_text(_CARDS.replace("serialization: safetensors", "serialization: unsupported"))
    strict_att.reset_attestation_cache()
    assert not strict_att.model_cui_eligible("lmstudio/llama-3.1-8b-instruct")
    assert strict_att.model_cui_eligible("bedrock/anthropic.claude-3-5-sonnet")


def test_governed_piper_refused_before_download(strict_att, tmp_path, monkeypatch):
    from tools import tts_tool
    monkeypatch.setattr(tts_tool, "_import_piper", lambda: object())
    monkeypatch.setattr(tts_tool.subprocess, "run", lambda *a, **kw: pytest.fail("unexpected voice download"))
    with pytest.raises(ValueError):
        tts_tool._generate_piper_tts("test", str(tmp_path / "out.wav"),
                                     {"piper": {"voice": "sample", "voices_dir": str(tmp_path)}})


def test_governed_stt_discovery_leaves_local_install_to_the_loader(strict_att, monkeypatch):
    from tools import transcription_tools as stt
    monkeypatch.setattr(stt, "_HAS_FASTER_WHISPER", False)
    monkeypatch.setattr(stt, "_has_local_command", lambda: False)
    monkeypatch.setattr(stt, "_try_lazy_install_stt", lambda: pytest.fail("installation during discovery"))
    stt._get_provider({"provider": "local"})
    stt._get_provider({})


def test_governed_neutts_validates_codec_in_originating_profile(strict_att, monkeypatch, tmp_path):
    from tools import tts_tool
    backbone = tmp_path / "sample.gguf"
    backbone.touch()
    monkeypatch.setattr(tts_tool.subprocess, "run", lambda *a, **kw: pytest.fail("unexpected child"))
    with pytest.raises(ValueError, match="verified local codec"):
        tts_tool._generate_neutts("review", "spoken.wav", {"neutts": {"model": str(backbone)}})


def test_governed_neutts_missing_package_reports_codec_policy(strict_att, monkeypatch, tmp_path):
    from tools import tts_tool

    monkeypatch.setattr(tts_tool, "_check_neutts_available", lambda: False)
    monkeypatch.setattr(tts_tool, "_load_tts_config", lambda: {"provider": "neutts"})
    result = json.loads(tts_tool.text_to_speech_tool("review", str(tmp_path / "voice.wav")))
    assert result["success"] is False
    assert "verified local codec" in result["error"]
    assert "pip install" not in result["error"]


def test_standalone_governed_neutts_reports_codec_policy_before_reading_reference(strict_att, monkeypatch):
    import sys
    from tools import neutts_synth

    monkeypatch.setattr(sys, "argv", ["neutts_synth", "--text", "review", "--out", "voice.wav",
                                      "--ref-audio", "absent.wav", "--ref-text", "absent.txt"])
    with pytest.raises(ValueError, match="verified local codec"):
        neutts_synth.main()


def test_neutts_child_resolves_source_modules_and_relative_files(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from tools import tts_tool
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("agent.attestation._is_strict", lambda: False)
    calls = []
    def child(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(tts_tool.subprocess, "run", child)
    tts_tool._generate_neutts("review", "spoken.wav", {"neutts": {"ref_audio": "sample.wav", "ref_text": "sample.txt"}})
    (args, kwargs), = calls
    assert args[1:3] == ["-m", "tools.neutts_synth"]
    assert (Path(kwargs["cwd"]) / "agent/attestation.py").is_file()
    for flag, basename in (("--ref-audio", "sample.wav"), ("--ref-text", "sample.txt"), ("--out", "spoken.wav")):
        assert Path(args[args.index(flag) + 1]) == tmp_path / basename
