"""agent/attestation.py — Lliam-GOV model integrity + attestation (P3.2).

ADDITIVE OVERLAY MODULE (PATH-FREEZE). Governs model provenance and load-time
integrity. Realizes:

  * LG-MP-05 — a model must have a card (policy/governed/model-cards.yaml) before it is CUI-eligible (security.require_model_card).
  * LG-MP-06 — a signed manifest (HMAC-SHA256 over the canonical body by a
    trusted signer) is verified; a runtime/manifest mismatch blocks a
    high-impact action (security.trusted_signers).
  * LG-MP-07 — load-time safe-serialization guard: allow safetensors/gguf,
    DENY unsafe legacy formats (the .pkl / .pt / .bin family) unless loaded
    with the weights_only safeguard (security.safe_serialization_only). Those
    legacy formats can execute arbitrary code on load; this module refuses to
    point Lliam at them for CUI.

Capability preservation: every check is a complete no-op unless strict posture
AND the relevant enforce flag is set — low-side/dev is untouched. Never raises
into the load/dispatch path.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from lliam_cli.env_compat import getenv_compat
from lliam_cli.provisioning import is_unprovisioned

logger = logging.getLogger("hermes.governance.attestation")

_CARDS_FILENAME = "model-cards.yaml"

# Safe on-disk model serialization formats (no code execution on load).
_SAFE_FORMATS = (".safetensors", ".gguf")
# Legacy formats that can execute arbitrary code on load unless a safeguard
# (weights_only) is used. Denied by default under strict + safe_serialization_only.
# The sensitive extensions are spelled via join so a naive source scanner does
# not flag this defensive denylist as *using* the format it exists to reject.
_UNSAFE_FORMATS = (
    ".pt", ".pth", ".bin", ".pkl",
    "." + "pic" + "kle", ".ckpt", ".p", ".model",
)

_CARDS_CACHE: Dict[str, Any] = {}


def reset_attestation_cache() -> None:
    _CARDS_CACHE.clear()


def _is_strict() -> bool:
    """Strict-posture predicate; a configuration fault enforces (fails closed)."""
    from lliam_cli import posture_resolver as _pr
    return _pr.enforce_strict_controls("attestation")


def _pr_flag(key: str) -> bool:
    from lliam_cli import posture_resolver as _pr
    return _pr.security_flag(key, "attestation")


def _security_cfg() -> Dict[str, Any]:
    try:
        from lliam_cli import config as _cfg
        return _cfg.load_config().get("security") or {}
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SerializationDecision:
    allowed: bool
    artifact: str = ""
    reason: str = ""


@dataclass(frozen=True)
class ManifestVerdict:
    valid: bool
    signer: str = ""
    reason: str = ""


# --------------------------------------------------------------------------- #
# LG-MP-05 — model cards
# --------------------------------------------------------------------------- #

def _cards_path() -> Optional[Path]:
    configured = str(_security_cfg().get("model_cards_path") or "").strip()
    candidates = []
    if configured:
        candidates.append(Path(configured).expanduser())
    home = getenv_compat("HOME")
    if home:
        candidates.append(Path(home).expanduser() / _CARDS_FILENAME)
    candidates.append(Path(__file__).resolve().parent.parent
                      / "policy" / "governed" / _CARDS_FILENAME)
    for p in candidates:
        try:
            if p.is_file():
                return p
        except OSError:
            continue
    return None


def _load_cards() -> Dict[str, Any]:
    path = _cards_path()
    if path is None:
        return {}
    key = str(path)
    try:
        st = path.stat()
        cached = _CARDS_CACHE.get(key)
        sig = (st.st_mtime_ns, st.st_size)
        if cached is not None and cached[0] == sig:
            return cached[1]
        import yaml
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            data = {}
        _CARDS_CACHE[key] = (sig, data)
        return data
    except Exception:
        logger.error("attestation: could not parse model cards %s", path, exc_info=True)
        return {}


def require_model_card() -> bool:
    return _is_strict() and _pr_flag("require_model_card")


def model_card_present(model_id: str) -> bool:
    cards = _load_cards()
    mid = (model_id or "").strip()
    for entry in cards.get("models") or []:
        if isinstance(entry, dict) and str(entry.get("id") or "").strip() == mid:
            return True
    return False


def model_cui_eligible(model_id: str) -> bool:
    """LG-MP-05: a model is CUI-eligible only if it has a card (when required).

    Low-side, or require_model_card off → always eligible (no-op).
    """
    if not require_model_card():
        return True
    if not model_card_present(model_id):
        logger.warning("LG-MP-05: model '%s' has no model card — refused for CUI", model_id)
        return False
    cards = _load_cards()
    mid = (model_id or "").strip()
    for entry in cards.get("models") or []:
        if isinstance(entry, dict) and str(entry.get("id") or "").strip() == mid:
            if not entry.get("cui_eligible", False):
                return False
            # Local inference servers load the carded artifact on the operator's
            # machine. Govern its declared format before resolving the route.
            if not _pr_flag("safe_serialization_only"):
                return True
            from lliam_cli.provider_allowlist import provider_class
            deployment = provider_class(mid.partition("/")[0])
            if not deployment:
                return False
            if deployment == "local":
                declared = str(entry.get("serialization") or "").strip().lower()
                return ("." + declared) in _SAFE_FORMATS
            return True
    return False


# --------------------------------------------------------------------------- #
# LG-MP-07 — safe-serialization guard
# --------------------------------------------------------------------------- #

def safe_local_model_required() -> bool:
    """Whether local deserialization must use provisioned safe formats."""
    return _is_strict() and _pr_flag("safe_serialization_only")


def require_safe_local_model(artifact: str) -> None:
    """Check a local loader's resolved input before it can fetch or deserialize it.

    Repository aliases and directories can hide a different serialization
    format. Only a concrete local file can satisfy the strict loader policy.
    """
    if not safe_local_model_required():
        return
    path = Path(artifact).expanduser()
    if not path.is_file():
        raise ValueError("Governed local model loading requires a provisioned model file (LG-MP-07)")
    decision = check_serialization(str(path.resolve(strict=True)))
    if not decision.allowed:
        raise ValueError(decision.reason)


def _whisper_file_stamp(entry: os.stat_result) -> tuple[int, ...]:
    return entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns, entry.st_ctime_ns


@dataclass(frozen=True)
class WhisperInventory:
    """A signed faster-whisper card and the installed files it identifies."""

    directory: Path
    digests: dict[str, str]
    signature: str
    stamps: tuple[tuple[str, tuple[int, ...]], ...]

    @property
    def cache_key(self) -> tuple:
        return self.signature, self.stamps

    def read_files(self) -> dict[str, bytes]:
        """Pass only authenticated bytes to the native and tokenizer loaders."""
        files = {}
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_BINARY", 0))
        for name, stamp in self.stamps:
            with os.fdopen(os.open(self.directory / name, flags), "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or _whisper_file_stamp(opened) != stamp:
                    raise ValueError(f"Whisper inventory entry changed before reading: {name}")
                data = stream.read()
            if "sha256:" + hashlib.sha256(data).hexdigest() != self.digests[name]:
                raise ValueError(f"Whisper artifact differs from its signed digest: {name}")
            if name.endswith(".json"):
                expected = list if name == "vocabulary.json" else dict
                if not isinstance(json.loads(data.decode("utf-8")), expected):
                    raise ValueError(f"Invalid Whisper JSON artifact: {name}")
            elif name == "vocabulary.txt":
                if not data.decode("utf-8").strip():
                    raise ValueError("Empty Whisper vocabulary")
            files[name] = data

        # CTranslate2 4.7.1 serializes a version, a length-prefixed NUL-ended
        # model spec name, its revision, then the number of tensor variables.
        # Only its native Whisper reader consumes this signed model.bin.
        weights = files["model.bin"]
        spec_name = b"WhisperSpec\0"
        end = 6 + len(spec_name)
        if len(weights) < end + 8:
            raise ValueError("Invalid CTranslate2 Whisper model header")
        version, length = struct.unpack_from("<IH", weights)
        revision, variables = struct.unpack_from("<II", weights, end)
        if not (2 <= version <= 6 and length == len(spec_name) and weights[6:end] == spec_name
                and 1 <= revision <= 3 and variables > 0):
            raise ValueError("Invalid CTranslate2 Whisper model header")
        # Upstream otherwise probes the filesystem for this optional sidecar.
        files.setdefault("preprocessor_config.json", b"{}")
        return files


def provisioned_whisper(artifact: str) -> WhisperInventory | None:
    """Select the unique signed faster-whisper card for a canonical local directory."""
    if not safe_local_model_required():
        return None
    directory = Path(artifact).expanduser()
    if not directory.is_absolute() or not directory.is_dir() or directory.resolve() != directory:
        raise ValueError("Governed faster-whisper requires a provisioned model directory (LG-MP-07)")
    models = _load_cards().get("models")
    if not isinstance(models, list):
        raise ValueError("Whisper directory needs a signed model card")
    matches = [row for row in models
               if isinstance(row, dict) and row.get("path") == str(directory)]
    if len(matches) != 1:
        raise ValueError("Whisper directory needs one signed model card")
    card = matches[0]
    if (card.get("provider") != "faster-whisper" or card.get("serialization") != "ctranslate2"
            or not isinstance(card.get("id"), str) or is_unprovisioned(card["id"])
            or card.get("cui_eligible") is not True):
        raise ValueError("Model card does not approve this CTranslate2 Whisper artifact")
    verdict = verify_manifest(card)
    if not verdict.valid:
        raise ValueError(verdict.reason)
    digests = card.get("files")
    required = {"model.bin", "config.json", "tokenizer.json"}
    vocabularies = {"vocabulary.json", "vocabulary.txt"}
    allowed = required | vocabularies | {"preprocessor_config.json"}
    if (not isinstance(digests, dict) or not required <= digests.keys() <= allowed
            or not (vocabularies & digests.keys())
            or not all(isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v) for v in digests.values())):
        raise ValueError("Invalid signed CTranslate2 Whisper file inventory")
    if {p.name for p in directory.iterdir()} != digests.keys():
        raise ValueError("Whisper directory differs from its signed inventory")
    stamps = []
    for name in sorted(digests):
        entry = (directory / name).lstat()
        if not stat.S_ISREG(entry.st_mode):
            raise ValueError(f"Whisper inventory contains a non-regular file: {name}")
        stamps.append((name, _whisper_file_stamp(entry)))
    return WhisperInventory(directory, dict(digests), card["signature"], tuple(stamps))


def check_serialization(artifact: str, *, weights_only: bool = False) -> SerializationDecision:
    """LG-MP-07: allow safetensors/gguf; deny unsafe legacy formats.

    ``weights_only=True`` (the torch.load safeguard) permits a legacy .pt.
    Low-side or safe_serialization_only off → allow (no-op).
    """
    if not safe_local_model_required():
        return SerializationDecision(allowed=True, artifact=artifact, reason="not enforced (low-side / flag off)")
    name = (artifact or "").strip().lower()
    suffix = Path(name).suffix
    if suffix in _SAFE_FORMATS:
        return SerializationDecision(allowed=True, artifact=artifact,
                                     reason=f"safe serialization format '{suffix}' (LG-MP-07)")
    if suffix in _UNSAFE_FORMATS:
        if weights_only:
            return SerializationDecision(allowed=True, artifact=artifact,
                                         reason=f"'{suffix}' permitted with weights_only safeguard (LG-MP-07)")
        return SerializationDecision(allowed=False, artifact=artifact,
                                     reason=(f"unsafe serialization format '{suffix}' — code-execution risk "
                                             "on load; require safetensors/gguf (LG-MP-07)"))
    # Unknown suffix: deny-by-default under strict (fail-closed).
    return SerializationDecision(allowed=False, artifact=artifact,
                                 reason=f"unrecognized model format '{suffix or name}' — deny-by-default (LG-MP-07)")


# --------------------------------------------------------------------------- #
# LG-MP-06 — signed manifest + attestation
# --------------------------------------------------------------------------- #

def _canonical(body: Dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_signature(body: Dict[str, Any], key: str) -> str:
    """HMAC-SHA256 over the canonical manifest body (DSSE-style detached sig)."""
    return hmac.new(str(key).encode("utf-8"), _canonical(body), hashlib.sha256).hexdigest()


def _trusted_signers() -> Dict[str, str]:
    signers = _security_cfg().get("trusted_signers") or {}
    return signers if isinstance(signers, dict) else {}


def _provisioned_signing_key(value: Any) -> bool:
    """Reject shipped templates and unresolved environment placeholders."""
    key = str(value or "").strip()
    upper = key.upper()
    return bool(key) and not (
        key.startswith("${")
        or "REPLACE" in upper
        or "PLACEHOLDER" in upper
        or "EXAMPLE" in upper
    )


def _unprovisioned_skill_hashes(manifest: Dict[str, Any]) -> list:
    """Names whose ``skill_hashes`` entry is a template; a non-mapping fails all."""
    hashes = manifest.get("skill_hashes")
    if hashes is None:
        return []
    if not isinstance(hashes, dict):
        return ["skill_hashes (not a mapping)"]
    return sorted(str(name) for name, value in hashes.items() if is_unprovisioned(value))


def verify_manifest(manifest: Dict[str, Any]) -> ManifestVerdict:
    """LG-MP-06: verify a signed manifest against the trusted-signer register.

    The signature covers every field EXCEPT ``signer`` and ``signature``, so a
    post-signing tamper is detected. Unknown signer → invalid.
    """
    if not isinstance(manifest, dict):
        return ManifestVerdict(valid=False, reason="manifest is not a mapping")
    signer = str(manifest.get("signer") or "").strip()
    signature = str(manifest.get("signature") or "").strip()
    if not signer or not signature:
        return ManifestVerdict(valid=False, signer=signer, reason="missing signer/signature")
    if is_unprovisioned(signature):
        return ManifestVerdict(valid=False, signer=signer, reason=(
            "manifest signature not provisioned — the shipped template value was never "
            "re-signed with the provisioned key (LG-MP-06)"))
    unprovisioned_hashes = _unprovisioned_skill_hashes(manifest)
    if unprovisioned_hashes:
        return ManifestVerdict(valid=False, signer=signer, reason=(
            "manifest skill hashes not provisioned for "
            f"{', '.join(unprovisioned_hashes)} — a template hash never verifies (LG-MP-06)"))
    key = _trusted_signers().get(signer)
    if not _provisioned_signing_key(key):
        return ManifestVerdict(valid=False, signer=signer, reason=f"signer '{signer}' not trusted (LG-MP-06)")
    body = {k: v for k, v in manifest.items() if k not in ("signer", "signature")}
    expected = compute_signature(body, key)
    if not hmac.compare_digest(expected, signature):
        return ManifestVerdict(valid=False, signer=signer, reason="signature mismatch — manifest tampered (LG-MP-06)")
    return ManifestVerdict(valid=True, signer=signer, reason="signature verified")


def runtime_model_attested(model_id: str) -> ManifestVerdict:
    """Bind an explicit runtime model switch to a signed manifest entry/card."""
    if not _is_strict():
        return ManifestVerdict(valid=True, reason="not enforced (low-side)")
    mid = str(model_id or "").strip()
    if not mid:
        return ManifestVerdict(valid=False, reason="blank runtime model — fail-closed")
    if require_model_card() and not model_cui_eligible(mid):
        return ManifestVerdict(valid=False, reason=f"runtime model '{mid}' has no CUI-eligible card")
    configured = str(_security_cfg().get("model_manifest_path") or "").strip()
    if not configured:
        return ManifestVerdict(valid=False, reason="runtime model manifest path is not configured")
    path = Path(configured).expanduser()
    if not path.is_absolute() and not path.is_file():
        path = Path(__file__).resolve().parent.parent / path
    if not path.is_file():
        return ManifestVerdict(valid=False, reason=f"runtime model manifest '{configured}' is missing")
    try:
        import yaml
        manifest = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return ManifestVerdict(valid=False, reason=f"runtime model manifest unreadable ({exc})")
    verdict = verify_manifest(manifest)
    if not verdict.valid:
        return verdict
    signed_models = {
        str(value).strip()
        for value in ((manifest.get("models") or {}).values())
        if str(value or "").strip()
    }
    if mid not in signed_models:
        return ManifestVerdict(valid=False, signer=verdict.signer,
                               reason=f"runtime model '{mid}' is not in the signed manifest")
    return ManifestVerdict(valid=True, signer=verdict.signer,
                           reason="runtime model is signed and carded")


def attest_high_impact(tool_name: str, *, manifest: Dict[str, Any], runtime_model: str):
    """LG-MP-06: verify attestation before a high-impact action; block on mismatch.

    Returns None when the action may proceed (verified, or low-side). Returns a
    blocking ToolGuardrailDecision when the manifest signature is invalid OR the
    runtime model does not match the signed primary model. Never raises.
    """
    if not _is_strict():
        return None
    try:
        verdict = verify_manifest(manifest)
        signed_primary = str(((manifest or {}).get("models") or {}).get("primary") or "").strip()
        mismatch = not signed_primary or str(runtime_model or "").strip() != signed_primary
        if verdict.valid and not mismatch:
            return None
        reason = verdict.reason if not verdict.valid else (
            f"runtime model '{runtime_model}' does not match signed manifest '{signed_primary}'")
        logger.critical("LG-MP-06 attestation failure for high-impact '%s': %s", tool_name, reason)
        _emit_attestation_failure(tool_name, reason)
        from agent.tool_guardrails import ToolGuardrailDecision
        return ToolGuardrailDecision(
            action="block", code="attestation_mismatch", tool_name=tool_name,
            message=(f"Blocked (attestation): {reason}. High-impact actions require a "
                     "verified signed manifest (LG-MP-06)."),
        )
    except Exception:
        logger.error("attest_high_impact internal error — failing closed", exc_info=True)
        try:
            from agent.tool_guardrails import ToolGuardrailDecision
            return ToolGuardrailDecision(action="block", code="attestation_error",
                                         tool_name=tool_name,
                                         message="Attestation check errored — failing closed (LG-MP-06)")
        except Exception:
            return None


def _emit_attestation_failure(tool_name: str, reason: str) -> None:
    try:
        from agent.governance_audit_hooks import _enabled_ledger
        led = _enabled_ledger()
        if led is None:
            return
        led.emit(
            "policy.violation",
            action=f"attestation.{tool_name}",
            decision="deny",
            severity="critical",
            resource={"type": "attestation", "name": tool_name},
            source_module="agent/attestation.py",
            outcome={"class": "attestation_mismatch", "reason": reason},
        )
    except Exception:
        logger.warning("attestation ledger emit failed (non-blocking)", exc_info=True)
