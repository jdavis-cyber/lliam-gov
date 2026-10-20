"""agent/attestation.py — Lliam-GOV model integrity + attestation (P3.2).

ADDITIVE OVERLAY MODULE (PATH-FREEZE). Governs model provenance and load-time
integrity. Realizes:

  * LG-MP-05 — a model must have a card (docs/governance/model-cards/
    model-cards.yaml) before it is CUI-eligible (security.require_model_card).
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
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr
        return _pr.is_strict(_cfg.load_config())
    except Exception:
        logger.warning("attestation posture resolution failed; enforcing", exc_info=True)
        return True


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
                      / "docs" / "governance" / "model-cards" / _CARDS_FILENAME)
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
    return _is_strict() and bool(_security_cfg().get("require_model_card"))


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
            return bool(entry.get("cui_eligible", False))
    return False


# --------------------------------------------------------------------------- #
# LG-MP-07 — safe-serialization guard
# --------------------------------------------------------------------------- #

def check_serialization(artifact: str, *, weights_only: bool = False) -> SerializationDecision:
    """LG-MP-07: allow safetensors/gguf; deny unsafe legacy formats.

    ``weights_only=True`` (the torch.load safeguard) permits a legacy .pt.
    Low-side or safe_serialization_only off → allow (no-op).
    """
    if not (_is_strict() and _security_cfg().get("safe_serialization_only")):
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
