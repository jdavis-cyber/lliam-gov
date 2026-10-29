"""lliam_cli/provisioning.py — explicit detection of unprovisioned values.

ADDITIVE OVERLAY MODULE. The governed overlay ships template values that the
owner provisions out of repo: the model-manifest ``signature`` and
``skill_hashes`` (LG-MP-06), and the Bedrock guardrail identifier/version.
A template value must never verify, or be handed to a provider, as if it were
real. This module names the template shapes in one place so every consumer
can refuse them with a clear "not provisioned" reason instead of an incidental
downstream failure (e.g. an HMAC mismatch that reads like tampering, or a
provider-side validation error).

Consumers:
  * agent/attestation.py — manifest signature + skill hashes (LG-MP-06)
  * lliam_cli/runtime_provider.py, agent/agent_init.py — Bedrock guardrail
    binding (via :func:`bedrock_guardrail_config`)

Capability preservation: under a non-strict posture the Bedrock guardrail
binding behaves exactly as before (a placeholder is only logged).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Mapping, Optional

logger = logging.getLogger("lliam.governance.provisioning")

# Substrings that only ever appear in shipped templates, never in a real
# signature (hex), digest (hex) or Bedrock guardrail id ([a-z0-9]{12}).
_TEMPLATE_TOKENS = (
    "REPLACE", "PLACEHOLDER", "RECOMPUTE", "UNPROVISIONED", "CHANGEME", "EXAMPLE",
)
# ``<bedrock-guardrail-id>`` / ``AWS-GOVCLOUD-ATO-<id>`` style slots.
_ANGLE_SLOT = re.compile(r"<[^<>]*>")
# A published Bedrock guardrail version. ``DRAFT`` is the mutable working
# draft, so it is not accepted as a provisioned binding under strict posture.
_PUBLISHED_GUARDRAIL_VERSION = re.compile(r"^[1-9][0-9]*$")


class UnprovisionedValueError(RuntimeError):
    """A governed value is still a shipped template under strict posture."""

    def __init__(self, message: str, *, field: str = "") -> None:
        super().__init__(message)
        self.field = field


def is_unprovisioned(value: Any) -> bool:
    """True when ``value`` is blank, an unresolved ``${ENV}`` reference, an
    angle-bracket slot, or carries a template token (REPLACE / PLACEHOLDER /
    RECOMPUTE / UNPROVISIONED / CHANGEME / EXAMPLE)."""
    if value is None:
        return True
    text = str(value).strip()
    if not text or text.lower() in {"none", "null"}:
        return True
    if "${" in text or _ANGLE_SLOT.search(text):
        return True
    upper = text.upper()
    return any(token in upper for token in _TEMPLATE_TOKENS)


def strict_posture(config: Optional[Mapping[str, Any]] = None) -> bool:
    """Effective strict posture; a posture-resolution fault enforces."""
    try:
        from lliam_cli import posture_resolver as _pr
        if config is None:
            from lliam_cli import config as _cfg
            config = _cfg.load_config()
        return bool(_pr.is_strict(dict(config)))
    except Exception:
        logger.warning("provisioning: posture resolution failed; enforcing", exc_info=True)
        return True


def bedrock_guardrail_config(
    guardrail: Optional[Mapping[str, Any]], *, strict: bool
) -> Optional[Dict[str, Any]]:
    """Build the Bedrock ``guardrailConfig`` from a ``bedrock.guardrail`` block.

    No identifier and no version → ``None`` (no guardrail configured), as
    before. Under strict posture a binding that is only partly set, uses a
    template identifier, or pins the mutable ``DRAFT`` / a template version
    raises :class:`UnprovisionedValueError` — it is never sent to Bedrock.
    Non-strict keeps the previous pass-through behaviour.
    """
    gr = guardrail if isinstance(guardrail, Mapping) else {}
    identifier = gr.get("guardrail_identifier")
    version = gr.get("guardrail_version")
    if not identifier and not version:
        return None

    if strict:
        if is_unprovisioned(identifier):
            raise UnprovisionedValueError(
                f"Bedrock guardrail not provisioned: bedrock.guardrail.guardrail_identifier "
                f"{identifier!r} is blank or a template value. Set the real guardrail id "
                "before routing to Bedrock under strict posture.",
                field="bedrock.guardrail.guardrail_identifier",
            )
        version_text = str(version or "").strip()
        if not _PUBLISHED_GUARDRAIL_VERSION.match(version_text):
            raise UnprovisionedValueError(
                f"Bedrock guardrail not provisioned: bedrock.guardrail.guardrail_version "
                f"{version!r} is not a published version number (DRAFT is the mutable "
                "working draft). Pin a published guardrail version under strict posture.",
                field="bedrock.guardrail.guardrail_version",
            )
    elif identifier and version and (is_unprovisioned(identifier) or is_unprovisioned(version)):
        logger.warning(
            "bedrock.guardrail carries a template value (%r / %r); Bedrock will reject it",
            identifier, version,
        )

    if not (identifier and version):
        return None
    config: Dict[str, Any] = {
        "guardrailIdentifier": identifier,
        "guardrailVersion": version,
    }
    if gr.get("stream_processing_mode"):
        config["streamProcessingMode"] = gr["stream_processing_mode"]
    if gr.get("trace"):
        config["trace"] = gr["trace"]
    return config
