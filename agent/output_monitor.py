"""Deployed-output bias/toxicity + PII/CUI egress monitor (LG-PF-08/09, P5.2).

Post-deployment output monitoring: samples/scores generated output for bias
and toxic content (LG-PF-08) and detects PII/CUI in outbound content, blocking
egress to an unapproved sink (LG-PF-09). Additive and capability-preserving:

  * ``scan_output(text, sink=...)`` returns an :class:`OutputVerdict`.
  * A bias/toxicity finding is **detect-and-log** (alerts, does not block) —
    generated content is not censored, it is flagged for the LG-MO-09 metrics
    and the appeal/recourse channel (LG-HO-09).
  * PII/CUI is **blocked only for an egress sink** (network/external send);
    the same content to an internal workspace sink is allowed (the agent must
    still be able to work with CUI it legitimately processes). This composes
    with the existing DLP taint gate (LG-DP-10) and the LG-PI-09 sink check —
    it does not rename or replace them.

Detection is pattern-based (SSN, CUI markings, obvious toxicity/bias markers);
it is a monitor, not a classifier — the objective is a high-recall egress
tripwire and a governance-metrics signal, not content moderation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# Egress sinks where PII/CUI must be blocked (LG-PF-09). Internal sinks
# (workspace, memory) are not egress and are allowed.
_EGRESS_SINKS = frozenset({
    "network.egress", "external_send", "web", "browser", "email", "mcp",
})

# PII / CUI markers (high-recall tripwire; not exhaustive classification).
_PII_CUI_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                 # SSN
    re.compile(r"\bCUI//[A-Z/-]+\b"),                     # CUI portion marking
    re.compile(r"\bCUI\b(?=\s*(//|:|-|\bSP\b))"),         # CUI banner
    re.compile(r"\b\d{16}\b"),                            # PAN-length digit run
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
]

# Bias / toxicity markers (detect-and-log signal for LG-PF-08 / MO-09 metrics).
_TOXICITY_PATTERNS = [
    re.compile(r"\b(idiot|stupid|worthless|inferior|ashamed of you)\b", re.I),
    re.compile(r"\ball\s+(members\s+of\s+)?(that|those)\s+(group|people)\s+"
               r"are\b", re.I),
    re.compile(r"\b(inherently|genetically)\s+(inferior|superior)\b", re.I),
]


@dataclass(frozen=True)
class OutputVerdict:
    bias_or_toxicity: bool
    pii_or_cui: bool
    block: bool
    reasons: tuple[str, ...] = ()


def _is_egress(sink: str) -> bool:
    return str(sink).strip() in _EGRESS_SINKS


def scan_output(text: str, *, sink: str = "") -> OutputVerdict:
    """Scan generated output. Blocks only PII/CUI to an egress sink."""
    content = text or ""
    reasons: list[str] = []

    toxic = any(p.search(content) for p in _TOXICITY_PATTERNS)
    if toxic:
        reasons.append("LG-PF-08: bias/toxicity marker in generated output")

    pii = any(p.search(content) for p in _PII_CUI_PATTERNS)
    if pii:
        reasons.append("LG-PF-09: PII/CUI marker in generated output")

    block = bool(pii and _is_egress(sink))
    if block:
        reasons.append(f"LG-PF-09: egress to '{sink}' blocked (PII/CUI present)")

    return OutputVerdict(bias_or_toxicity=toxic, pii_or_cui=pii,
                         block=block, reasons=tuple(reasons))
