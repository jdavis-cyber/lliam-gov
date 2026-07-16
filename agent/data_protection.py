"""agent/data_protection.py — Lliam-GOV data protection + DLP taint-gate (P2.4).

ADDITIVE OVERLAY MODULE (PATH-FREEZE). Realizes the data-protection controls
not already covered by the P0/P1 redaction (LG-DP-03/05), TLS (LG-DP-06), and
think-scrub (LG-DP-09) surfaces:

  * LG-DP-01 — classify content as CUI vs public and drive differential
    handling from the tag.
  * LG-DP-02 — detect + preserve CUI banner / portion markings.
  * LG-DP-04 — CUI/PII pattern pack (SSN, DOB, CUI banner lines).
  * LG-DP-10 — DLP taint-gate: once CUI is exposed in a session, block egress
    to a NON-allowlisted sink until the taint clears (the step's key control).
  * LG-DP-07/08 — at-rest encryption wrapper (Fernet) keyed from a store denied
    to first-party file tools (<lliam_home>/keys, on the write-denylist).
  * LG-DP-11 — output masking + retention-TTL accessor for tool results.

Capability preservation: every classification is ``public`` and the taint-gate
is a no-op on low-side postures; the DLP gate only blocks egress AFTER real CUI
exposure AND only to non-allowlisted sinks — an untainted session, or egress to
an allowlisted sink, is never blocked.
"""

from __future__ import annotations

import logging
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hermes.governance.data_protection")


# --------------------------------------------------------------------------- #
# CUI / PII pattern pack (LG-DP-04)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class PatternHit:
    kind: str
    span: str


# Each: (kind, compiled regex). Deliberately conservative — high-signal PII +
# the CUI banner. Tunable per deployment via security.cui_redaction.extra.
_CUI_PII_PATTERNS = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("dob", re.compile(r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b")),
    ("cui_banner", re.compile(r"(?m)^\s*(?:CUI|CONTROLLED)\b.*$")),
    ("cui_portion", re.compile(r"\(\s*CUI\s*\)")),
]

# Banner / portion markings to detect + preserve (LG-DP-02).
_MARKING_RE = re.compile(r"(?m)^\s*(CUI(?://[A-Z/\-]+)?)\s*$")


@dataclass(frozen=True)
class Classification:
    level: str                        # cui | public
    markings: List[str] = field(default_factory=list)
    hits: List[PatternHit] = field(default_factory=list)


# DLP state is keyed by runtime session. The default key preserves compatibility
# for CLI callers without an explicit identity while gateway sessions remain
# isolated from one another.
_STATES: Dict[str, Dict[str, bool]] = {}


def _state(session_id: Optional[str] = None) -> Dict[str, bool]:
    return _STATES.setdefault(str(session_id or "default"), {"cui_tainted": False})


def _is_strict() -> bool:
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr
        return _pr.is_strict(_cfg.load_config())
    except Exception:
        return False


def _security_cfg() -> dict:
    try:
        from lliam_cli import config as _cfg
        return _cfg.load_config().get("security") or {}
    except Exception:
        return {}


def reset_dp_state(session_id: Optional[str] = None) -> None:
    if session_id is None:
        _STATES.clear()
    else:
        _STATES.pop(str(session_id or "default"), None)


def _classification_text(value: Any) -> str:
    """Flatten structured tool results before classification.

    Tool dispatch returns JSON strings, so scanning only the serialized first
    line misses a CUI banner nested in fields such as ``content``.
    """
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (TypeError, ValueError):
            return value
        if decoded == value:
            return value
        return _classification_text(decoded)
    if isinstance(value, dict):
        return "\n".join(
            _classification_text(item) for item in value.values()
            if item is not None
        )
    if isinstance(value, (list, tuple, set)):
        return "\n".join(_classification_text(item) for item in value)
    return str(value or "")


def cui_pii_matches(text: str) -> List[PatternHit]:
    """LG-DP-04: return CUI/PII pattern hits in text ([] if none / low-side)."""
    if not text or not _is_strict():
        return []
    hits: List[PatternHit] = []
    for kind, rx in _CUI_PII_PATTERNS:
        m = rx.search(text)
        if m:
            hits.append(PatternHit(kind=kind, span=m.group(0)[:64]))
    return hits


def classify_content(text: Any) -> Classification:
    """LG-DP-01/02: classify content CUI vs public + capture markings.

    CUI when it carries a CUI banner/portion marking OR any PII pattern hit.
    No-op (public) on low-side postures.
    """
    text = _classification_text(text)
    if not text or not _is_strict():
        return Classification(level="public")
    markings = [m.group(1) for m in _MARKING_RE.finditer(text)]
    hits = cui_pii_matches(text)
    level = "cui" if (markings or hits) else "public"
    return Classification(level=level, markings=markings, hits=hits)


# --------------------------------------------------------------------------- #
# DLP taint-gate (LG-DP-10)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class DlpDecision:
    blocked: bool
    reason: str = ""


def note_cui_exposure(
    source: str, text: Any, *, session_id: Optional[str] = None
) -> bool:
    """Taint the session if ``text`` is CUI (LG-DP-10). Returns True if tainted."""
    if not _is_strict():
        return False
    if classify_content(text).level == "cui":
        state = _state(session_id)
        if not state["cui_tainted"]:
            logger.warning(
                "LG-DP-10: CUI exposed in session via '%s' — DLP egress gate armed",
                source,
            )
        state["cui_tainted"] = True
        return True
    return False


def session_cui_tainted(*, session_id: Optional[str] = None) -> bool:
    return bool(_state(session_id)["cui_tainted"])


def _host_allowlisted(destination: str, allowlist: List[str]) -> bool:
    from urllib.parse import urlparse

    parsed = urlparse(destination if "://" in (destination or "") else f"//{destination}")
    dest = (parsed.hostname or "").lower().rstrip(".")
    for entry in allowlist or []:
        e = str(entry).strip().lower().lstrip("*.").rstrip(".")
        if e and (dest == e or dest.endswith("." + e)):
            return True
    return False


def dlp_egress_decision(
    destination: str,
    *,
    allowlist: Optional[List[str]] = None,
    session_id: Optional[str] = None,
) -> DlpDecision:
    """LG-DP-10: block a CUI-tainted session from a non-allowlisted egress sink.

    Untainted sessions and allowlisted sinks are never blocked (capability).
    ``allowlist`` defaults to security.data_protection.egress_allowlist; the
    full destination allowlist policy is P2.5 — this gate composes with it.
    """
    if not _is_strict() or not session_cui_tainted(session_id=session_id):
        return DlpDecision(blocked=False)
    if allowlist is None:
        allowlist = list((_security_cfg().get("data_protection") or {}).get("egress_allowlist") or [])
    if _host_allowlisted(destination, allowlist):
        return DlpDecision(blocked=False, reason="allowlisted CUI sink")
    return DlpDecision(
        blocked=True,
        reason=(
            "CUI-tainted session may not egress to non-allowlisted sink "
            f"'{destination}' (LG-DP-10) — route to an approved destination or "
            "clear the session"
        ),
    )


# --------------------------------------------------------------------------- #
# Output masking + retention (LG-DP-11)
# --------------------------------------------------------------------------- #

def mask_tool_result(text: str) -> str:
    """LG-DP-11/DP-03: mask secrets + CUI/PII in a tool result. No-op low-side."""
    if not text or not _is_strict():
        return text
    try:
        from agent.redact import redact_sensitive_text
        text = redact_sensitive_text(text, force=True)
    except Exception:
        logger.warning("mask_tool_result redaction unavailable", exc_info=True)
    for kind, rx in _CUI_PII_PATTERNS:
        text = rx.sub(f"[REDACTED-{kind.upper()}]", text)
    return text


def result_retention_ttl_seconds() -> Optional[int]:
    """LG-DP-11: configured retention TTL for stored tool results (or None)."""
    try:
        ttl = (_security_cfg().get("data_protection") or {}).get("result_retention_ttl_seconds")
        return int(ttl) if ttl is not None else None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# At-rest encryption wrapper (LG-DP-07/08)
# --------------------------------------------------------------------------- #

def _lliam_home() -> Path:
    from lliam_cli.env_compat import getenv_compat
    home = getenv_compat("HOME") or os.path.expanduser("~/.lliam")
    return Path(home).expanduser()


def at_rest_keyfile_path() -> Path:
    """The at-rest key store path — under <lliam_home>/keys (write-denied)."""
    override = os.environ.get("LLIAM_AT_REST_KEYFILE")
    if override:
        return Path(override).expanduser()
    return _lliam_home() / "keys" / "at-rest.key"


def ensure_at_rest_key() -> bytes:
    """LG-DP-08: ensure a Fernet key exists in the write-denied key store.

    The portable keyfile is generated mode 0600 and denied to first-party file
    tools. It is defense in depth inside the process, not an OS isolation
    boundary; deployments should supply an external secret manager/keychain.
    """
    from cryptography.fernet import Fernet

    path = at_rest_keyfile_path()
    if path.is_file():
        return path.read_bytes().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def encrypt_at_rest(data: bytes) -> bytes:
    """LG-DP-07: encrypt CUI/audit bytes at rest with the managed key."""
    from cryptography.fernet import Fernet

    return Fernet(ensure_at_rest_key()).encrypt(data)


def decrypt_at_rest(token: bytes) -> bytes:
    from cryptography.fernet import Fernet

    return Fernet(ensure_at_rest_key()).decrypt(token)
