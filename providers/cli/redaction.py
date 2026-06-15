"""Secret/credential redaction for provider subprocess boundaries (AI-334).

Lliam-GOV never reads or stores provider tokens — but provider CLIs can echo
secrets into their own stdout/stderr (e.g. an error that prints a bearer token,
or a stray ``ANTHROPIC_API_KEY=...`` in a stack trace). This module scrubs such
material before any provider output reaches a log sink or an audit record.

Design rules:

* Pure, dependency-free, and side-effect-free so it can be unit-tested
  exhaustively and called from hot paths.
* Conservative: it errs toward over-redaction. False positives only cost a
  ``«redacted»`` marker; false negatives could leak a credential.
* It is *not* a substitute for the env allowlist or the no-token-read rule — it
  is the last line of defence on the logging/audit surface only.
"""

from __future__ import annotations

import re

REDACTION_MARKER = "«redacted»"

# Ordered, conservative patterns. Each captures a *prefix* group we keep so the
# log still says *what kind* of secret was scrubbed without revealing it.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # key=value / token: value style assignments for sensitive-looking names.
    (
        re.compile(
            r"(?i)(\b[A-Z0-9_]*"
            r"(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|BEARER|CREDENTIAL|"
            r"SESSION[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH)"
            r"\s*[:=]\s*)([^\s'\"]+)"
        ),
        r"\1" + REDACTION_MARKER,
    ),
    # Authorization: Bearer <token> headers.
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]{8,}"), r"\1" + REDACTION_MARKER),
    # Provider-style key prefixes (OpenAI sk-, Anthropic sk-ant-, GitHub, Slack).
    (re.compile(r"\bsk-ant-[A-Za-z0-9._\-]{6,}"), REDACTION_MARKER),
    (re.compile(r"\bsk-[A-Za-z0-9]{16,}"), REDACTION_MARKER),
    (re.compile(r"\bgh[posru]_[A-Za-z0-9]{20,}"), REDACTION_MARKER),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), REDACTION_MARKER),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTION_MARKER),
    (re.compile(r"\bya29\.[A-Za-z0-9._\-]{10,}"), REDACTION_MARKER),  # Google OAuth
    # JWTs (three base64url segments).
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}"),
        REDACTION_MARKER,
    ),
)


def redact_secrets(text: str | None) -> str:
    """Return ``text`` with credential-like substrings replaced by a marker.

    Safe on ``None`` (returns ``""``). Idempotent: redacting already-redacted
    text leaves the marker intact.
    """
    if not text:
        return ""
    out = text
    for pattern, repl in _PATTERNS:
        out = pattern.sub(repl, out)
    return out


def redacted_snippet(text: str | None, *, limit: int = 240) -> str:
    """Redact then truncate to ``limit`` chars for compact audit/log lines."""
    red = redact_secrets(text)
    if len(red) <= limit:
        return red
    return red[:limit] + "…[truncated]"
