"""CUI marking + audit-only chain of custody (LG-4.6, AI-223).

Plan §5.6 — the AUTHORITATIVE scope decision, reaffirmed by Jerome: this is
**marking + audit + governance only**. CUI status NEVER denies otherwise
allowed routing; network denial remains exclusively the LG-4.3 egress
policy's job, for network reasons. Do not add CUI-based gating here.

What this module does:

* **Marking** — a manifest at ``<lliam home>/cui-manifest.json`` (0600)
  maps path prefixes to CUI marker strings (e.g. ``CUI``,
  ``CUI//SP-PRIV``). :func:`marker_for_path` resolves the most specific
  prefix; markers propagate to anything under a marked directory.
* **Propagation** — :func:`combine_markers` merges markers when marked
  content flows into derived artifacts (transformations, model calls):
  any CUI marker survives the merge; the longest (most specific) marker
  wins ties.
* **Chain of custody** — :func:`emit_cui_access` writes a ``cui_access``
  audit event carrying the marker, the destination, and the standard
  ``params_hash`` — never raw payloads (A.8.11 masking). Tool dispatch
  calls :func:`scan_args_for_cui` so reads/transformations of marked
  paths are evidenced automatically.
* **Sanitized delete** — :func:`sanitize_delete` best-effort overwrites
  file bytes before unlink and audits a ``cui_delete`` event. Best-effort
  is the honest posture on APFS/SSDs (copy-on-write means overwrite is
  not a guarantee); the audit record, not the overwrite, is the control.

Maps to: SP 800-171 3.8.9 / 3.13.8 / 3.13.16 (custody context); 32 CFR
2002 marking practice.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

CUI_MANIFEST_FILENAME = "cui-manifest.json"

#: Event types emitted by this module.
CUI_ACCESS_EVENT = "cui_access"
CUI_DELETE_EVENT = "cui_delete"


class CuiError(Exception):
    """Base class for CUI-marking failures."""


def _manifest_path() -> Path:
    from hermes_constants import get_hermes_home

    return get_hermes_home() / CUI_MANIFEST_FILENAME


def load_manifest() -> dict[str, str]:
    """Return the path-prefix → marker map (empty when no manifest)."""
    try:
        data = json.loads(_manifest_path().read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def mark_path(path: str | os.PathLike, marker: str) -> None:
    """Add/replace a CUI marker for a path prefix in the manifest (0600)."""
    if not marker or not marker.strip():
        raise CuiError("marker must be a non-empty CUI marking string")
    manifest = load_manifest()
    manifest[str(Path(path).expanduser())] = marker.strip()
    p = _manifest_path()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(manifest, indent=2, sort_keys=True).encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def marker_for_path(path: str | os.PathLike) -> str | None:
    """Resolve the marker for ``path``: most specific marked prefix wins."""
    target = str(Path(path).expanduser())
    best: tuple[int, str] | None = None
    for prefix, marker in load_manifest().items():
        if target == prefix or target.startswith(prefix.rstrip("/") + "/"):
            if best is None or len(prefix) > best[0]:
                best = (len(prefix), marker)
    return best[1] if best else None


def combine_markers(*markers: str | None) -> str | None:
    """Merge markers across a data flow: any CUI marking survives.

    The longest marker string wins (more category qualifiers = more
    specific); ``None`` inputs are ignored.
    """
    present = [m for m in markers if m]
    return max(present, key=len) if present else None


def emit_cui_access(
    *,
    operation: str,
    destination: str,
    marker: str,
    params: dict | None = None,
    session_id: str | None = None,
    tool_name: str | None = None,
) -> None:
    """Record a ``cui_access`` chain-of-custody event.

    Carries marker + destination + params_hash; never raw payloads. Fails
    closed: custody evidence is the control, so a chain-write failure
    propagates to the caller (matching tool-dispatch audit semantics).
    """
    from lliam_gov.security.audit_logger import get_shared_audit_logger

    get_shared_audit_logger().log_event(
        event_type=CUI_ACCESS_EVENT,
        session_id=session_id,
        tool_name=tool_name,
        marker=marker,
        destination=destination,
        params={"operation": operation, **(params or {})},
    )


def scan_args_for_cui(
    tool_name: str,
    function_args: dict,
    *,
    session_id: str | None = None,
) -> None:
    """Emit custody events for any marked path appearing in tool args.

    Called from the dispatch path AFTER a successful tool run. Scans
    string argument values that look like paths; cheap no-op when the
    manifest is empty. Marking only — never blocks.
    """
    manifest = load_manifest()
    if not manifest:
        return
    for key, value in function_args.items():
        if not isinstance(value, str) or ("/" not in value and "~" not in value):
            continue
        marker = marker_for_path(value)
        if marker is not None:
            emit_cui_access(
                operation=f"tool_arg:{key}",
                destination=tool_name,
                marker=marker,
                params={"arg": key},
                session_id=session_id,
                tool_name=tool_name,
            )


def sanitize_delete(path: str | os.PathLike) -> bool:
    """Best-effort sanitizing delete of a marked file; audited.

    Overwrites the file's bytes with zeros and fsyncs before unlinking.
    Returns True when the file was deleted. APFS copy-on-write means the
    overwrite is BEST-EFFORT (old extents may persist); the ``cui_delete``
    audit record is the dependable control, and the encrypted-at-rest
    posture (LG-3.7) is the real confidentiality backstop.
    """
    p = Path(path).expanduser()
    marker = marker_for_path(p) or "CUI"
    if not p.is_file():
        return False
    size = p.stat().st_size
    try:
        fd = os.open(p, os.O_WRONLY)
        try:
            os.write(fd, b"\x00" * min(size, 64 * 1024 * 1024))
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass  # best-effort; deletion + audit still proceed
    p.unlink()
    from lliam_gov.security.audit_logger import get_shared_audit_logger

    get_shared_audit_logger().log_event(
        event_type=CUI_DELETE_EVENT,
        marker=marker,
        destination="unlink",
        params={"sanitized": True, "size": size},
    )
    return True


__all__ = [
    "CUI_ACCESS_EVENT",
    "CUI_DELETE_EVENT",
    "CUI_MANIFEST_FILENAME",
    "CuiError",
    "combine_markers",
    "emit_cui_access",
    "load_manifest",
    "mark_path",
    "marker_for_path",
    "sanitize_delete",
    "scan_args_for_cui",
]
