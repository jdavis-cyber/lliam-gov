"""agent/memory_governance.py — Lliam-GOV memory governance (P2.6).

ADDITIVE OVERLAY MODULE (PATH-FREEZE). Governs persistent memory as controlled
knowledge. MC-01 (sanitize-before-memory) and MC-03 (provenance) already ship
at P0.5/P1.2; MC-04 staged write-approval is on since P0.2. This module adds:

  * LG-MC-02 — per-session/identity partitioned memory paths + permission-aware
    visibility (a session's memory is not visible to another session, and never
    across identities).
  * LG-MC-04 — a CRITICAL memory write requires HITL (composes with the
    existing tools/write_approval.py staging gate).
  * LG-MC-05 — purpose-limited retention TTL + PII-exclusion policy.
  * LG-MC-06 — secure purge (best-effort overwrite, then unlink).
  * LG-MC-07 — reset/wipe a session's memory partition between unrelated tasks.

Capability preservation: on low-side postures partitioning collapses to the
shipped single store, nothing is swept or excluded, and no write is gated —
a complete no-op. The clock is injectable (``now=``) so tests are deterministic.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hermes.governance.memory_governance")

# Write kinds that are "critical" and must route to HITL under strict posture
# (LG-MC-04). Everything else stages/flows per the existing write_approval gate.
_CRITICAL_WRITE_KINDS = frozenset({"critical", "identity", "policy", "cross_session"})


def _is_strict() -> bool:
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr
        return _pr.is_strict(_cfg.load_config())
    except Exception:
        logger.warning(
            "memory-governance posture resolution failed; enforcing strict controls",
            exc_info=True,
        )
        return True


# --------------------------------------------------------------------------- #
# LG-MC-02 — partitioning + visibility
# --------------------------------------------------------------------------- #

def _safe_component(value: str) -> str:
    """A filesystem-safe partition component (no traversal, bounded)."""
    v = "".join(c for c in str(value or "") if c.isalnum() or c in ("-", "_"))
    return (v or "default")[:128]


def partition_path(base: Path, *, session_id: str, identity: str = "default") -> Path:
    """Per-identity/session memory partition under ``base`` (LG-MC-02).

    Low-side: returns ``base`` unchanged (shipped single-store behavior).
    Strict: ``base/partitions/<identity>/<session_id>`` so concurrent sessions
    and identities do not share a store.
    """
    base = Path(base)
    if not _is_strict():
        return base
    return base / "partitions" / _safe_component(identity) / _safe_component(session_id)


def entry_visible(entry: Dict[str, Any], *, session_id: str, identity: str = "default") -> bool:
    """LG-MC-02 permission-aware visibility for a stored entry.

    An entry is visible when it belongs to the same identity AND either the same
    session or an explicitly ``shared`` scope. Cross-identity is never visible.
    Low-side: everything visible (shipped behavior).
    """
    if not _is_strict():
        return True
    if str(entry.get("identity") or "default") != str(identity or "default"):
        return False
    if str(entry.get("scope") or "session") == "shared":
        return True
    return str(entry.get("session_id") or "") == str(session_id or "")


# --------------------------------------------------------------------------- #
# LG-MC-04 — critical-write HITL
# --------------------------------------------------------------------------- #

def write_requires_hitl(kind: str = "routine") -> bool:
    """True when a memory write of ``kind`` must route to HITL (LG-MC-04)."""
    if not _is_strict():
        return False
    return str(kind or "routine").strip().lower() in _CRITICAL_WRITE_KINDS


# --------------------------------------------------------------------------- #
# LG-MC-05 — retention TTL + PII exclusion
# --------------------------------------------------------------------------- #

def sweep_expired(
    entries: List[Dict[str, Any]],
    *,
    ttl_seconds: int,
    now: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """Return entries within the retention TTL; drop expired (LG-MC-05).

    Each entry carries a ``ts`` epoch-seconds field. Low-side: no sweep.
    ``now`` is injectable for deterministic tests.
    """
    if not _is_strict():
        return entries
    if now is None:
        import time
        now = time.time()
    kept: List[Dict[str, Any]] = []
    for e in entries:
        try:
            ts = float(e.get("ts", 0))
        except (TypeError, ValueError):
            ts = 0.0
        if now - ts <= ttl_seconds:
            kept.append(e)
    dropped = len(entries) - len(kept)
    if dropped:
        logger.info("LG-MC-05 retention sweep: purged %d expired memory entr(ies)", dropped)
    return kept


def pii_excluded(content: str) -> bool:
    """LG-MC-05: True when content carries PII and must NOT be persisted.

    Reuses the P2.4 CUI/PII pattern pack. Low-side: never excludes.
    """
    if not _is_strict() or not content:
        return False
    try:
        from agent.data_protection import cui_pii_matches
        return bool(cui_pii_matches(content))
    except Exception:
        logger.warning("memory PII classifier unavailable; excluding content", exc_info=True)
        return True


# --------------------------------------------------------------------------- #
# LG-MC-06 / MC-07 — secure purge + context reset
# --------------------------------------------------------------------------- #

def secure_purge(path: Path) -> None:
    """Best-effort secure delete: overwrite bytes then unlink (LG-MC-06).

    No-op if the path is absent. Never raises. Directory trees are purged
    recursively (files overwritten, then the tree removed).
    """
    p = Path(path)
    try:
        if p.is_dir():
            for child in sorted(p.rglob("*"), reverse=True):
                if child.is_file():
                    _overwrite_and_unlink(child)
                elif child.is_dir():
                    try:
                        child.rmdir()
                    except OSError:
                        pass
            try:
                p.rmdir()
            except OSError:
                pass
        elif p.is_file():
            _overwrite_and_unlink(p)
    except Exception:
        logger.warning("secure_purge failed for %s", p, exc_info=True)


def _overwrite_and_unlink(f: Path) -> None:
    try:
        size = f.stat().st_size
        with open(f, "r+b") as fh:
            fh.write(os.urandom(size) if size else b"")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    try:
        f.unlink()
    except OSError:
        pass


def reset_session_context(base: Path, *, session_id: str, identity: str = "default") -> None:
    """LG-MC-07: securely purge one session's memory partition between tasks."""
    if not _is_strict():
        return
    part = partition_path(base, session_id=session_id, identity=identity)
    if part == Path(base):
        return   # low-side collapse guard — never purge the shared store here
    secure_purge(part)
    logger.info("LG-MC-07 context reset: purged partition for session %s", _safe_component(session_id))
