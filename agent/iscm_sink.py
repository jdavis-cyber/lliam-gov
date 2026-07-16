"""ISCM/SIEM export sink for the governance audit ledger (LG-MO-05, P5.1).

Streams each sealed ledger record as a SIEM-consumable event to the sink
configured at ``monitoring.iscm_sink`` in the gov overlay. Additive — the
existing ``dashboard_auth/audit.py`` and the ledger schema are unchanged; the
sink is a read-only forwarder hooked at ``agent/governance_audit.emit`` after
the record is sealed.

Design:
  * ``build_sink(config)`` returns a sink or ``None`` (no-op) when monitoring
    is not configured/enabled — complete no-op on the low side.
  * ``forward(record)`` is fail-safe: it never raises into the emit path (a
    sink failure must not break the tamper-evident write).
  * SIEM formats: ``json`` (one JSON object per line, the SIEM-consumable
    default) and ``cef`` (ArcSight CEF-style line). Each forwarded event is
    stamped with ``ts_ingest`` and ``source`` so a downstream SIEM can key on
    ingest time and provenance without re-deriving them.

Sink kinds:
  * ``file``   — append JSON/CEF lines to a path (the eval default; a syslog
    or OTel collector tails it).
  * ``syslog`` — emit via the stdlib syslog handler when available.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger("hermes.iscm")

_SOURCE = "lliam-gov"


def _monitoring(config: Optional[dict]) -> dict:
    if not isinstance(config, dict):
        return {}
    sec = config.get("security")
    # monitoring lives at the top level of the overlay, but tolerate a nested
    # security.monitoring shape too.
    mon = config.get("monitoring")
    if isinstance(mon, dict):
        return mon
    if isinstance(sec, dict) and isinstance(sec.get("monitoring"), dict):
        return sec["monitoring"]
    return {}


def _ingest_stamp() -> str:
    """UTC ingest timestamp. Import time lazily so the module import stays
    cheap and Date-free at module scope (the workflow bans argless now())."""
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds")


def _to_cef(record: dict) -> str:
    sev_map = {"info": 2, "notice": 4, "warning": 7, "critical": 10}
    sev = sev_map.get(str(record.get("severity")), 4)
    name = str(record.get("event", "event"))
    ext = " ".join(
        f"{k}={json.dumps(v) if not isinstance(v, str) else v}"
        for k, v in (
            ("act", record.get("action")),
            ("outcome", record.get("decision")),
            ("cs1", record.get("correlation_id")),
            ("cs2", record.get("source_module")),
        ) if v is not None
    )
    return (f"CEF:0|Lliam-GOV|governance-audit|1.0|{name}|{name}|{sev}|{ext}")


class IscmSink:
    """A fail-safe forwarder to a SIEM-consumable sink."""

    def __init__(self, *, kind: str, fmt: str, path: Optional[Path] = None,
                 syslog_address: Optional[str] = None) -> None:
        self.kind = kind
        self.fmt = fmt
        self.path = path
        self._syslog: Optional[logging.Logger] = None
        if kind == "syslog":
            self._syslog = self._build_syslog(syslog_address)

    @staticmethod
    def _build_syslog(address) -> Optional[logging.Logger]:
        try:
            from logging.handlers import SysLogHandler
            lg = logging.getLogger("hermes.iscm.syslog")
            lg.propagate = False
            if not lg.handlers:
                h = SysLogHandler(address=address or "/dev/log")
                lg.addHandler(h)
                lg.setLevel(logging.INFO)
            return lg
        except Exception as e:  # pragma: no cover - platform dependent
            _log.debug("syslog sink unavailable, falling back to log: %s", e)
            return None

    def _serialize(self, record: dict) -> str:
        enriched = dict(record)
        enriched["ts_ingest"] = _ingest_stamp()
        enriched["source"] = _SOURCE
        if self.fmt == "cef":
            return _to_cef(enriched)
        return json.dumps(enriched, sort_keys=True, default=str)

    def forward(self, record: dict) -> None:
        """Forward one sealed record. Never raises into the caller."""
        try:
            line = self._serialize(record)
        except Exception as e:
            _log.debug("iscm serialize failed: %s", e)
            return
        try:
            if self.kind == "syslog" and self._syslog is not None:
                self._syslog.info(line)
                return
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                return
            # last resort: structured log so the event is not silently lost
            _log.info("iscm-event %s", line)
        except Exception as e:
            _log.debug("iscm forward failed (non-fatal): %s", e)


def build_sink(config: Optional[dict]) -> Optional[IscmSink]:
    """Build the ISCM sink from ``monitoring.iscm_sink``; None if not enabled."""
    mon = _monitoring(config)
    spec = mon.get("iscm_sink")
    if not isinstance(spec, dict) or not spec.get("enabled"):
        return None
    kind = str(spec.get("kind") or "file")
    fmt = str(spec.get("format") or "json")
    path = spec.get("path")
    return IscmSink(
        kind=kind, fmt=fmt,
        path=Path(str(path)).expanduser() if path else None,
        syslog_address=spec.get("syslog_address"),
    )
