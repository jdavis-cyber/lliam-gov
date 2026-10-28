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

Sink kinds (``monitoring.iscm_sink.kind``):
  * ``file``      — append JSON/CEF lines to a path (the default; a syslog
    or OTel collector tails it). The record stays on the host.
  * ``syslog``    — stdlib ``SysLogHandler`` to ``syslog_address``: a local
    socket path (``/dev/log``, ``/var/run/syslog``) or ``host:port`` over
    ``syslog_protocol`` udp|tcp. A non-loopback host must pass
    ``check_egress("syslog://host:port", surface="messaging")``; if it does
    not, the network handler is not built and the refusal is logged at ERROR.
  * ``otlp_http`` — OTLP/HTTP JSON logs (``POST {"resourceLogs": ...}``) to
    the https ``otlp_endpoint`` (e.g. a collector's ``/v1/logs``), batched on
    a background thread. The endpoint must pass
    ``check_egress(endpoint, surface="messaging")`` before every batch.
  For ``syslog`` / ``otlp_http`` a configured ``path`` is still written, so
  the host keeps a local copy when the off-host leg is down or refused.
"""
from __future__ import annotations

import json
import logging
import queue
import socket
import sys
import threading
import time
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


_OTLP_SEVERITY = {"info": (9, "INFO"), "notice": (10, "INFO2"),
                  "warning": (13, "WARN"), "critical": (21, "FATAL")}


def _default_syslog_socket() -> str:
    return "/var/run/syslog" if sys.platform == "darwin" else "/dev/log"


def _parse_syslog_address(address) -> tuple:
    """``/path`` → ('unix', path); ``host:port`` / ``[v6]:port`` / ``host``
    → ('net', host, port)."""
    a = str(address or "").strip()
    if not a:
        return ("unix", _default_syslog_socket())
    if a.startswith("/"):
        return ("unix", a)
    host, port = a, 514
    if a.startswith("["):
        host, _, rest = a[1:].partition("]")
        if rest.startswith(":"):
            port = int(rest[1:])
    elif a.count(":") == 1:
        host, _, p = a.partition(":")
        port = int(p)
    return ("net", host, port)


def _otlp_payload(lines: list) -> dict:
    """OTLP/HTTP JSON logs document for a batch of (record, line) pairs."""
    logs = []
    for rec, line in lines:
        num, text = _OTLP_SEVERITY.get(str(rec.get("severity")), (9, "INFO"))
        attrs = [{"key": k, "value": {"stringValue": str(rec.get(k))}}
                 for k in ("event", "action", "decision", "correlation_id",
                           "source_module", "control")
                 if rec.get(k) is not None]
        logs.append({"timeUnixNano": str(time.time_ns()),
                     "severityNumber": num, "severityText": text,
                     "body": {"stringValue": line},
                     "attributes": attrs})
    return {"resourceLogs": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": _SOURCE}},
            {"key": "host.name",
             "value": {"stringValue": socket.gethostname()}}]},
        "scopeLogs": [{"scope": {"name": "lliam-gov.iscm"},
                       "logRecords": logs}]}]}


class _OtlpForwarder:
    """Background, batched OTLP/HTTP JSON shipper. Never blocks the caller."""

    def __init__(self, endpoint: str, *, timeout: float = 5.0,
                 auth_header_env=None, max_attempts: int = 3,
                 batch_size: int = 100, poster=None) -> None:
        from agent import notify_transport as _nt
        self._nt = _nt
        self.endpoint = endpoint
        self.timeout = timeout
        self.auth_header_env = auth_header_env
        self.max_attempts = max(1, int(max_attempts))
        self.batch_size = max(1, int(batch_size))
        self._post = poster
        self._q: "queue.Queue[tuple]" = queue.Queue(maxsize=10000)
        self.dropped = 0
        self.refused = 0
        self.sent = 0
        self._worker: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def submit(self, record: dict, line: str) -> None:
        try:
            self._q.put_nowait((record, line))
        except queue.Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 1000 == 0:
                _log.error("ISCM otlp_http queue full — %d event(s) dropped "
                           "from the off-host stream", self.dropped)
            return
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(
                    target=self._run, name="lliam-iscm-otlp", daemon=True)
                self._worker.start()

    def flush(self, timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._q.unfinished_tasks == 0:
                return True
            time.sleep(0.01)
        return False

    def _send(self, batch: list) -> None:
        ok, reason = self._nt.egress_permits(self.endpoint)
        if not ok:
            self.refused += len(batch)
            _log.error("ISCM otlp_http REFUSED (%d event(s) not shipped): %s",
                       len(batch), reason)
            return
        payload = _otlp_payload(batch)
        headers = self._nt.auth_headers(self.auth_header_env)
        last = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                post = self._post or self._nt.https_post_json
                post(self.endpoint, payload, timeout=self.timeout,
                     headers=headers)
                self.sent += len(batch)
                return
            except Exception as e:
                last = e
                if attempt < self.max_attempts:
                    time.sleep(min(0.5 * (2 ** (attempt - 1)), 5.0))
        self.dropped += len(batch)
        _log.error("ISCM otlp_http DELIVERY FAILED after %d attempt(s), %d "
                   "event(s) not shipped (local file copy kept if "
                   "configured): %s", self.max_attempts, len(batch), last)

    def _run(self) -> None:
        while True:
            item = self._q.get()
            batch = [item]
            while len(batch) < self.batch_size:
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break
            try:
                self._send(batch)
            except Exception as e:  # pragma: no cover - defensive
                _log.error("ISCM otlp_http worker error: %s", e)
            finally:
                for _ in batch:
                    self._q.task_done()


class IscmSink:
    """A fail-safe forwarder to a SIEM-consumable sink."""

    def __init__(self, *, kind: str, fmt: str, path: Optional[Path] = None,
                 syslog_address: Optional[str] = None,
                 syslog_protocol: str = "udp",
                 otlp_endpoint: Optional[str] = None,
                 otlp_timeout: float = 5.0,
                 otlp_auth_header_env: Optional[str] = None,
                 otlp_poster=None) -> None:
        self.kind = kind
        self.fmt = fmt
        self.path = path
        self.refused_reason: Optional[str] = None
        self._syslog: Optional[logging.Handler] = None
        self._otlp: Optional[_OtlpForwarder] = None
        if kind == "syslog":
            self._syslog = self._build_syslog(syslog_address, syslog_protocol)
        elif kind == "otlp_http":
            self._otlp = self._build_otlp(otlp_endpoint, otlp_timeout,
                                          otlp_auth_header_env, otlp_poster)

    def _refuse(self, reason: str) -> None:
        self.refused_reason = reason
        _log.error("ISCM %s sink REFUSED — %s; events stay on the host%s",
                   self.kind, reason,
                   f" ({self.path})" if self.path else "")

    def _build_syslog(self, address, protocol) -> Optional[logging.Handler]:
        try:
            from logging.handlers import SysLogHandler
            parsed = _parse_syslog_address(address)
            if parsed[0] == "unix":
                return SysLogHandler(address=parsed[1])
            _, host, port = parsed
            if not _is_loopback(host):
                from agent import notify_transport as _nt
                ok, reason = _nt.egress_permits(f"syslog://{host}:{port}")
                if not ok:
                    self._refuse(reason)
                    return None
            socktype = (socket.SOCK_STREAM
                        if str(protocol).lower() == "tcp"
                        else socket.SOCK_DGRAM)
            return SysLogHandler(address=(host, int(port)), socktype=socktype)
        except Exception as e:
            _log.error("ISCM syslog sink unavailable (%s): %s", address, e)
            return None

    def _build_otlp(self, endpoint, timeout, auth_env,
                    poster) -> Optional[_OtlpForwarder]:
        from urllib.parse import urlparse
        ep = str(endpoint or "").strip()
        if not ep or urlparse(ep).scheme.lower() != "https":
            self._refuse("otlp_endpoint must be an https URL")
            return None
        from agent import notify_transport as _nt
        ok, reason = _nt.egress_permits(ep)
        if not ok:
            self._refuse(reason)
            return None
        return _OtlpForwarder(ep, timeout=float(timeout or 5),
                              auth_header_env=auth_env, poster=poster)

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
        shipped = False
        try:
            if self._syslog is not None:
                self._syslog.handle(logging.makeLogRecord({
                    "name": "lliam-gov.iscm", "levelno": logging.INFO,
                    "levelname": "INFO", "msg": line, "args": None}))
                shipped = True
            elif self._otlp is not None:
                self._otlp.submit(record, line)
                shipped = True
        except Exception as e:
            _log.error("ISCM %s forward failed: %s", self.kind, e)
        try:
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                return
            if not shipped:
                # last resort: structured log so the event is not silently lost
                _log.info("iscm-event %s", line)
        except Exception as e:
            _log.debug("iscm forward failed (non-fatal): %s", e)

    def flush(self, timeout: float = 10.0) -> bool:
        if self._otlp is not None:
            return self._otlp.flush(timeout)
        if self._syslog is not None:
            try:
                self._syslog.flush()
            except Exception:
                pass
        return True


def _is_loopback(host: str) -> bool:
    from agent import notify_transport as _nt
    return _nt.is_loopback_host(host)


def build_sink(config: Optional[dict]) -> Optional[IscmSink]:
    """Build the ISCM sink from ``monitoring.iscm_sink``; None if not enabled."""
    mon = _monitoring(config)
    spec = mon.get("iscm_sink")
    if not isinstance(spec, dict) or not spec.get("enabled"):
        return None
    kind = str(spec.get("kind") or "file")
    fmt = str(spec.get("format") or "json")
    from agent import notify_transport as _nt
    return IscmSink(
        kind=kind, fmt=fmt,
        path=_nt.resolve_path(spec.get("path")),
        syslog_address=spec.get("syslog_address"),
        syslog_protocol=str(spec.get("syslog_protocol") or "udp"),
        otlp_endpoint=spec.get("otlp_endpoint"),
        otlp_timeout=float(spec.get("otlp_timeout_seconds") or 5),
        otlp_auth_header_env=spec.get("otlp_auth_header_env"),
    )
