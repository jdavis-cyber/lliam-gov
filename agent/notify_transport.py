"""Notification delivery for the runtime monitors (LG-MO-06, JER-76).

``MonitorHub._maybe_notify`` used to build a :class:`Notification`, keep it
in memory and log one warning line: nothing left the process, so the
``monitoring.notify`` list paged nobody. This module is the transport.

Every notification is first appended to a durable, append-only JSONL record
under the agent home (``<home>/logs/notifications.jsonl``, mode 0600) with
``status: queued``. Delivery then runs on a background worker so the audit
emit path never blocks on the network. Each attempt's outcome is appended as
its own record (``delivered`` / ``failed`` / ``refused`` / ``undelivered``),
so a missed delivery is visible on disk and :func:`redeliver_pending`
(called by the scheduled assurance job) can retry it later.

Transports (``monitoring.notify_transport``; all disabled by default):

* ``webhook`` — HTTPS POST of a JSON document. The URL must be ``https``
  and must pass ``tools.egress_policy.check_egress(url, surface="messaging")``
  before every send, so the channel cannot be repointed into an exfil path
  without an allowlist entry. Redirects are refused (a redirect would skip
  the egress check). An optional ``Authorization`` value is read from the
  environment variable named by ``auth_header_env``; it is never stored in
  config or in the record.
* ``smtp`` — plain ``smtplib`` to a relay. A loopback relay (``localhost``
  / ``127.0.0.0/8`` / ``::1``) is the local MTA, whose onward routing is the
  host's own configuration; any other host must pass
  ``check_egress("smtp://host:port", surface="messaging")``.

Delivery failures are logged at ERROR, retried with backoff up to
``max_attempts``, and recorded. Nothing here raises into the caller.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import queue
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

_log = logging.getLogger("hermes.notify")

SCHEMA = "lg-mo/notify/1"
EGRESS_SURFACE = "messaging"
_RECORD_NAME = "notifications.jsonl"
_FINAL_OK = "delivered"
_RETRYABLE = frozenset({"queued", "failed"})


# ---------------------------------------------------------------------------
# Shared helpers (also used by agent/iscm_sink.py off-host forwarders)
# ---------------------------------------------------------------------------

def lliam_home() -> Path:
    try:
        from lliam_constants import get_lliam_home
        return Path(get_lliam_home())
    except Exception:
        return Path(os.environ.get("LLIAM_HOME")
                    or os.environ.get("HERMES_HOME")
                    or Path.home() / ".lliam")


def resolve_path(raw: Any) -> Optional[Path]:
    """Resolve a configured path. ``$HERMES_HOME`` / ``${HERMES_HOME}`` /
    ``$LLIAM_HOME`` map to the effective agent home even when only the other
    variable is exported (the config loader only expands ``${VAR}`` that is
    set, and never the brace-less form)."""
    if raw is None or str(raw).strip() == "":
        return None
    s = str(raw).strip()
    home = str(lliam_home())
    for token in ("${HERMES_HOME}", "$HERMES_HOME", "${LLIAM_HOME}",
                  "$LLIAM_HOME"):
        s = s.replace(token, home)
    return Path(os.path.expandvars(s)).expanduser()


def is_loopback_host(host: str) -> bool:
    h = (host or "").strip().strip("[]").lower()
    if h in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def egress_permits(url: str) -> tuple[bool, str]:
    """Run the public egress policy check. Fail closed on any error."""
    try:
        from tools.egress_policy import check_egress
        decision = check_egress(url, surface=EGRESS_SURFACE)
    except Exception as e:
        return False, f"egress policy unavailable ({e}) — failing closed"
    if decision.disposition != "allow":
        return False, (f"egress policy {decision.disposition}: "
                       f"{decision.reason}")
    return True, decision.reason


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: following one would skip the egress check."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code,
            f"redirect to {newurl!r} refused (egress-checked channel)",
            headers, fp)


def https_post_json(url: str, payload: Any, *, timeout: float = 5.0,
                    headers: Optional[dict] = None) -> int:
    """POST ``payload`` as JSON to an https URL. Returns the HTTP status.

    Raises on transport errors and non-2xx statuses. Does NOT run the egress
    check; callers do that first (see :func:`egress_permits`).
    """
    if urlparse(url).scheme.lower() != "https":
        raise ValueError("only https endpoints are permitted")
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "lliam-gov-notify/1")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    opener = urllib.request.build_opener(_NoRedirectHandler())
    with opener.open(req, timeout=timeout) as resp:
        status = int(getattr(resp, "status", 0) or resp.getcode())
    if status < 200 or status >= 300:
        raise RuntimeError(f"HTTP {status}")
    return status


def auth_headers(env_name: Any) -> dict:
    name = str(env_name or "").strip()
    if not name:
        return {}
    val = os.environ.get(name, "").strip()
    return {"Authorization": val} if val else {}


# ---------------------------------------------------------------------------
# Durable record
# ---------------------------------------------------------------------------

def _stamp() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


class NotificationRecord:
    """Append-only JSONL record of every notification and delivery attempt."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def append(self, entry: dict) -> None:
        line = json.dumps(entry, sort_keys=True, default=str) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path),
                         os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)

    def entries(self) -> list[dict]:
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError:
            return []
        out = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
        return out


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------

class TransportRefused(Exception):
    """Delivery was refused by policy; retrying would not help."""


class WebhookTransport:
    name = "webhook"

    def __init__(self, spec: dict,
                 poster: Optional[Callable[..., int]] = None) -> None:
        self.url = str(spec.get("url") or "").strip()
        self.timeout = float(spec.get("timeout_seconds") or 5)
        self.auth_header_env = spec.get("auth_header_env")
        self._post = poster

    def send(self, payload: dict) -> str:
        if urlparse(self.url).scheme.lower() != "https":
            raise TransportRefused("webhook url must be https")
        ok, reason = egress_permits(self.url)
        if not ok:
            raise TransportRefused(reason)
        post = self._post or https_post_json
        status = post(self.url, payload, timeout=self.timeout,
                      headers=auth_headers(self.auth_header_env))
        return f"HTTP {status}"


class SmtpTransport:
    name = "smtp"

    def __init__(self, spec: dict, recipients: list[str]) -> None:
        self.host = str(spec.get("host") or "").strip()
        self.port = int(spec.get("port") or 25)
        self.from_addr = str(spec.get("from_addr") or "").strip()
        self.starttls = bool(spec.get("starttls"))
        self.timeout = float(spec.get("timeout_seconds") or 5)
        self.recipients = list(recipients)

    def send(self, payload: dict) -> str:
        if not self.host or not self.from_addr or not self.recipients:
            raise TransportRefused(
                "smtp transport needs host, from_addr and monitoring.notify "
                "recipients")
        if not is_loopback_host(self.host):
            ok, reason = egress_permits(f"smtp://{self.host}:{self.port}")
            if not ok:
                raise TransportRefused(reason)
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = (f"[Lliam-GOV {payload.get('severity', '')}] "
                          f"{str(payload.get('summary', ''))[:150]}")
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(json.dumps(payload, indent=2, sort_keys=True,
                                   default=str))
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
            if self.starttls:
                import ssl
                s.starttls(context=ssl.create_default_context())
            s.send_message(msg)
        return f"smtp {self.host}:{self.port}"


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def _spec(config: Optional[dict]) -> dict:
    if not isinstance(config, dict):
        return {}
    mon = config.get("monitoring")
    if not isinstance(mon, dict):
        sec = config.get("security")
        mon = sec.get("monitoring") if isinstance(sec, dict) else None
    if not isinstance(mon, dict):
        return {}
    spec = mon.get("notify_transport")
    return spec if isinstance(spec, dict) else {}


def _recipients(config: Optional[dict]) -> list[str]:
    if not isinstance(config, dict):
        return []
    mon = config.get("monitoring")
    if not isinstance(mon, dict):
        return []
    return [str(r) for r in (mon.get("notify") or [])]


class NotificationDispatcher:
    """Record every notification durably, then deliver it off-thread."""

    def __init__(self, config: Optional[dict], *,
                 record_path: Optional[Path] = None,
                 poster: Optional[Callable[..., int]] = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        spec = _spec(config)
        self.recipients = _recipients(config)
        path = record_path or resolve_path(spec.get("record_path"))
        self.record = NotificationRecord(
            path or lliam_home() / "logs" / _RECORD_NAME)
        self.max_attempts = max(1, int(spec.get("max_attempts") or 3))
        self.backoff = float(spec.get("retry_backoff_seconds")
                             if spec.get("retry_backoff_seconds") is not None
                             else 2)
        self._sleep = sleep
        self.transports: list = []
        wh = spec.get("webhook")
        if isinstance(wh, dict) and wh.get("enabled"):
            self.transports.append(WebhookTransport(wh, poster=poster))
        sm = spec.get("smtp")
        if isinstance(sm, dict) and sm.get("enabled"):
            self.transports.append(SmtpTransport(sm, self.recipients))
        self._queue: "queue.Queue[dict]" = queue.Queue(maxsize=1000)
        self._worker: Optional[threading.Thread] = None
        self._worker_lock = threading.Lock()

    # -- public -------------------------------------------------------------

    def dispatch(self, *, severity: str, summary: str, session: str,
                 alerts: Optional[list] = None,
                 recipients: Optional[list] = None) -> Optional[dict]:
        """Record + queue one notification. Never raises."""
        try:
            payload = {
                "schema": SCHEMA,
                "id": uuid.uuid4().hex,
                "ts": _stamp(),
                "source": "lliam-gov",
                "host": socket.gethostname(),
                "severity": severity,
                "session": session,
                "summary": summary,
                "recipients": list(recipients if recipients is not None
                                   else self.recipients),
                "alerts": [self._alert_view(a) for a in (alerts or [])],
            }
            self._record(payload, status="queued", transport=None,
                         payload_full=True)
            if not self.transports:
                self._record(payload, status="undelivered", transport="none",
                             detail="no notify_transport enabled")
                _log.warning("[ISCM notify] no transport enabled — "
                             "notification %s recorded only", payload["id"])
                return payload
            try:
                self._queue.put_nowait(payload)
            except queue.Full:
                _log.error("[ISCM notify] delivery queue full — %s stays "
                           "queued on disk for redelivery", payload["id"])
                return payload
            self._ensure_worker()
            return payload
        except Exception as e:
            _log.error("[ISCM notify] could not record/queue notification: %s",
                       e)
            return None

    def deliver(self, payload: dict,
                only: Optional[list] = None) -> dict:
        """Deliver ``payload`` on every enabled transport (or the ``only``
        subset), synchronously. Returns ``{transport: outcome}``."""
        results = {}
        for t in self.transports:
            if only is not None and t.name not in only:
                continue
            results[t.name] = self._deliver_one(t, payload)
        return results

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait until the queue is drained (tests / shutdown)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.unfinished_tasks == 0:
                return True
            time.sleep(0.01)
        return False

    def pending(self, *, max_age_hours: float = 72.0,
                min_age_seconds: float = 600.0) -> list[tuple[dict, list]]:
        """``(payload, [transport names])`` still owed a delivery: the latest
        state on that enabled transport is queued/failed (``delivered`` and
        ``refused`` are final). Records younger than ``min_age_seconds`` are
        skipped so an in-flight worker in the agent process is not raced."""
        import datetime as _dt
        names = [t.name for t in self.transports]
        if not names:
            return []
        payloads: dict[str, dict] = {}
        state: dict[tuple, str] = {}
        for rec in self.record.entries():
            nid = rec.get("id")
            if not nid:
                continue
            if isinstance(rec.get("payload"), dict):
                payloads[nid] = rec["payload"]
            tr = rec.get("transport")
            if tr in names:
                state[(nid, tr)] = str(rec.get("status"))
        now = _dt.datetime.now(_dt.timezone.utc)
        out = []
        for nid, payload in payloads.items():
            try:
                age = (now - _dt.datetime.fromisoformat(
                    str(payload.get("ts")))).total_seconds()
            except (TypeError, ValueError):
                continue
            if age > max_age_hours * 3600 or age < min_age_seconds:
                continue
            owed = [n for n in names
                    if state.get((nid, n), "queued") in _RETRYABLE]
            if owed:
                out.append((payload, owed))
        return out

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _alert_view(a: Any) -> dict:
        if isinstance(a, dict):
            return dict(a)
        return {k: getattr(a, k, None)
                for k in ("control", "kind", "severity", "detail")}

    def _record(self, payload: dict, *, status: str,
                transport: Optional[str], detail: str = "",
                attempts: int = 0, payload_full: bool = False) -> None:
        entry = {"schema": SCHEMA, "id": payload.get("id"), "ts": _stamp(),
                 "status": status, "transport": transport,
                 "severity": payload.get("severity"),
                 "session": payload.get("session")}
        if detail:
            entry["detail"] = str(detail)[:500]
        if attempts:
            entry["attempts"] = attempts
        if payload_full:
            entry["payload"] = payload
        try:
            self.record.append(entry)
        except Exception as e:
            _log.error("[ISCM notify] notification record write failed "
                       "(%s): %s", self.record.path, e)

    def _deliver_one(self, transport, payload: dict) -> str:
        last = ""
        for attempt in range(1, self.max_attempts + 1):
            try:
                detail = transport.send(payload)
            except TransportRefused as e:
                _log.error("[ISCM notify] %s REFUSED for %s: %s",
                           transport.name, payload.get("id"), e)
                self._record(payload, status="refused",
                             transport=transport.name, detail=str(e),
                             attempts=attempt)
                return "refused"
            except Exception as e:
                last = f"{type(e).__name__}: {e}"
                _log.warning("[ISCM notify] %s attempt %d/%d failed for %s: "
                             "%s", transport.name, attempt, self.max_attempts,
                             payload.get("id"), last)
                if attempt < self.max_attempts and self.backoff > 0:
                    self._sleep(self.backoff * (2 ** (attempt - 1)))
                continue
            self._record(payload, status=_FINAL_OK, transport=transport.name,
                         detail=detail, attempts=attempt)
            return _FINAL_OK
        _log.error("[ISCM notify] %s DELIVERY FAILED for %s after %d "
                   "attempt(s): %s — kept on disk for redelivery (%s)",
                   transport.name, payload.get("id"), self.max_attempts, last,
                   self.record.path)
        self._record(payload, status="failed", transport=transport.name,
                     detail=last, attempts=self.max_attempts)
        return "failed"

    def _ensure_worker(self) -> None:
        with self._worker_lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._worker = threading.Thread(
                target=self._run, name="lliam-notify", daemon=True)
            self._worker.start()

    def _run(self) -> None:
        while True:
            payload = self._queue.get()
            try:
                self.deliver(payload)
            except Exception as e:  # pragma: no cover - defensive
                _log.error("[ISCM notify] delivery worker error: %s", e)
            finally:
                self._queue.task_done()


def redeliver_pending(config: Optional[dict], *,
                      dispatcher: Optional[NotificationDispatcher] = None,
                      max_age_hours: float = 72.0,
                      min_age_seconds: float = 600.0) -> dict:
    """Retry undelivered notifications (called by the scheduled assurance
    job). Returns ``{"pending": n, "delivered": k}``. Never raises."""
    try:
        d = dispatcher or NotificationDispatcher(config)
        todo = d.pending(max_age_hours=max_age_hours,
                         min_age_seconds=min_age_seconds)
        delivered = 0
        for payload, owed in todo:
            res = d.deliver(payload, only=owed)
            if res and all(v == _FINAL_OK for v in res.values()):
                delivered += 1
        return {"pending": len(todo), "delivered": delivered}
    except Exception as e:
        _log.error("[ISCM notify] redelivery failed: %s", e)
        return {"pending": -1, "delivered": 0, "error": str(e)}
