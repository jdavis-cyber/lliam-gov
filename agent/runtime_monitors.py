"""Runtime anomaly / drift / runaway monitors (LG-MO-01..06, P5.1).

Consumes each sealed governance-audit record and raises graduated alerts:

  * LG-MO-01 runaway loop / non-progress — repeated identical tool dispatches
    beyond a threshold.
  * LG-MO-02 egress anomaly — a first-seen egress host, or an egress volume
    spike beyond a threshold.
  * LG-MO-03 provider/MCP schema/permission drift — a load event whose
    tools-hash or scope set changed from the last observed signature.
  * LG-MO-04 behavioral/goal drift + policy-violation patterns — any
    policy.violation / deny / security.error event.
  * LG-MO-06 session risk-timeline correlation + near-real-time notification —
    alerts are correlated per session into a timeline and, above a severity,
    queued as notifications to the configured named staff. Each notification
    is recorded durably and delivered off-thread by
    ``agent/notify_transport.py`` (``monitoring.notify_transport``).

Design: additive and fail-safe. ``MonitorHub.observe(record)`` returns the
alerts raised by that record and streams them to the ISCM sink as
SIEM-consumable ``security.alert`` events. A hub built from a config with no
``monitoring`` block is a **complete no-op** (``enabled == False``) — the low
side is untouched. Monitors never raise into the emit path.
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional

from agent import iscm_sink as _iscm
from agent import notify_transport as _nt

_log = logging.getLogger("hermes.monitors")

_EGRESS_EVENTS = frozenset({"provider.call", "mcp.call"})
_EGRESS_TOOL_ACTIONS = frozenset({
    "web_fetch", "web_search", "browser", "network.egress", "external_send",
})


@dataclass(frozen=True)
class Alert:
    control: str
    kind: str
    severity: str
    session: str
    detail: str


@dataclass
class Notification:
    recipients: list[str]
    severity: str
    summary: str
    session: str
    alerts: list[Alert] = field(default_factory=list)


def _mon(config: Optional[dict]) -> dict:
    if not isinstance(config, dict):
        return {}
    if isinstance(config.get("monitoring"), dict):
        return config["monitoring"]
    sec = config.get("security")
    if isinstance(sec, dict) and isinstance(sec.get("monitoring"), dict):
        return sec["monitoring"]
    return {}


def _host_of(record: dict) -> Optional[str]:
    out = record.get("outcome")
    if isinstance(out, dict):
        for key in ("host", "base_url_host", "domain", "url_host"):
            v = out.get(key)
            if v:
                return str(v)
    return None


class MonitorHub:
    """Stateful consumer of sealed audit records; raises graduated alerts."""

    def __init__(self, config: Optional[dict]) -> None:
        mon = _mon(config)
        self.enabled = bool(mon)
        self.sink = _iscm.build_sink(config) if self.enabled else None
        self.notify_recipients: list[str] = list(mon.get("notify") or [])
        self.runaway_threshold = int(mon.get("runaway_threshold", 8))
        self.egress_volume_threshold = int(
            mon.get("egress_volume_threshold", 50))
        self.notify_severity = str(mon.get("notify_severity", "warning"))

        # per-session state
        self._recent: dict[str, deque] = defaultdict(lambda: deque(maxlen=64))
        self._seen_hosts: dict[str, set] = defaultdict(set)
        self._egress_count: dict[str, int] = defaultdict(int)
        self._timeline: dict[str, list] = defaultdict(list)
        # cross-session load signatures (drift is cross-session, LG-MO-03)
        self._load_sigs: dict[str, dict] = {}
        self._notifications: list[Notification] = []
        self._dispatcher: Optional[_nt.NotificationDispatcher] = None
        if self.enabled and self.notify_recipients:
            try:
                self._dispatcher = _nt.NotificationDispatcher(config)
            except Exception as e:  # never break hub construction
                _log.error("notification transport unavailable: %s", e)

    # -- public API ---------------------------------------------------------

    def observe(self, record: dict) -> list[Alert]:
        if not self.enabled or not isinstance(record, dict):
            return []
        try:
            return self._observe(record)
        except Exception as e:  # fail-safe: never break the emit path
            _log.debug("monitor observe failed (non-fatal): %s", e)
            return []

    def session_timeline(self, session: str) -> list:
        return list(self._timeline.get(session, []))

    def drain_notifications(self) -> list[Notification]:
        out = self._notifications
        self._notifications = []
        return out

    # -- internals ----------------------------------------------------------

    def _observe(self, record: dict) -> list[Alert]:
        session = str(record.get("correlation_id") or "default")
        event = record.get("event")
        alerts: list[Alert] = []

        alerts += self._check_runaway(session, record, event)
        alerts += self._check_egress(session, record, event)
        alerts += self._check_drift(session, record, event)
        alerts += self._check_policy(session, record, event)

        for a in alerts:
            self._timeline[session].append(a)
            self._stream(a)
        self._maybe_notify(session, alerts)
        return alerts

    def _check_runaway(self, session, record, event) -> list[Alert]:
        if event != "tool.dispatch":
            return []
        out = record.get("outcome") if isinstance(record.get("outcome"),
                                                  dict) else {}
        sig = (record.get("action"), out.get("target"))
        buf = self._recent[session]
        buf.append(sig)
        # count consecutive identical signatures at the tail
        run = 0
        for s in reversed(buf):
            if s == sig:
                run += 1
            else:
                break
        if run >= self.runaway_threshold:
            return [Alert("LG-MO-01", "runaway_loop", "warning", session,
                          f"{run} consecutive identical dispatches "
                          f"of {sig[0]!r}")]
        return []

    def _check_egress(self, session, record, event) -> list[Alert]:
        is_egress = (event in _EGRESS_EVENTS or
                     (event == "tool.dispatch" and
                      str(record.get("action")) in _EGRESS_TOOL_ACTIONS))
        if not is_egress:
            return []
        alerts: list[Alert] = []
        host = _host_of(record)
        if host:
            seen = self._seen_hosts[session]
            if host not in seen:
                if seen:  # not the first egress overall — a NEW host appeared
                    alerts.append(Alert(
                        "LG-MO-02", "first_seen_domain", "warning", session,
                        f"first-seen egress host {host!r}"))
                seen.add(host)
        self._egress_count[session] += 1
        if self._egress_count[session] > self.egress_volume_threshold:
            alerts.append(Alert(
                "LG-MO-02", "egress_volume_spike", "warning", session,
                f"egress volume exceeded {self.egress_volume_threshold}"))
        return alerts

    def _check_drift(self, session, record, event) -> list[Alert]:
        if event not in ("mcp.load", "skill.load", "provider.call"):
            return []
        out = record.get("outcome") if isinstance(record.get("outcome"),
                                                  dict) else {}
        server = out.get("server") or out.get("provider") or record.get(
            "action")
        if not server:
            return []
        sig = {"tools_hash": out.get("tools_hash"),
               "scopes": tuple(sorted(out.get("scopes") or ()))}
        key = f"{event}:{server}"
        prev = self._load_sigs.get(key)
        self._load_sigs[key] = sig
        if prev is not None and prev != sig:
            return [Alert("LG-MO-03", "supplier_drift", "warning", session,
                          f"{server!r} signature drifted {prev} -> {sig}")]
        return []

    def _check_policy(self, session, record, event) -> list[Alert]:
        sev = str(record.get("severity"))
        decision = str(record.get("decision"))
        if (event in ("policy.violation", "security.error")
                or decision == "deny"):
            out_sev = "critical" if event == "security.error" else "warning"
            return [Alert("LG-MO-04", "policy_violation", out_sev, session,
                          f"{event} decision={decision} sev={sev}")]
        return []

    def _stream(self, alert: Alert) -> None:
        if self.sink is None:
            return
        self.sink.forward({
            "schema": "lg-mo/1",
            "event": "security.alert",
            "severity": alert.severity,
            "control": alert.control,
            "kind": alert.kind,
            "correlation_id": alert.session,
            "action": alert.kind,
            "decision": "n/a",
            "outcome": {"detail": alert.detail},
            "source_module": "agent/runtime_monitors.py",
        })

    def _maybe_notify(self, session, alerts: list[Alert]) -> None:
        if not alerts or not self.notify_recipients:
            return
        order = {"info": 0, "notice": 1, "warning": 2, "critical": 3}
        floor = order.get(self.notify_severity, 2)
        notable = [a for a in alerts if order.get(a.severity, 0) >= floor]
        if not notable:
            return
        top = max(notable, key=lambda a: order.get(a.severity, 0))
        note = Notification(
            recipients=list(self.notify_recipients),
            severity=top.severity, session=session,
            summary=f"{len(notable)} alert(s) in session {session}: "
                    + "; ".join(a.detail for a in notable[:3]),
            alerts=notable,
        )
        self._notifications.append(note)
        # near-real-time: log at warning so an operator tail sees it now
        _log.warning("[ISCM notify %s] %s",
                     ",".join(note.recipients), note.summary)
        if self._dispatcher is not None:
            # durable record + off-thread delivery; never raises
            self._dispatcher.dispatch(
                severity=note.severity, summary=note.summary,
                session=session, alerts=notable,
                recipients=note.recipients)
        if self.sink is not None:
            self.sink.forward({
                "schema": "lg-mo/1", "event": "security.alert",
                "severity": top.severity, "control": "LG-MO-06",
                "kind": "notification", "correlation_id": session,
                "action": "notify", "decision": "n/a",
                "outcome": {"recipients": note.recipients,
                            "summary": note.summary},
                "source_module": "agent/runtime_monitors.py",
            })
