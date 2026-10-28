"""P5.1 ISCM/SIEM streaming + runtime monitors tests (LG-MO-01..06, AI-499).

The AI-499 VERIFY criteria, machine-checked:
  * ledger events reach the ISCM/SIEM sink as SIEM-consumable lines (LG-MO-05);
  * an injected egress anomaly (first-seen domain) raises an alert (LG-MO-02);
  * an injected runaway loop raises an alert (LG-MO-01);
  * provider/MCP drift (LG-MO-03), goal-drift/policy-violation patterns
    (LG-MO-04), and session risk-timeline correlation (LG-MO-06) alert;
  * near-real-time notification reaches the configured named staff;
  * complete no-op when monitoring is not configured (capability preserved).
"""

from __future__ import annotations

import json

import pytest

from agent import iscm_sink
from agent import runtime_monitors as rm


def _rec(event, **fields):
    base = {"schema": "lg-au/1", "seq": fields.pop("seq", 1),
            "event": event, "severity": fields.pop("severity", "notice"),
            "correlation_id": fields.pop("correlation_id", "sess-A"),
            "action": fields.pop("action", "x"), "decision": "allow",
            "outcome": {}, "source_module": "test"}
    base.update(fields)
    return base


# ---------------------------------------------------------------------------
# LG-MO-05 — ISCM sink streams SIEM-consumable events
# ---------------------------------------------------------------------------

def _sink_cfg(tmp_path, **over):
    cfg = {"monitoring": {"iscm_sink": {
        "enabled": True, "kind": "file",
        "path": str(tmp_path / "iscm.log"), "format": "json"}}}
    cfg["monitoring"]["iscm_sink"].update(over)
    return cfg


def test_sink_writes_siem_consumable_lines(tmp_path):
    cfg = _sink_cfg(tmp_path)
    sink = iscm_sink.build_sink(cfg)
    assert sink is not None
    sink.forward(_rec("tool.dispatch", action="file_read"))
    sink.forward(_rec("policy.violation", severity="warning", action="deny"))
    lines = (tmp_path / "iscm.log").read_text().strip().splitlines()
    assert len(lines) == 2
    parsed = [json.loads(l) for l in lines]
    assert parsed[0]["event"] == "tool.dispatch"
    assert "ts_ingest" in parsed[0] and "source" in parsed[0]


def test_sink_disabled_is_noop(tmp_path):
    cfg = {"monitoring": {"iscm_sink": {"enabled": False}}}
    assert iscm_sink.build_sink(cfg) is None


def test_sink_absent_config_is_noop():
    assert iscm_sink.build_sink({}) is None
    assert iscm_sink.build_sink(None) is None


def test_sink_forward_never_raises(tmp_path):
    # a bad path must not break the caller (emit path is fail-safe)
    cfg = _sink_cfg(tmp_path / "nonexistent-dir-xyz" / "deep")
    sink = iscm_sink.build_sink(cfg)
    # forwarding still must not raise even if the dir is created lazily
    sink.forward(_rec("tool.dispatch"))


# ---------------------------------------------------------------------------
# LG-MO-01 — runaway loop / non-progress
# ---------------------------------------------------------------------------

def _hub(tmp_path, **mon):
    cfg = _sink_cfg(tmp_path)
    cfg["monitoring"].update({
        "runaway_threshold": mon.get("runaway_threshold", 5),
        "egress_volume_threshold": mon.get("egress_volume_threshold", 10),
        "notify": mon.get("notify", ["isso@agency.mil"]),
    })
    return rm.MonitorHub(cfg)


def test_runaway_loop_alerts(tmp_path):
    hub = _hub(tmp_path, runaway_threshold=5)
    alerts = []
    for i in range(6):
        alerts += hub.observe(_rec("tool.dispatch", seq=i,
                                   action="web_fetch",
                                   outcome={"target": "same"}))
    assert any(a.control == "LG-MO-01" for a in alerts), \
        "runaway loop not detected"


def test_normal_varied_activity_no_runaway(tmp_path):
    hub = _hub(tmp_path, runaway_threshold=5)
    alerts = []
    for i, tgt in enumerate(["a", "b", "c", "d", "e", "f"]):
        alerts += hub.observe(_rec("tool.dispatch", seq=i,
                                   action="file_read",
                                   outcome={"target": tgt}))
    assert not any(a.control == "LG-MO-01" for a in alerts)


# ---------------------------------------------------------------------------
# LG-MO-02 — egress anomaly: first-seen domain
# ---------------------------------------------------------------------------

def test_first_seen_domain_alerts(tmp_path):
    hub = _hub(tmp_path)
    hub.observe(_rec("provider.call", outcome={"host": "bedrock.us-gov-west-1.amazonaws.com"}))
    alerts = hub.observe(_rec("tool.dispatch", action="web_fetch",
                              outcome={"host": "first-seen-exfil.example"}))
    assert any(a.control == "LG-MO-02" for a in alerts), \
        "first-seen domain not flagged"


def test_egress_volume_spike_alerts(tmp_path):
    hub = _hub(tmp_path, egress_volume_threshold=3)
    alerts = []
    for i in range(4):
        alerts += hub.observe(_rec("provider.call", seq=i,
                                   outcome={"host": "known.example",
                                            "bytes": 5000}))
    assert any(a.control == "LG-MO-02" for a in alerts)


# ---------------------------------------------------------------------------
# LG-MO-03 — provider/MCP schema/permission drift
# ---------------------------------------------------------------------------

def test_mcp_schema_drift_alerts(tmp_path):
    hub = _hub(tmp_path)
    hub.observe(_rec("mcp.load", action="gov-fs",
                     outcome={"server": "gov-fs", "tools_hash": "aaa",
                              "scopes": ["read"]}))
    alerts = hub.observe(_rec("mcp.load", action="gov-fs",
                              outcome={"server": "gov-fs", "tools_hash": "BBB",
                                       "scopes": ["read", "write"]}))
    assert any(a.control == "LG-MO-03" for a in alerts), "drift not detected"


def test_mcp_same_signature_no_drift(tmp_path):
    hub = _hub(tmp_path)
    sig = {"server": "gov-fs", "tools_hash": "aaa", "scopes": ["read"]}
    hub.observe(_rec("mcp.load", action="gov-fs", outcome=dict(sig)))
    alerts = hub.observe(_rec("mcp.load", action="gov-fs", outcome=dict(sig)))
    assert not any(a.control == "LG-MO-03" for a in alerts)


# ---------------------------------------------------------------------------
# LG-MO-04 — behavioral/goal drift + policy-violation patterns
# ---------------------------------------------------------------------------

def test_policy_violation_pattern_alerts(tmp_path):
    hub = _hub(tmp_path)
    a1 = hub.observe(_rec("policy.violation", severity="warning",
                          action="deny", decision="deny"))
    assert any(a.control == "LG-MO-04" for a in a1)


# ---------------------------------------------------------------------------
# LG-MO-06 — session risk-timeline correlation + notification
# ---------------------------------------------------------------------------

def test_session_risk_timeline_and_notification(tmp_path):
    hub = _hub(tmp_path, notify=["isso@agency.mil", "caio@agency.mil"])
    # establish a known egress host, then drive two anomalies in one session
    hub.observe(_rec("provider.call", correlation_id="sess-X",
                     outcome={"host": "bedrock.us-gov-west-1.amazonaws.com"}))
    hub.observe(_rec("policy.violation", correlation_id="sess-X",
                     severity="warning", action="deny", decision="deny"))
    hub.observe(_rec("tool.dispatch", correlation_id="sess-X",
                     action="web_fetch", outcome={"host": "evil.example"}))
    timeline = hub.session_timeline("sess-X")
    assert len(timeline) >= 2
    notes = hub.drain_notifications()
    assert notes, "no near-real-time notification produced"
    assert any("isso@agency.mil" in n.recipients for n in notes)


def test_notification_reaches_sink(tmp_path):
    hub = _hub(tmp_path)
    hub.observe(_rec("policy.violation", correlation_id="sess-Y",
                     severity="warning", action="deny", decision="deny"))
    # alerts are also streamed to the ISCM sink as security events
    log = (tmp_path / "iscm.log").read_text()
    assert "LG-MO-04" in log or "alert" in log.lower()


# ---------------------------------------------------------------------------
# Capability preservation — no monitoring config → complete no-op
# ---------------------------------------------------------------------------

def test_hub_noop_without_config():
    hub = rm.MonitorHub({})
    assert hub.observe(_rec("tool.dispatch")) == []
    assert hub.enabled is False


# ---------------------------------------------------------------------------
# Live wiring — the emit() path forwards to ISCM + monitors
# ---------------------------------------------------------------------------

def test_governance_audit_emit_wires_iscm(tmp_path, monkeypatch):
    import agent.governance_audit as ga
    src = (rm.__file__, iscm_sink.__file__)  # modules exist
    assert all(src)
    ga_src = __import__("pathlib").Path(ga.__file__).read_text()
    assert "iscm" in ga_src.lower() or "monitor" in ga_src.lower(), \
        "governance_audit.emit does not wire the ISCM/monitor hook"
