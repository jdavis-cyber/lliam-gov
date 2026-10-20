"""Monitoring, notification and assurance actually operate (JER-76).

  * a monitor notification is recorded durably and POSTed as JSON to the
    configured webhook; an egress-denied webhook is refused and recorded; a
    delivery failure never raises and is redelivered later;
  * the scheduled assurance entry runs the cATO cycle, so a posture break
    auto-suspends via the kill-switch (and steady state does not);
  * the schedule installer renders a launchd plist / systemd user timer
    (into a temp dir — never the real system);
  * control-effectiveness asserts assurance-job freshness on a deployed host
    and is n/a in a repo checkout;
  * the ISCM stream can leave the host (syslog / OTLP-HTTP), egress-checked.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import plistlib
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "ci" / "governance-ci-gates"))

import control_effectiveness as ce  # noqa: E402
import scheduled_assurance as sa  # noqa: E402
from agent import cato_loop as cato  # noqa: E402
from agent import iscm_sink  # noqa: E402
from agent import killswitch as ks  # noqa: E402
from agent import notify_transport as nt  # noqa: E402
from agent import runtime_monitors as rm  # noqa: E402
from lliam_cli import assurance_schedule as sched  # noqa: E402
from tools.egress_policy import EgressDecision  # noqa: E402

_CRON = _REPO / "ci" / "governance-ci-gates" / "scheduled_assurance_cron.sh"


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(ks, "_state_path", lambda: tmp_path / "killswitch.state")
    ks.reset_for_tests()
    yield
    ks.reset_for_tests()


@pytest.fixture
def egress(monkeypatch):
    """Record every egress check; allow unless a URL is in ``deny``."""
    calls: list = []
    deny: set = set()

    def fake(url, *, surface="web", session_id=None):
        calls.append((url, surface))
        if url in deny:
            return EgressDecision("deny", reason=f"{url} not allowlisted")
        return EgressDecision("allow", reason="test allow")

    import tools.egress_policy as ep
    monkeypatch.setattr(ep, "check_egress", fake)
    return calls, deny


def _cfg(tmp_path, *, webhook=None, smtp=None, **transport):
    spec = {"max_attempts": 2, "retry_backoff_seconds": 0,
            "record_path": str(tmp_path / "notifications.jsonl"), **transport}
    if webhook is not None:
        spec["webhook"] = webhook
    if smtp is not None:
        spec["smtp"] = smtp
    return {"monitoring": {
        "iscm_sink": {"enabled": True, "kind": "file", "format": "json",
                      "path": str(tmp_path / "iscm.log")},
        "notify": ["isso@agency.mil"], "notify_severity": "warning",
        "notify_transport": spec}}


_HOOK = "https://hooks.example.test/lliam"


def _records(tmp_path):
    p = tmp_path / "notifications.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# Notification transport
# ---------------------------------------------------------------------------

def test_webhook_posts_notification_json(tmp_path, egress):
    calls, _ = egress
    posted = []

    def poster(url, payload, *, timeout, headers):
        posted.append((url, payload, headers))
        return 204

    cfg = _cfg(tmp_path, webhook={"enabled": True, "url": _HOOK,
                                  "auth_header_env": "LLIAM_TEST_HOOK_AUTH"})
    os.environ["LLIAM_TEST_HOOK_AUTH"] = "Bearer test-only"
    try:
        hub = rm.MonitorHub(cfg)
        hub._dispatcher = nt.NotificationDispatcher(cfg, poster=poster)
        hub.observe({"event": "policy.violation", "severity": "warning",
                     "correlation_id": "sess-W", "action": "deny",
                     "decision": "deny", "outcome": {}})
        assert hub._dispatcher.flush(5)
    finally:
        os.environ.pop("LLIAM_TEST_HOOK_AUTH", None)

    assert len(posted) == 1
    url, payload, headers = posted[0]
    assert url == _HOOK
    assert payload["schema"] == "lg-mo/notify/1"
    assert payload["session"] == "sess-W"
    assert payload["severity"] == "warning"
    assert payload["recipients"] == ["isso@agency.mil"]
    assert payload["alerts"][0]["control"] == "LG-MO-04"
    assert headers == {"Authorization": "Bearer test-only"}
    assert (_HOOK, "messaging") in calls  # egress-checked on the messaging surface
    statuses = [(r["status"], r["transport"]) for r in _records(tmp_path)]
    assert ("queued", None) in statuses and ("delivered", "webhook") in statuses
    assert oct((tmp_path / "notifications.jsonl").stat().st_mode & 0o777) == "0o600"


def test_egress_denied_webhook_is_refused_and_recorded(tmp_path, egress):
    _, deny = egress
    deny.add(_HOOK)
    posted = []
    d = nt.NotificationDispatcher(
        _cfg(tmp_path, webhook={"enabled": True, "url": _HOOK}),
        poster=lambda *a, **k: posted.append(a) or 200)
    d.dispatch(severity="critical", summary="x", session="s")
    assert d.flush(5)
    assert posted == []  # nothing left the host
    refused = [r for r in _records(tmp_path) if r["status"] == "refused"]
    assert refused and "not allowlisted" in refused[0]["detail"]
    # refused is final — not retried by redelivery
    assert d.pending(min_age_seconds=0) == []


def test_non_https_webhook_refused(tmp_path, egress):
    d = nt.NotificationDispatcher(
        _cfg(tmp_path, webhook={"enabled": True,
                                "url": "http://hooks.example.test/x"}),
        poster=lambda *a, **k: 200)
    assert d.deliver({"id": "n1"}) == {"webhook": "refused"}
    with pytest.raises(ValueError):
        nt.https_post_json("http://hooks.example.test/x", {})


def test_delivery_failure_never_raises_and_is_redelivered(tmp_path, egress):
    def down(*a, **k):
        raise ConnectionError("receiver down")

    cfg = _cfg(tmp_path, webhook={"enabled": True, "url": _HOOK})
    d = nt.NotificationDispatcher(cfg, poster=down)
    d.dispatch(severity="critical", summary="posture", session="s")  # no raise
    assert d.flush(5)
    failed = [r for r in _records(tmp_path) if r["status"] == "failed"]
    assert failed and failed[0]["attempts"] == 2

    ok = []
    d2 = nt.NotificationDispatcher(cfg, poster=lambda *a, **k: ok.append(a) or 200)
    res = nt.redeliver_pending(cfg, dispatcher=d2, min_age_seconds=0)
    assert res == {"pending": 1, "delivered": 1}
    assert len(ok) == 1
    assert nt.redeliver_pending(cfg, dispatcher=d2, min_age_seconds=0) == \
        {"pending": 0, "delivered": 0}


def test_no_transport_records_undelivered(tmp_path):
    d = nt.NotificationDispatcher(_cfg(tmp_path))
    d.dispatch(severity="warning", summary="x", session="s")
    assert [r["status"] for r in _records(tmp_path)] == ["queued", "undelivered"]


def test_smtp_non_loopback_relay_is_egress_checked(tmp_path, egress, monkeypatch):
    calls, deny = egress
    deny.add("smtp://relay.example.test:25")
    import smtplib
    monkeypatch.setattr(smtplib, "SMTP", lambda *a, **k: pytest.fail("sent"))
    d = nt.NotificationDispatcher(_cfg(tmp_path, smtp={
        "enabled": True, "host": "relay.example.test",
        "from_addr": "lliam@example.test"}))
    assert d.deliver({"id": "n1", "severity": "warning"}) == {"smtp": "refused"}
    assert ("smtp://relay.example.test:25", "messaging") in calls


def test_smtp_loopback_relay_sends(tmp_path, monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent.append((host, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def send_message(self, msg):
            sent.append(msg["To"])

    import smtplib
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    d = nt.NotificationDispatcher(_cfg(tmp_path, smtp={
        "enabled": True, "host": "127.0.0.1", "port": 2525,
        "from_addr": "lliam@example.test"}))
    assert d.deliver({"id": "n1", "severity": "warning",
                      "summary": "s"}) == {"smtp": "delivered"}
    assert sent == [("127.0.0.1", 2525), "isso@agency.mil"]


# ---------------------------------------------------------------------------
# Scheduled assurance → cATO cycle
# ---------------------------------------------------------------------------

def _overlay(tmp_path, *, godmode_enabled=False):
    data = yaml.safe_load((_REPO / "cli-config.gov.yaml").read_text())
    if godmode_enabled:
        data["skills"]["disabled"] = [s for s in data["skills"]["disabled"]
                                      if s != "godmode"]
    data["monitoring"]["iscm_sink"]["path"] = str(tmp_path / "iscm.log")
    data["monitoring"]["notify_transport"]["record_path"] = \
        str(tmp_path / "notifications.jsonl")
    p = tmp_path / "cli-config.gov.yaml"
    p.write_text(yaml.safe_dump(data))
    return p, data


def test_assurance_entry_runs_cato_and_suspends_on_break(tmp_path):
    overlay, cfg = _overlay(tmp_path, godmode_enabled=True)
    home = tmp_path / "home"
    beat = sa.run_assurance(home=home, config=cfg, overlay_path=overlay,
                            run_redteam=False)
    assert beat["cato"]["suspend"] is True
    assert "godmode" in beat["cato"]["reason"]
    assert ks.is_engaged(), "posture break did not auto-suspend"
    assert ks.state()["actor"] == sa.ACTOR
    # heartbeat written and the break was notified (recorded on disk)
    saved = json.loads((home / "logs/assurance/last-run.json").read_text())
    assert saved["ok"] is False and saved["completed_at"]
    notes = _records(tmp_path)
    assert any(r.get("severity") == "critical" and r["status"] == "queued"
               for r in notes)


def test_assurance_entry_steady_state_does_not_suspend(tmp_path):
    overlay, cfg = _overlay(tmp_path)
    beat = sa.run_assurance(home=tmp_path / "home", config=cfg,
                            overlay_path=overlay, run_redteam=False)
    assert beat["effectiveness_failures"] == []
    assert beat["cato"]["suspend"] is False
    assert beat["ok"] is True
    assert not ks.is_engaged()


def test_assurance_entry_passes_iscm_alerts_to_cato(tmp_path):
    overlay, cfg = _overlay(tmp_path)
    seen = {}

    def spy(**kw):
        seen.update(kw)
        return cato.evaluate(alerts=kw["alerts"],
                             effectiveness_failures=kw["effectiveness_failures"])

    sink = iscm_sink.build_sink(cfg)
    sink.forward({"event": "security.alert", "severity": "critical",
                  "control": "LG-MO-04"})
    beat = sa.run_assurance(home=tmp_path / "home", config=cfg,
                            overlay_path=overlay, run_redteam=False,
                            cato_cycle=spy)
    assert seen["actor"] == sa.ACTOR
    assert [a.severity for a in seen["alerts"]] == ["critical"]
    assert beat["cato"]["suspend"] is True


def test_assurance_respects_auto_suspend_off(tmp_path):
    overlay, cfg = _overlay(tmp_path, godmode_enabled=True)
    cfg["cato"]["auto_suspend_on_break"] = False
    beat = sa.run_assurance(home=tmp_path / "home", config=cfg,
                            overlay_path=overlay, run_redteam=False)
    assert beat["cato"]["suspend"] is True  # break still reported
    assert not ks.is_engaged()


def _shim(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)
    return path


def test_cron_wrapper_calls_assurance_entry_and_pages(tmp_path):
    marker = tmp_path / "alert_stdin"
    py = _shim(tmp_path / "py", 'echo "ARGS:$*"\nexit 1\n')
    alert = _shim(tmp_path / "alert", f"cat > {str(marker)!r}\n")
    env = {**os.environ, "HERMES_HOME": str(tmp_path),
           "HERMES_CONFIG": str(tmp_path / "x.yaml"),
           "LLIAM_PYTHON": str(py), "LLIAM_ASSURANCE_ALERT_CMD": str(alert)}
    proc = subprocess.run(["bash", str(_CRON)], env=env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 1
    assert "scheduled_assurance.py" in proc.stdout
    assert "scheduled_assurance.py" in marker.read_text()


def test_cron_wrapper_fails_closed_without_env(tmp_path):
    env = {k: v for k, v in os.environ.items()
           if k not in ("HERMES_HOME", "HERMES_CONFIG")}
    proc = subprocess.run(["bash", str(_CRON)], env=env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 2


# ---------------------------------------------------------------------------
# Schedule installer (rendered into tmp — never the real system)
# ---------------------------------------------------------------------------

class _Runner:
    def __init__(self):
        self.cmds = []

    def __call__(self, cmd):
        self.cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_launchd_plist_rendering(tmp_path):
    run = _Runner()
    home = tmp_path / "home"
    paths = sched.install(platform="launchd", dest_dir=tmp_path / "la",
                          home=home, overlay=tmp_path / "o.yaml",
                          python="/opt/py", hour=6, minute=5, runner=run)
    doc = plistlib.loads(paths[0].read_bytes())
    assert doc["Label"] == sched.LAUNCHD_LABEL
    assert doc["ProgramArguments"][-1].endswith(
        "ci/governance-ci-gates/scheduled_assurance_cron.sh")
    assert doc["EnvironmentVariables"]["HERMES_HOME"] == str(home)
    assert doc["EnvironmentVariables"]["HERMES_CONFIG"] == str(tmp_path / "o.yaml")
    assert doc["EnvironmentVariables"]["LLIAM_PYTHON"] == "/opt/py"
    assert doc["StartCalendarInterval"] == {"Hour": 6, "Minute": 5}
    assert any(c[:2] == ["launchctl", "bootstrap"] for c in run.cmds)

    removed = sched.uninstall(platform="launchd", dest_dir=tmp_path / "la",
                              runner=run)
    assert removed == paths and not paths[0].exists()


def test_systemd_timer_rendering(tmp_path):
    run = _Runner()
    paths = sched.install(platform="systemd", dest_dir=tmp_path / "sd",
                          home=tmp_path / "home", overlay=tmp_path / "o.yaml",
                          python="/opt/py", runner=run)
    names = sorted(p.name for p in paths)
    assert names == ["lliam-gov-assurance.service", "lliam-gov-assurance.timer"]
    svc = (tmp_path / "sd" / "lliam-gov-assurance.service").read_text()
    tmr = (tmp_path / "sd" / "lliam-gov-assurance.timer").read_text()
    assert "Type=oneshot" in svc
    assert "scheduled_assurance_cron.sh" in svc
    assert f'Environment="HERMES_HOME={tmp_path / "home"}"' in svc
    assert "OnCalendar=*-*-* 07:23:00" in tmr and "Persistent=true" in tmr
    assert ["systemctl", "--user", "enable", "--now",
            "lliam-gov-assurance.timer"] in run.cmds
    sched.uninstall(platform="systemd", dest_dir=tmp_path / "sd", runner=run)
    assert not any(p.exists() for p in paths)


def test_install_no_activate_runs_nothing(tmp_path):
    run = _Runner()
    sched.install(platform="systemd", dest_dir=tmp_path / "sd",
                  home=tmp_path / "home", overlay=tmp_path / "o.yaml",
                  activate=False, runner=run)
    assert run.cmds == []


def test_status_reports_freshness(tmp_path):
    home = tmp_path / "home"
    st = sched.status(platform="systemd", dest_dir=tmp_path, home=home)
    assert st["installed"] is False and st["fresh"] is False
    hb = home / "logs/assurance/last-run.json"
    hb.parent.mkdir(parents=True)
    hb.write_text(json.dumps({"completed_at": dt.datetime.now(
        dt.timezone.utc).isoformat(), "ok": True}))
    assert sched.status(platform="systemd", dest_dir=tmp_path,
                        home=home)["fresh"] is True


# ---------------------------------------------------------------------------
# control-effectiveness: assurance freshness on a deployed host
# ---------------------------------------------------------------------------

def _deployed(tmp_path, monkeypatch, completed_at=None):
    home = tmp_path / "deployed"
    (home / "logs").mkdir(parents=True)
    (home / "logs" / "agent-audit.log").write_text("{}\n")
    if completed_at is not None:
        hb = home / "logs" / "assurance" / "last-run.json"
        hb.parent.mkdir(parents=True)
        hb.write_text(json.dumps({"completed_at": completed_at.isoformat()}))
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def _fresh_failures():
    return [f for f in ce.check_effectiveness(repo_root=_REPO)
            if "assurance" in f]


def test_freshness_na_in_repo_checkout():
    # per-test HERMES_HOME has no ledger → not a deployed host
    assert _fresh_failures() == []


def test_freshness_fails_on_deployed_host_without_job(tmp_path, monkeypatch):
    _deployed(tmp_path, monkeypatch)
    assert _fresh_failures(), "missing assurance heartbeat not flagged"


def test_freshness_fails_when_stale(tmp_path, monkeypatch):
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=72)
    _deployed(tmp_path, monkeypatch, completed_at=old)
    assert _fresh_failures()


def test_freshness_passes_when_recent(tmp_path, monkeypatch):
    _deployed(tmp_path, monkeypatch,
              completed_at=dt.datetime.now(dt.timezone.utc))
    assert _fresh_failures() == []


def test_assurance_job_excludes_its_own_freshness(tmp_path, monkeypatch):
    _deployed(tmp_path, monkeypatch)
    assert ce.check_effectiveness(repo_root=_REPO,
                                  check_assurance_freshness=False) == []


# ---------------------------------------------------------------------------
# ISCM off-host: syslog + OTLP/HTTP
# ---------------------------------------------------------------------------

def test_iscm_path_resolves_home_variable(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    sink = iscm_sink.build_sink({"monitoring": {"iscm_sink": {
        "enabled": True, "path": "$HERMES_HOME/logs/iscm-events.log"}}})
    assert sink.path == tmp_path / "logs" / "iscm-events.log"


def test_syslog_sink_emits(tmp_path):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(5)
    port = srv.getsockname()[1]
    try:
        sink = iscm_sink.build_sink({"monitoring": {"iscm_sink": {
            "enabled": True, "kind": "syslog",
            "syslog_address": f"127.0.0.1:{port}", "syslog_protocol": "udp",
            "path": str(tmp_path / "iscm.log")}}})
        sink.forward({"event": "security.alert", "severity": "critical",
                      "control": "LG-MO-04"})
        data = srv.recv(65535).decode()
    finally:
        srv.close()
    assert '"event": "security.alert"' in data
    assert "security.alert" in (tmp_path / "iscm.log").read_text()  # local copy


def test_syslog_remote_denied_by_egress_stays_local(tmp_path, egress):
    calls, deny = egress
    deny.add("syslog://siem.example.test:514")
    sink = iscm_sink.build_sink({"monitoring": {"iscm_sink": {
        "enabled": True, "kind": "syslog",
        "syslog_address": "siem.example.test:514",
        "path": str(tmp_path / "iscm.log")}}})
    assert ("syslog://siem.example.test:514", "messaging") in calls
    assert sink.refused_reason and sink._syslog is None
    sink.forward({"event": "tool.dispatch"})  # never raises
    assert "tool.dispatch" in (tmp_path / "iscm.log").read_text()


def test_otlp_http_forwarder_posts_logs(tmp_path, egress):
    calls, _ = egress
    posted = []
    ep = "https://otel.example.test/v1/logs"
    sink = iscm_sink.IscmSink(
        kind="otlp_http", fmt="json", path=tmp_path / "iscm.log",
        otlp_endpoint=ep,
        otlp_poster=lambda url, payload, **k: posted.append((url, payload)) or 200)
    sink.forward({"event": "security.alert", "severity": "warning",
                  "control": "LG-MO-02"})
    assert sink.flush(5)
    url, payload = posted[0]
    assert url == ep
    rec = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert rec["severityText"] == "WARN"
    assert json.loads(rec["body"]["stringValue"])["event"] == "security.alert"
    assert (ep, "messaging") in calls


def test_otlp_http_denied_by_egress_is_refused(tmp_path, egress):
    _, deny = egress
    ep = "https://otel.example.test/v1/logs"
    deny.add(ep)
    sink = iscm_sink.IscmSink(kind="otlp_http", fmt="json",
                              path=tmp_path / "iscm.log", otlp_endpoint=ep,
                              otlp_poster=lambda *a, **k: pytest.fail("sent"))
    assert sink._otlp is None and sink.refused_reason
    sink.forward({"event": "tool.dispatch"})
    assert "tool.dispatch" in (tmp_path / "iscm.log").read_text()


def test_gov_overlay_keeps_off_host_disabled():
    data = yaml.safe_load((_REPO / "cli-config.gov.yaml").read_text())
    mon = data["monitoring"]
    assert mon["iscm_sink"]["kind"] == "file"
    assert mon["notify_transport"]["webhook"]["enabled"] is False
    assert mon["notify_transport"]["smtp"]["enabled"] is False
