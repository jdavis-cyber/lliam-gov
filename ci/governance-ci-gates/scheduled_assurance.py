#!/usr/bin/env python3
"""scheduled_assurance.py — the recurring assurance job on a deployed host
(LG-MO-07/08/09 + LG-GV-07 cATO, JER-76).

One run, in order:
  1. control-effectiveness (LG-MO-08) against the deployed overlay
     (HERMES_CONFIG), not the repo copy;
  2. scheduled red-team corpus (LG-MO-07) → report under
     ``<home>/logs/assurance``;
  3. governance metrics (LG-MO-09) from the real ledger;
  4. the cATO cycle (``agent.cato_loop.run_cato_cycle``) over the
     effectiveness failures + the ISCM ``security.alert`` events raised since
     the previous run. A posture break auto-suspends via the kill-switch per
     the cycle's existing logic (only when ``cato.enabled`` and
     ``cato.auto_suspend_on_break``; otherwise it is evaluated and reported);
  5. a notification for any break, then redelivery of notifications still
     owed a delivery (``agent.notify_transport``);
  6. a heartbeat ``<home>/logs/assurance/last-run.json`` plus one line in
     ``runs.jsonl`` — the freshness record control_effectiveness asserts on a
     deployed host.

The job excludes its own freshness from step 1 (it is running now; a gap
after host sleep must not self-suspend). A gap since the previous run is
reported and notified instead.

Exit: 0 = all green, 1 = a break (effectiveness / red-team / cATO suspend),
2 = error. Wrapped by scheduled_assurance_cron.sh; installed by
``lliam-gov assurance install``.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any, Callable, Optional

_GATES = Path(__file__).resolve().parent
_REPO_ROOT = _GATES.parents[1]
for _p in (str(_GATES), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

ACTOR = "scheduled-assurance"
_HEARTBEAT = Path("logs") / "assurance" / "last-run.json"


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _home(home: Optional[Path]) -> Path:
    if home is not None:
        return Path(home)
    from agent import notify_transport as _nt
    return _nt.lliam_home()


def _overlay_path(repo_root: Path) -> Path:
    raw = os.environ.get("LLIAM_CONFIG") or os.environ.get("HERMES_CONFIG")
    if raw:
        p = Path(raw).expanduser()
        for cand in (p, repo_root / p):
            if cand.is_file():
                return cand
    return repo_root / "cli-config.gov.yaml"


def _load_config(overlay: Path) -> dict:
    try:
        from lliam_cli import config as _cfg
        cfg = _cfg.load_config()
        if isinstance(cfg, dict) and cfg.get("monitoring") is not None:
            return cfg
    except Exception:
        pass
    try:
        import yaml
        return yaml.safe_load(overlay.read_text("utf-8")) or {}
    except Exception:
        return {}


def read_heartbeat(home: Path) -> Optional[dict]:
    try:
        data = json.loads((home / _HEARTBEAT).read_text("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _write_heartbeat(home: Path, beat: dict) -> Path:
    path = home / _HEARTBEAT
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(beat, indent=2, sort_keys=True), "utf-8")
    os.replace(tmp, path)
    with open(path.parent / "runs.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(beat, sort_keys=True) + "\n")
    return path


def iscm_alerts_since(config: dict, since: Optional[_dt.datetime]) -> list:
    """``AlertView``s for ISCM ``security.alert`` events after ``since``."""
    from agent import cato_loop as cato
    from agent import notify_transport as _nt
    mon = config.get("monitoring") if isinstance(config, dict) else None
    spec = (mon or {}).get("iscm_sink") if isinstance(mon, dict) else None
    path = _nt.resolve_path((spec or {}).get("path"))
    if path is None or not path.is_file():
        return []
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("event") != "security.alert":
                continue
            if since is not None:
                try:
                    ts = _dt.datetime.fromisoformat(str(rec.get("ts_ingest")))
                except ValueError:
                    continue
                if ts <= since:
                    continue
            out.append(cato.AlertView(control=str(rec.get("control") or "?"),
                                      severity=str(rec.get("severity") or "")))
    return out


def run_assurance(*, repo_root: Path = _REPO_ROOT,
                  home: Optional[Path] = None,
                  config: Optional[dict] = None,
                  overlay_path: Optional[Path] = None,
                  stamp: Optional[str] = None,
                  run_redteam: bool = True,
                  lookback_hours: float = 24.0,
                  dispatcher: Any = None,
                  cato_cycle: Optional[Callable[..., Any]] = None,
                  now: Optional[_dt.datetime] = None) -> dict:
    """Run one assurance cycle; return the heartbeat dict (also written)."""
    import control_effectiveness as ce
    import governance_metrics as gm
    from agent import cato_loop as cato
    from agent import notify_transport as _nt

    started = now or _utcnow()
    home = _home(home)
    overlay = overlay_path or _overlay_path(repo_root)
    config = config if config is not None else _load_config(overlay)
    stamp = stamp or started.strftime("%Y%m%dT%H%M%SZ")
    report_dir = home / "logs" / "assurance"
    previous = read_heartbeat(home)
    beat: dict = {"schema": "lg-mo/assurance-heartbeat/1",
                  "host": socket.gethostname(),
                  "started_at": started.isoformat(timespec="seconds"),
                  "overlay": str(overlay), "errors": []}

    # 1. control effectiveness (own freshness excluded — see module doc)
    try:
        failures = ce.check_effectiveness(repo_root=repo_root,
                                          overlay_path=overlay,
                                          check_assurance_freshness=False)
    except Exception as e:
        failures = []
        beat["errors"].append(f"control_effectiveness: {e}")
    beat["effectiveness_failures"] = failures

    # 2. red-team
    if run_redteam:
        try:
            import scheduled_redteam as sr
            rt = sr.run_redteam(repo_root=repo_root, report_dir=report_dir,
                                stamp=stamp)
            beat["redteam"] = {k: rt.get(k) for k in
                               ("total", "passed", "failed", "exit_code")}
            if not rt.get("total"):
                beat["errors"].append("red-team corpus produced no results")
        except Exception as e:
            beat["errors"].append(f"scheduled_redteam: {e}")

    # 3. metrics
    ledger = home / "logs" / "agent-audit.log"
    if ledger.is_file():
        try:
            beat["metrics"] = gm.compute_metrics(ledger_path=ledger)
        except Exception as e:
            beat["errors"].append(f"governance_metrics: {e}")

    # 4. cATO cycle
    since = None
    if previous and previous.get("started_at"):
        try:
            since = _dt.datetime.fromisoformat(str(previous["started_at"]))
        except ValueError:
            since = None
    if since is None:
        since = started - _dt.timedelta(hours=lookback_hours)
    alerts = iscm_alerts_since(config, since)
    cato_cfg = config.get("cato") if isinstance(config.get("cato"), dict) \
        else {}
    auto_suspend = bool(cato_cfg.get("enabled")) and bool(
        cato_cfg.get("auto_suspend_on_break", True))
    try:
        if auto_suspend:
            verdict = (cato_cycle or cato.run_cato_cycle)(
                alerts=alerts, effectiveness_failures=failures,
                actor=ACTOR, repo_root=repo_root)
        else:
            verdict = cato.evaluate(alerts=alerts,
                                    effectiveness_failures=failures)
        beat["cato"] = {"suspend": bool(verdict.suspend),
                        "reason": verdict.reason,
                        "auto_suspend_enabled": auto_suspend,
                        "alerts_considered": len(alerts)}
    except Exception as e:
        beat["errors"].append(f"cato: {e}")
        beat["cato"] = {"suspend": False, "reason": f"error: {e}",
                        "auto_suspend_enabled": auto_suspend,
                        "alerts_considered": len(alerts)}

    # gap since the previous completed run (reported, never self-suspends)
    max_age = float(((config.get("monitoring") or {}).get("assurance") or {})
                    .get("max_age_hours") or ce._ASSURANCE_MAX_AGE_HOURS)
    if previous and previous.get("completed_at"):
        try:
            gap = (started - _dt.datetime.fromisoformat(
                str(previous["completed_at"]))).total_seconds() / 3600
            beat["hours_since_previous"] = round(gap, 2)
            beat["gap_exceeded"] = gap > max_age
        except ValueError:
            pass

    rt_failed = bool((beat.get("redteam") or {}).get("failed"))
    broke = bool(failures) or rt_failed or beat["cato"]["suspend"]
    beat["ok"] = not broke and not beat["errors"]

    # 5. notify + redeliver
    try:
        disp = dispatcher or _nt.NotificationDispatcher(config)
        problems = []
        if beat["cato"]["suspend"]:
            what = ("AUTO-SUSPEND" if auto_suspend
                    else "posture break (auto-suspend off)")
            problems.append(f"cATO {what}: {beat['cato']['reason']}")
        problems += failures[:3]
        if rt_failed:
            problems.append(f"red-team regression: "
                            f"{beat['redteam']['failed']} case(s) failed")
        problems += beat["errors"][:3]
        if beat.get("gap_exceeded"):
            problems.append(f"assurance gap: {beat['hours_since_previous']}h "
                            f"since the previous run (max {max_age}h)")
        if problems:
            sev = "critical" if broke else "warning"
            disp.dispatch(severity=sev, session="scheduled-assurance",
                          summary="; ".join(problems))
            if hasattr(disp, "flush"):
                disp.flush(timeout=30)
        beat["redelivery"] = _nt.redeliver_pending(config, dispatcher=disp)
    except Exception as e:
        beat["errors"].append(f"notify: {e}")

    # 6. heartbeat
    beat["completed_at"] = _utcnow().isoformat(timespec="seconds") \
        if now is None else started.isoformat(timespec="seconds")
    try:
        beat["heartbeat"] = str(_write_heartbeat(home, beat))
    except Exception as e:
        beat["errors"].append(f"heartbeat: {e}")
    return beat


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--skip-redteam", action="store_true",
                        help="skip the red-team corpus (needs pytest)")
    args = parser.parse_args(argv)
    try:
        beat = run_assurance(repo_root=Path(args.repo_root),
                             stamp=args.stamp,
                             run_redteam=not args.skip_redteam)
    except Exception as e:  # pragma: no cover
        print(f"scheduled_assurance: error ({e})")
        return 2
    print(json.dumps({"job": "scheduled-assurance", **beat}, indent=2,
                     sort_keys=True, default=str))
    if beat["effectiveness_failures"] or beat["cato"]["suspend"] or (
            (beat.get("redteam") or {}).get("failed")):
        print("[assurance] BREAK — see effectiveness_failures / redteam / "
              "cato above")
        return 1
    if beat["errors"]:
        print("[assurance] ERROR — a job step could not run (see errors)")
        return 2
    print("[assurance] OK — control-effectiveness + red-team green; cATO "
          "steady state; metrics recorded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
