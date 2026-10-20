"""``lliam-gov assurance`` — install / remove / inspect the scheduled
assurance job (JER-76).

The job (``ci/governance-ci-gates/scheduled_assurance_cron.sh`` →
``scheduled_assurance.py``) runs control-effectiveness, the red-team corpus,
governance metrics and the cATO cycle, and writes a freshness heartbeat. This
module puts it on a schedule:

* macOS — a launchd agent ``~/Library/LaunchAgents/<label>.plist`` with
  ``StartCalendarInterval`` (a run missed while asleep fires on wake);
* Linux — a systemd *user* service + timer under
  ``~/.config/systemd/user/`` with ``Persistent=true``.

Both pin ``HERMES_HOME`` / ``HERMES_CONFIG`` / ``LLIAM_PYTHON`` (the cron
script fails closed without the first two). ``--dest-dir`` writes the unit
files somewhere else and ``--no-activate`` skips launchctl / systemctl, so
the rendering can be inspected or tested without touching the real system.
"""
from __future__ import annotations

import argparse
import json
import os
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

LAUNCHD_LABEL = "com.secondorderstrategy.lliam-gov.assurance"
SYSTEMD_NAME = "lliam-gov-assurance"
_REPO_ROOT = Path(__file__).resolve().parents[1]
_CRON_SCRIPT = Path("ci") / "governance-ci-gates" / "scheduled_assurance_cron.sh"
_HEARTBEAT = Path("logs") / "assurance" / "last-run.json"

Runner = Callable[[list], "subprocess.CompletedProcess"]


def _home() -> Path:
    try:
        from lliam_constants import get_lliam_home
        return Path(get_lliam_home()).expanduser().resolve()
    except Exception:
        return (Path.home() / ".lliam").resolve()


def _overlay(home: Path, repo_root: Path) -> Path:
    raw = os.environ.get("LLIAM_CONFIG") or os.environ.get("HERMES_CONFIG")
    if raw:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = (Path.cwd() / p) if (Path.cwd() / p).is_file() else repo_root / p
        return p.resolve()
    for cand in (home / "cli-config.gov.yaml", repo_root / "cli-config.gov.yaml"):
        if cand.is_file():
            return cand.resolve()
    return (repo_root / "cli-config.gov.yaml").resolve()


def job_env(*, home: Path, overlay: Path, python: str) -> dict:
    return {"HERMES_HOME": str(home), "HERMES_CONFIG": str(overlay),
            "LLIAM_PYTHON": python, "PATH": "/usr/local/bin:/usr/bin:/bin"}


def render_launchd_plist(*, repo_root: Path, home: Path, overlay: Path,
                         python: str, hour: int, minute: int) -> bytes:
    log = home / "logs" / "assurance" / "assurance.log"
    doc = {
        "Label": LAUNCHD_LABEL,
        "ProgramArguments": ["/bin/bash", str(repo_root / _CRON_SCRIPT)],
        "EnvironmentVariables": job_env(home=home, overlay=overlay,
                                        python=python),
        "WorkingDirectory": str(home),
        "StartCalendarInterval": {"Hour": int(hour), "Minute": int(minute)},
        "RunAtLoad": False,
        "StandardOutPath": str(log),
        "StandardErrorPath": str(log),
        "ProcessType": "Background",
    }
    return plistlib.dumps(doc, sort_keys=False)


def _q(v: str) -> str:
    """systemd Environment= quoting."""
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_systemd_units(*, repo_root: Path, home: Path, overlay: Path,
                         python: str, hour: int, minute: int) -> dict:
    env = job_env(home=home, overlay=overlay, python=python)
    env_lines = "\n".join(f"Environment={_q(f'{k}={v}')}"
                          for k, v in env.items())
    service = (
        "[Unit]\n"
        "Description=Lliam-GOV scheduled assurance (control-effectiveness, "
        "red-team, metrics, cATO)\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"{env_lines}\n"
        f"WorkingDirectory={home}\n"
        f"ExecStart=/bin/bash {_q(str(repo_root / _CRON_SCRIPT))}\n"
    )
    timer = (
        "[Unit]\n"
        "Description=Daily Lliam-GOV scheduled assurance\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar=*-*-* {int(hour):02d}:{int(minute):02d}:00\n"
        "Persistent=true\n"
        f"Unit={SYSTEMD_NAME}.service\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    return {f"{SYSTEMD_NAME}.service": service,
            f"{SYSTEMD_NAME}.timer": timer}


def _platform() -> str:
    return "launchd" if sys.platform == "darwin" else "systemd"


def default_dest(platform: str) -> Path:
    if platform == "launchd":
        return Path.home() / "Library" / "LaunchAgents"
    return Path.home() / ".config" / "systemd" / "user"


def _run(cmd: list) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def install(*, platform: Optional[str] = None, dest_dir: Optional[Path] = None,
            activate: bool = True, hour: int = 7, minute: int = 23,
            repo_root: Path = _REPO_ROOT, home: Optional[Path] = None,
            overlay: Optional[Path] = None, python: Optional[str] = None,
            runner: Runner = _run) -> list[Path]:
    platform = platform or _platform()
    home = Path(home) if home else _home()
    overlay = Path(overlay) if overlay else _overlay(home, repo_root)
    python = python or sys.executable
    dest = Path(dest_dir) if dest_dir else default_dest(platform)
    dest.mkdir(parents=True, exist_ok=True)
    (home / "logs" / "assurance").mkdir(parents=True, exist_ok=True)
    kw = dict(repo_root=repo_root, home=home, overlay=overlay, python=python,
              hour=hour, minute=minute)
    written: list[Path] = []
    if platform == "launchd":
        p = dest / f"{LAUNCHD_LABEL}.plist"
        p.write_bytes(render_launchd_plist(**kw))
        written.append(p)
        if activate:
            uid = str(os.getuid())  # windows-footgun: ok — launchd branch, macOS only
            runner(["launchctl", "bootout", f"gui/{uid}", str(p)])
            res = runner(["launchctl", "bootstrap", f"gui/{uid}", str(p)])
            if res.returncode != 0:
                raise RuntimeError(f"launchctl bootstrap failed: "
                                   f"{(res.stderr or res.stdout).strip()}")
    elif platform == "systemd":
        for name, text in render_systemd_units(**kw).items():
            p = dest / name
            p.write_text(text, encoding="utf-8")
            written.append(p)
        if activate:
            for cmd in (["systemctl", "--user", "daemon-reload"],
                        ["systemctl", "--user", "enable", "--now",
                         f"{SYSTEMD_NAME}.timer"]):
                res = runner(cmd)
                if res.returncode != 0:
                    raise RuntimeError(f"{' '.join(cmd)} failed: "
                                       f"{(res.stderr or res.stdout).strip()}")
    else:
        raise ValueError(f"unknown platform {platform!r}")
    return written


def uninstall(*, platform: Optional[str] = None,
              dest_dir: Optional[Path] = None, activate: bool = True,
              runner: Runner = _run) -> list[Path]:
    platform = platform or _platform()
    dest = Path(dest_dir) if dest_dir else default_dest(platform)
    removed: list[Path] = []
    if platform == "launchd":
        p = dest / f"{LAUNCHD_LABEL}.plist"
        if activate and p.exists():
            runner(["launchctl", "bootout", f"gui/{os.getuid()}", str(p)])  # windows-footgun: ok — launchd branch
        paths = [p]
    else:
        if activate:
            runner(["systemctl", "--user", "disable", "--now",
                    f"{SYSTEMD_NAME}.timer"])
        paths = [dest / f"{SYSTEMD_NAME}.timer",
                 dest / f"{SYSTEMD_NAME}.service"]
    for p in paths:
        if p.exists():
            p.unlink()
            removed.append(p)
    if platform == "systemd" and activate:
        runner(["systemctl", "--user", "daemon-reload"])
    return removed


def status(*, platform: Optional[str] = None, dest_dir: Optional[Path] = None,
           home: Optional[Path] = None, max_age_hours: float = 26.0) -> dict:
    import datetime as _dt
    platform = platform or _platform()
    dest = Path(dest_dir) if dest_dir else default_dest(platform)
    home = Path(home) if home else _home()
    unit = (dest / f"{LAUNCHD_LABEL}.plist" if platform == "launchd"
            else dest / f"{SYSTEMD_NAME}.timer")
    out = {"platform": platform, "installed": unit.exists(),
           "unit": str(unit), "heartbeat": str(home / _HEARTBEAT),
           "last_run": None, "age_hours": None, "fresh": False}
    try:
        beat = json.loads((home / _HEARTBEAT).read_text("utf-8"))
        done = _dt.datetime.fromisoformat(str(beat["completed_at"]))
        age = (_dt.datetime.now(_dt.timezone.utc) - done).total_seconds() / 3600
        out.update(last_run=beat["completed_at"], age_hours=round(age, 2),
                   fresh=age <= max_age_hours, ok=beat.get("ok"),
                   cato=beat.get("cato"))
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# argparse wiring (called from lliam_cli.main)
# ---------------------------------------------------------------------------

def _cmd_install(args) -> int:
    try:
        paths = install(platform=args.platform, dest_dir=args.dest_dir,
                        activate=not args.no_activate, hour=args.hour,
                        minute=args.minute)
    except Exception as e:
        print(f"assurance install failed: {e}", file=sys.stderr)
        return 1
    for p in paths:
        print(f"wrote {p}")
    if args.no_activate:
        print("not activated (--no-activate)")
    else:
        print(f"scheduled daily at {args.hour:02d}:{args.minute:02d} local time")
    return 0


def _cmd_uninstall(args) -> int:
    removed = uninstall(platform=args.platform, dest_dir=args.dest_dir,
                        activate=not args.no_activate)
    for p in removed:
        print(f"removed {p}")
    if not removed:
        print("nothing installed")
    return 0


def _max_age_hours() -> float:
    try:
        import yaml
        cfg = yaml.safe_load(_overlay(_home(), _REPO_ROOT).read_text("utf-8"))
        return float(((cfg.get("monitoring") or {}).get("assurance") or {})
                     .get("max_age_hours") or 26.0)
    except Exception:
        return 26.0


def _cmd_status(args) -> int:
    st = status(platform=args.platform, dest_dir=args.dest_dir,
                max_age_hours=_max_age_hours())
    print(json.dumps(st, indent=2, sort_keys=True, default=str))
    return 0 if (st["installed"] and st["fresh"]) else 1


def _cmd_run(args) -> int:
    script = _REPO_ROOT / _CRON_SCRIPT
    env = dict(os.environ)
    home = _home()
    env.setdefault("HERMES_HOME", str(home))
    env.setdefault("HERMES_CONFIG", str(_overlay(home, _REPO_ROOT)))
    env.setdefault("LLIAM_PYTHON", sys.executable)
    return subprocess.call(["/bin/bash", str(script)], env=env)


def _exiting(fn):
    """main() ignores handler return values; surface a nonzero status."""
    def _wrapped(args):
        rc = fn(args)
        if rc:
            sys.exit(rc)
        return rc
    return _wrapped


def register_cli(parent: argparse.ArgumentParser) -> None:
    """Attach ``assurance`` subcommands to *parent*."""
    parent.set_defaults(func=lambda a: (parent.print_help(), 0)[1])
    subs = parent.add_subparsers(dest="assurance_command")

    def _common(p):
        p.add_argument("--platform", choices=["launchd", "systemd"],
                       default=None,
                       help="default: launchd on macOS, systemd elsewhere")
        p.add_argument("--dest-dir", type=Path, default=None,
                       help="write unit files here instead of the user's "
                            "LaunchAgents / systemd user directory")

    p_install = subs.add_parser(
        "install", help="Install the daily assurance job (launchd / systemd "
                        "user timer)")
    _common(p_install)
    p_install.add_argument("--hour", type=int, default=7)
    p_install.add_argument("--minute", type=int, default=23)
    p_install.add_argument("--no-activate", action="store_true",
                           help="write the files only; do not call "
                                "launchctl / systemctl")
    p_install.set_defaults(func=_exiting(_cmd_install))

    p_uninstall = subs.add_parser("uninstall",
                                  help="Remove the scheduled assurance job")
    _common(p_uninstall)
    p_uninstall.add_argument("--no-activate", action="store_true",
                             help="remove the files only")
    p_uninstall.set_defaults(func=_exiting(_cmd_uninstall))

    p_status = subs.add_parser(
        "status", help="Show whether the job is installed and its last run "
                       "(exit 1 if missing or stale)")
    _common(p_status)
    p_status.set_defaults(func=_exiting(_cmd_status))

    p_run = subs.add_parser("run", help="Run the assurance job once now")
    p_run.set_defaults(func=_exiting(_cmd_run))
