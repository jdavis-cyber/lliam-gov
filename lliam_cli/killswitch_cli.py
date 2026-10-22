"""Handler for ``lliam-gov killswitch status|engage|release``.

Thin operator surface over :mod:`agent.killswitch`. ``engage`` is a single
atomic local file write (plus a best-effort ledger record and a local
forensic snapshot) — no network, no agent startup. ``release`` requires an
explicit confirmation and delegates to :func:`agent.killswitch.recover`,
which verifies the audit chain, restores and re-verifies the signed
baseline, and records the release in the audit ledger before re-enabling
autonomy.
"""

from __future__ import annotations

import getpass
import json
import socket
import sys
from pathlib import Path
from typing import Optional

CONFIRM_WORD = "RELEASE"


def _default_actor() -> str:
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    try:
        host = socket.gethostname()
    except Exception:
        host = "localhost"
    return f"{user}@{host}"


def _emit(payload: dict, as_json: bool, lines: list[str]) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        for line in lines:
            print(line)


def _status(args) -> int:
    from agent import killswitch as ks
    st = ks.state()
    path = str(ks._state_path())
    if st.get("engaged"):
        lines = [
            "kill-switch: ENGAGED — tool execution and inference are halted",
            f"  reason:     {st.get('reason')}",
            f"  actor:      {st.get('actor')}",
            f"  engaged at: {st.get('engaged_at', 'unknown')}",
        ]
        if st.get("contain_classes"):
            lines.append(f"  contained:  {', '.join(st['contain_classes'])}")
        lines.append("  release with: lliam-gov killswitch release --reason '...'")
    else:
        lines = ["kill-switch: not engaged"]
        if st.get("released_at"):
            lines.append(f"  last released {st['released_at']} by "
                         f"{st.get('released_by')} — {st.get('release_reason')}")
    lines.append(f"  state file: {path}")
    _emit(dict(st, state_file=path), getattr(args, "json", False), lines)
    return 0


def _engage(args) -> int:
    from agent import killswitch as ks
    actor = args.actor or _default_actor()
    st = ks.engage(reason=args.reason, actor=actor,
                   contain_classes=list(args.contain or []))
    payload = dict(st, state_file=str(ks._state_path()))
    lines = [f"kill-switch ENGAGED by {actor} — {args.reason}",
             "  all tool execution and inference are halted on this host"]
    if not args.no_forensics:
        try:
            manifest = ks.preserve_forensics(actor=actor,
                                             reason=f"engage: {args.reason}")
            payload["evidence_dir"] = manifest.get("evidence_dir")
            payload["manifest_sha256"] = manifest.get("manifest_sha256")
            lines.append(f"  forensic snapshot: {manifest.get('evidence_dir')}")
        except Exception as e:  # the halt is already in force
            payload["forensics_error"] = str(e)
            lines.append(f"  warning: forensic snapshot failed ({e}); the halt "
                         "is in force regardless")
    _emit(payload, getattr(args, "json", False), lines)
    return 0


def _confirm(args) -> bool:
    if args.yes:
        return True
    if not sys.stdin.isatty():
        print("refusing: release needs confirmation — pass --yes, or run "
              f"interactively and type {CONFIRM_WORD}", file=sys.stderr)
        return False
    print("This verifies the audit chain, RESTORES the baseline-controlled "
          "files (gov overlay, policy/, critical-keys) from the signed "
          "baseline, and re-enables tool execution and inference.")
    try:
        answer = input(f"Type {CONFIRM_WORD} to confirm: ")
    except EOFError:
        answer = ""
    if answer.strip() != CONFIRM_WORD:
        print("aborted: confirmation not given", file=sys.stderr)
        return False
    return True


def _release(args) -> int:
    from agent import killswitch as ks
    if not ks.is_engaged():
        _emit({"ok": True, "reason": "kill-switch not engaged"},
              getattr(args, "json", False), ["kill-switch: not engaged; nothing to release"])
        return 0
    reason = str(args.reason or "").strip()
    if not reason:
        print("refusing: --reason must not be empty", file=sys.stderr)
        return 2
    dry_run = bool(getattr(args, "dry_run", False))
    if not dry_run and not _confirm(args):
        return 2
    actor = args.actor or _default_actor()
    repo_root: Optional[Path] = Path(args.repo_root).expanduser() if args.repo_root else None
    res = ks.recover(actor=actor, reason=reason, baseline_tag=args.baseline,
                     repo_root=repo_root, dry_run=dry_run)
    if dry_run:
        lines = [f"dry run ({'would release' if res.ok else 'would REFUSE'}) — "
                 "nothing written; the kill-switch stays engaged",
                 f"  audit chain: {(res.chain or {}).get('reason')}",
                 f"  baseline:    {res.baseline_ref} ({(res.baseline_commit or '')[:12]}, "
                 f"{res.baseline_source})"]
        if res.ok:
            lines.append("  would restore: "
                         + (", ".join(res.restored) or "nothing (already at baseline)"))
        else:
            lines.append(f"  reason: {res.reason}")
        lines += [f"  note: {n}" for n in res.notes]
    elif res.ok:
        lines = [f"kill-switch RELEASED by {actor} — {reason}",
                 f"  audit chain: {(res.chain or {}).get('reason')}",
                 f"  baseline:    {res.baseline_ref} ({(res.baseline_commit or '')[:12]}, "
                 f"{res.baseline_source})",
                 f"  restored:    {', '.join(res.restored) if res.restored else 'nothing (already at baseline)'}",
                 f"  evidence:    {res.evidence_dir}"]
        lines += [f"  note: {n}" for n in res.notes]
    else:
        lines = ["kill-switch release REFUSED — the halt stays in force",
                 f"  reason: {res.reason}"]
        if res.evidence_dir:
            lines.append(f"  evidence: {res.evidence_dir}")
    _emit(res.as_dict(), getattr(args, "json", False), lines)
    return 0 if res.ok else 1


def cmd_killswitch(args) -> None:
    """Dispatch ``lliam-gov killswitch <subcmd>``."""
    sub = getattr(args, "killswitch_command", None)
    if sub in (None, "status"):
        code = _status(args)
    elif sub == "engage":
        code = _engage(args)
    elif sub == "release":
        code = _release(args)
    else:
        print(f"unknown killswitch subcommand: {sub}", file=sys.stderr)
        code = 2
    sys.exit(code)
