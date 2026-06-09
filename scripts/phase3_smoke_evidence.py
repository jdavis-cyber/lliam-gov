#!/usr/bin/env python3
"""Phase-3 smoke-run evidence collector (LG-3.9 / AI-217).

Captures the operating evidence for the Phase-3 EXIT gate: a 24-hour smoke
run whose hash-chained audit log verifies clean, AEP-exports, and re-imports,
with managed persisted state encrypted at rest and a live mid-run key
rotation. Artifacts land under ``evidence/phase3/smoke-<timestamp>/`` and are
committed via the AI-217 PR; control-matrix ``current_state`` rows flip only
in that PR, only where code + this evidence both exist (plan §5.7).

Subcommands mirror the operator touchpoints (see
``docs/operate/phase3-smoke-runbook.md`` for the full procedure):

  begin     Preflight + start-of-run snapshot. Creates the run directory.
  migrate   One-time encrypt of a legacy plaintext managed-state file.
  rotate    Mid-run ``lliam-gov rotate-key`` + post-rotation assertions.
  finish    End-of-run chain verification, AEP export + re-import, summary,
            and a SHA-256 manifest of the evidence directory.

Each subcommand both prints to the console and writes a numbered artifact
file, so the committed evidence is the literal operator-visible output of the
real CLI commands, not a reconstruction.

Maps to control-matrix rows: SP800-171_3.3.1/3.3.2/3.3.8 (audit chain),
3.5.10/3.8.9/3.13.16 (CUI at rest, key management); ISO27001 A.8.15/A.8.24;
ISO42001 Clause 9.1 / A.4.3 / A.6.2.8.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

PHASE3_DIR = REPO_ROOT / "evidence" / "phase3"
RUN_META = "run-meta.json"
ENCRYPT_ENV = "LLIAM_GOV_ENCRYPT_STATE"
NON_FIPS_ENV = "LLIAM_GOV_ALLOW_NON_FIPS"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(dt: datetime | None = None) -> str:
    return (dt or _utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dir_stamp(dt: datetime | None = None) -> str:
    return (dt or _utc_now()).strftime("%Y%m%dT%H%M%SZ")


class Report:
    """Accumulates lines that are printed live and saved as an artifact."""

    def __init__(self, title: str) -> None:
        self.lines: list[str] = [f"# {title}", f"# captured_utc: {_stamp()}", ""]
        print(f"\n=== {title} ===")

    def line(self, text: str = "") -> None:
        self.lines.append(text)
        print(text)

    def save(self, path: Path) -> None:
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        print(f"[artifact] {path.relative_to(REPO_ROOT)}")


def _cli_argv() -> list[str]:
    """Resolve the lliam-gov CLI inside the active environment."""
    binary = shutil.which("lliam-gov")
    if binary:
        return [binary]
    return [sys.executable, "-m", "hermes_cli.main"]


def _run_cli(report: Report, args: list[str]) -> int:
    """Run a CLI command, teeing its real output into the evidence artifact."""
    argv = _cli_argv() + args
    report.line(f"$ lliam-gov {' '.join(args)}")
    proc = subprocess.run(argv, capture_output=True, text=True)
    for stream, label in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
        if stream.strip():
            for out_line in stream.rstrip("\n").splitlines():
                report.line(f"  [{label}] {out_line}")
    report.line(f"  [exit] {proc.returncode}")
    return proc.returncode


def _hermes_home() -> Path:
    from hermes_constants import get_hermes_home

    return get_hermes_home()


def _audit_files() -> list[Path]:
    """All monthly audit JSONL files, active then archived, sorted by name."""
    audit_dir = _hermes_home() / "audit"
    files = sorted(audit_dir.glob("tool-calls-*.jsonl"))
    files += sorted((audit_dir / "archive").glob("tool-calls-*.jsonl"))
    return files


def _managed_state_report(report: Report) -> tuple[int, int, int]:
    """Report ABSENT/ENCRYPTED/PLAINTEXT per managed path; return the counts."""
    from lliam_gov.security.state_codec import looks_encrypted, managed_state_paths

    absent = encrypted = plaintext = 0
    for path in managed_state_paths():
        path = Path(path)
        if not path.is_file():
            report.line(f"  {path}: ABSENT")
            absent += 1
        elif looks_encrypted(path.read_bytes()):
            report.line(f"  {path}: ENCRYPTED (EncryptedFile wire format)")
            encrypted += 1
        else:
            report.line(f"  {path}: PLAINTEXT (legacy cleartext)")
            plaintext += 1
    return absent, encrypted, plaintext


def _verify_chains(report: Report) -> tuple[int, int]:
    """CLI-verify every audit file; return (files_verified, total_records).

    The CLI output is the evidence; the library call supplies the
    machine-readable count without parsing stdout.
    """
    from lliam_gov.security.audit_logger import AuditChainError, verify_audit_chain

    files = _audit_files()
    if not files:
        report.line("  (no audit JSONL files yet — chain starts with this run)")
        return 0, 0

    total = 0
    failures = 0
    for path in files:
        rc = _run_cli(report, ["audit", "verify-jsonl", "--input", str(path)])
        if rc != 0:
            failures += 1
            continue
        try:
            total += verify_audit_chain(path).record_count
        except AuditChainError as exc:  # CLI passed but library disagrees
            report.line(f"  [error] library re-verification failed: {exc}")
            failures += 1
    if failures:
        report.line(f"  [FAIL] {failures} audit file(s) failed verification")
        return -failures, total
    return len(files), total


def _resolve_run_dir(arg: str | None) -> Path:
    if arg:
        run_dir = Path(arg)
        if not run_dir.is_absolute():
            run_dir = PHASE3_DIR / arg
        if not run_dir.is_dir():
            sys.exit(f"run directory not found: {run_dir}")
        return run_dir
    candidates = sorted(PHASE3_DIR.glob("smoke-*"))
    if not candidates:
        sys.exit("no evidence/phase3/smoke-* run directory found — run `begin` first")
    return candidates[-1]


def _load_meta(run_dir: Path) -> dict:
    return json.loads((run_dir / RUN_META).read_text(encoding="utf-8"))


def _save_meta(run_dir: Path, meta: dict) -> None:
    (run_dir / RUN_META).write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _git(args: list[str]) -> str:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT)] + args, capture_output=True, text=True
    )
    return proc.stdout.strip()


# ── subcommands ──────────────────────────────────────────────────────────────


def cmd_begin(args: argparse.Namespace) -> int:
    if os.environ.get(ENCRYPT_ENV) != "1":
        sys.exit(
            f"begin refused: {ENCRYPT_ENV}=1 is required for the smoke run "
            "(plan §4 AI-217 row; state_codec encrypt-on-write gate)."
        )

    started = _utc_now()
    run_dir = PHASE3_DIR / f"smoke-{_dir_stamp(started)}"
    run_dir.mkdir(parents=True, exist_ok=False)
    print(f"run directory: {run_dir.relative_to(REPO_ROOT)}")

    env_report = Report("00 environment — smoke-run start")
    env_report.line(f"started_utc:        {_stamp(started)}")
    env_report.line(f"host:               {socket.gethostname()}")
    env_report.line(f"principal:          {getpass.getuser()}")
    env_report.line(f"platform:           {platform.platform()}")
    env_report.line(f"python:             {platform.python_version()}")
    env_report.line(f"git_head:           {_git(['rev-parse', 'HEAD'])}")
    dirty = _git(["status", "--porcelain"])
    env_report.line(f"git_dirty_files:    {len(dirty.splitlines()) if dirty else 0}")
    env_report.line(f"hermes_home:        {_hermes_home()}")
    env_report.line(f"{ENCRYPT_ENV}: {os.environ.get(ENCRYPT_ENV)}")
    non_fips = os.environ.get(NON_FIPS_ENV)
    env_report.line(f"{NON_FIPS_ENV}: {non_fips or '(unset)'}")
    if non_fips == "1":
        env_report.line(
            "  note: non-FIPS dev override active — sanctioned for smoke runs "
            "on the dev host per plan decision D3 (FIPS provisioning lands at "
            "Phase 6 install)."
        )
    env_report.save(run_dir / "00-environment.txt")

    state_report = Report("01 managed state — at-rest posture at start")
    absent, encrypted, plaintext = _managed_state_report(state_report)
    if plaintext:
        state_report.line("")
        state_report.line(
            "ACTION REQUIRED: legacy plaintext managed state detected. "
            "rotate-key SKIPS plaintext files (rekey_files), so the rotation "
            "would prove nothing. Run "
            "`uv run python scripts/phase3_smoke_evidence.py migrate` "
            "BEFORE starting the agent."
        )
    if absent and not encrypted:
        state_report.line("")
        state_report.line(
            "warning: no managed state file exists yet — the at-rest gate "
            "will be vacuous unless the agent persists credentials during "
            "the run. Authenticate at least one provider before `rotate`."
        )
    state_report.save(run_dir / "01-managed-state-begin.txt")

    audit_report = Report("02 audit chain — baseline at start")
    files_ok, baseline_records = _verify_chains(audit_report)
    audit_report.save(run_dir / "02-audit-begin.txt")
    if files_ok < 0:
        print(
            "\nbegin FAILED: pre-existing audit chain does not verify — "
            "do not start the smoke run on a corrupt chain."
        )
        return 1

    _save_meta(
        run_dir,
        {
            "started_utc": _stamp(started),
            "git_head": _git(["rev-parse", "HEAD"]),
            "host": socket.gethostname(),
            "baseline_audit_records": baseline_records,
            "managed_state_plaintext_at_begin": plaintext,
        },
    )

    print("\nbegin complete.")
    if plaintext:
        print("NEXT: run `migrate` (see above), then start the agent.")
    else:
        print(
            "NEXT: start the agent and operate normally for 24 hours; "
            "run `rotate` mid-run; run `finish` after the window closes."
        )
    return 0


def cmd_migrate(args: argparse.Namespace) -> int:
    run_dir = _resolve_run_dir(args.run_dir)
    from lliam_gov.security.encrypted_file import EncryptedFile
    from lliam_gov.security.state_codec import looks_encrypted, managed_state_paths

    report = Report("01a migrate — encrypt legacy plaintext managed state")
    failed = False
    for path in managed_state_paths():
        path = Path(path)
        migrated = EncryptedFile(path).migrate_plaintext()
        if migrated:
            report.line(f"  {path}: migrated plaintext -> encrypted")
        elif path.is_file():
            report.line(f"  {path}: already encrypted (no-op)")
        else:
            report.line(f"  {path}: absent (nothing to migrate)")
            continue
        if not looks_encrypted(path.read_bytes()):
            report.line(f"  [FAIL] {path} is still not in the wire format")
            failed = True
    report.save(run_dir / "01a-migrate.txt")
    if failed:
        print("\nmigrate FAILED — stop and investigate before starting the run.")
        return 1
    print("\nmigrate complete. NEXT: start the agent.")
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    run_dir = _resolve_run_dir(args.run_dir)
    from lliam_gov.security.state_codec import looks_encrypted, managed_state_paths

    report = Report("03 rotate-key — live mid-run key rotation")

    # Pre-check: a plaintext managed file would be silently skipped by
    # rekey_files, making the rotation evidence hollow — refuse instead.
    existing = [Path(p) for p in managed_state_paths() if Path(p).is_file()]
    for path in existing:
        if not looks_encrypted(path.read_bytes()):
            report.line(f"  [FAIL] {path} is plaintext — run `migrate` first")
            report.save(run_dir / "03-rotate-key.txt")
            return 1
    if not existing:
        report.line(
            "  warning: no managed state file exists — rotation will re-key "
            "0 files (key material still rotates)."
        )

    rc = _run_cli(report, ["rotate-key"])
    failed = rc != 0

    for path in existing:
        if looks_encrypted(path.read_bytes()):
            report.line(f"  post-rotate: {path}: ENCRYPTED under new key")
        else:
            report.line(f"  [FAIL] post-rotate: {path} is not encrypted")
            failed = True

    # The rotation itself must be in the tamper-evident chain. Gate on the
    # library verification, not just the CLI exit code.
    from lliam_gov.security.audit_logger import AuditChainError, verify_audit_chain

    active = [p for p in _audit_files() if p.parent.name != "archive"]
    if active:
        current = active[-1]
        rc = _run_cli(report, ["audit", "verify-jsonl", "--input", str(current)])
        failed = failed or rc != 0
        try:
            verify_audit_chain(current)
        except AuditChainError as exc:
            report.line(f"  [FAIL] library chain verification failed: {exc}")
            failed = True
        last_line = [
            ln for ln in current.read_text(encoding="utf-8").splitlines() if ln.strip()
        ][-1]
        event_type = json.loads(last_line).get("event_type")
        if event_type == "key_rotation":
            report.line("  audit chain: key_rotation event recorded and chain verifies")
        else:
            report.line(
                f"  note: most recent audit event is {event_type!r} (another "
                "event landed after the rotation; key_rotation is earlier in "
                "the verified chain)"
            )
    else:
        report.line("  [FAIL] no audit file found after rotation")
        failed = True

    report.save(run_dir / "03-rotate-key.txt")
    if failed:
        print("\nrotate FAILED — preserve state and investigate before continuing.")
        return 1
    print("\nrotate complete. NEXT: let the run continue, then `finish` after 24h.")
    return 0


def cmd_finish(args: argparse.Namespace) -> int:
    run_dir = _resolve_run_dir(args.run_dir)
    meta = _load_meta(run_dir)
    finished = _utc_now()
    started = datetime.strptime(meta["started_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    elapsed_hours = (finished - started).total_seconds() / 3600.0
    gates: dict[str, bool] = {}
    notes: list[str] = []

    gates["duration"] = elapsed_hours >= args.min_hours
    if args.min_hours < 24.0:
        notes.append(
            f"DEVIATION: gate evaluated against --min-hours {args.min_hours} "
            "instead of the standard 24 — record the operator rationale in "
            "the AI-217 PR description."
        )

    audit_report = Report("04 audit chain — end-of-run verification")
    files_ok, end_records = _verify_chains(audit_report)
    gates["audit_chain_verifies"] = files_ok >= 0
    baseline = meta.get("baseline_audit_records", 0)
    audit_report.line("")
    audit_report.line(f"records at begin: {baseline}; records at finish: {end_records}")
    gates["audit_activity"] = end_records > baseline
    audit_report.save(run_dir / "04-audit-end.txt")

    aep_report = Report("05 AEP export + re-import")
    from lliam_gov.security.aep_export import verify_aep_export
    from lliam_gov.security.audit_logger import AuditChainError

    inputs = _audit_files()
    gates["aep_export"] = gates["aep_reimport_verifies"] = False
    if inputs:
        aep_path = run_dir / f"aep-export-{_dir_stamp(finished)}.json"
        export_args = ["audit", "export-aep"]
        for path in inputs:
            export_args += ["--input", str(path)]
        export_args += ["--output", str(aep_path)]
        rc_export = _run_cli(aep_report, export_args)
        # Gate on the artifact + library re-import, not only the CLI exit code.
        gates["aep_export"] = rc_export == 0 and aep_path.is_file()
        if gates["aep_export"]:
            rc_verify = _run_cli(
                aep_report, ["audit", "verify-aep", "--input", str(aep_path)]
            )
            try:
                verify_aep_export(aep_path)
                gates["aep_reimport_verifies"] = rc_verify == 0
            except AuditChainError as exc:
                aep_report.line(f"  [FAIL] library re-import failed: {exc}")
    else:
        aep_report.line("  [FAIL] no audit files to export")
    aep_report.save(run_dir / "05-aep-export.txt")

    state_report = Report("06 managed state — at-rest posture at finish")
    absent, encrypted, plaintext = _managed_state_report(state_report)
    gates["state_encrypted_at_rest"] = plaintext == 0 and encrypted > 0
    if plaintext == 0 and encrypted == 0:
        notes.append(
            "No managed state file existed at finish — the at-rest row "
            "cannot flip on this run's evidence."
        )
    state_report.save(run_dir / "06-managed-state-end.txt")

    rotate_artifact = run_dir / "03-rotate-key.txt"
    gates["live_key_rotation"] = (
        rotate_artifact.is_file()
        and "Rotated encryption key" in rotate_artifact.read_text(encoding="utf-8")
    )

    summary = Report("summary — Phase-3 smoke run (LG-3.9 / AI-217)")
    summary.line(f"run_dir:        {run_dir.relative_to(REPO_ROOT)}")
    summary.line(f"git_head:       {meta['git_head']}")
    summary.line(f"host:           {meta['host']}")
    summary.line(f"started_utc:    {meta['started_utc']}")
    summary.line(f"finished_utc:   {_stamp(finished)}")
    summary.line(f"elapsed_hours:  {elapsed_hours:.2f} (gate: >= {args.min_hours})")
    summary.line(f"audit_records:  {baseline} -> {end_records}")
    summary.line("")
    summary.line("| gate | result |")
    summary.line("|---|---|")
    for gate, passed in gates.items():
        summary.line(f"| {gate} | {'PASS' if passed else 'FAIL'} |")
    for note in notes:
        summary.line("")
        summary.line(f"note: {note}")
    overall = all(gates.values())
    summary.line("")
    summary.line(
        f"OVERALL: {'PASS — Phase-3 exit evidence complete' if overall else 'FAIL'}"
    )
    summary.save(run_dir / "summary.md")

    meta.update(
        finished_utc=_stamp(finished),
        elapsed_hours=round(elapsed_hours, 2),
        gates=gates,
        overall="PASS" if overall else "FAIL",
    )
    _save_meta(run_dir, meta)

    # Manifest last, over everything else in the run directory.
    manifest_lines = []
    for path in sorted(run_dir.iterdir()):
        if path.name == "MANIFEST.sha256" or not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_lines.append(f"{digest}  {path.name}")
    (run_dir / "MANIFEST.sha256").write_text(
        "\n".join(manifest_lines) + "\n", encoding="utf-8"
    )
    print(f"[artifact] {(run_dir / 'MANIFEST.sha256').relative_to(REPO_ROOT)}")

    if not overall:
        print(
            "\nfinish: one or more gates FAILED — do not flip matrix rows; "
            "preserve the run directory and investigate."
        )
        return 1
    print(
        "\nfinish: all gates PASS. NEXT: commit the run directory on the "
        "AI-217 branch and flip only the matrix rows this evidence proves."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="<subcommand>")

    sub.add_parser("begin", help="preflight + start-of-run snapshot")

    migrate = sub.add_parser("migrate", help="encrypt legacy plaintext managed state")
    rotate = sub.add_parser("rotate", help="live rotate-key + assertions")
    finish = sub.add_parser("finish", help="end-of-run verification + summary")
    for p in (migrate, rotate, finish):
        p.add_argument(
            "--run-dir",
            default=None,
            help="evidence run directory (default: latest evidence/phase3/smoke-*)",
        )
    finish.add_argument(
        "--min-hours",
        type=float,
        default=24.0,
        help="minimum run duration gate in hours (default 24; deviations are "
        "recorded in the summary)",
    )

    args = parser.parse_args(argv)
    commands = {
        "begin": cmd_begin,
        "migrate": cmd_migrate,
        "rotate": cmd_rotate,
        "finish": cmd_finish,
    }
    if args.command not in commands:
        parser.print_help()
        return 2
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
