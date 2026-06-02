#!/usr/bin/env python3
"""Phase 3 runtime smoke harness for Lliam-GOV audit/encryption evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
from types import SimpleNamespace
import sys
import time
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hermes_constants import get_hermes_home
from lliam_gov.security.audit_logger import AuditLogger, verify_audit_chain
from lliam_gov.security.gateway_audit import audit_gateway_auth
from lliam_gov.security.state_codec import (
    STATE_ENCRYPTION_ENV,
    decode_state_bytes,
    encode_state_bytes,
)


DEFAULT_CADENCE_SECONDS = 300
DEFAULT_HEARTBEAT_SECONDS = 60
DEFAULT_SLEEP_GAP_THRESHOLD_SECONDS = 5
END_EVENT_TYPE = "phase3_smoke_end"


class Phase3SmokeConfig:
    """Runtime configuration for the Phase 3 smoke harness."""

    def __init__(
        self,
        *,
        audit_dir: str | Path | None = None,
        output_dir: str | Path | None = None,
        cadence_seconds: int = DEFAULT_CADENCE_SECONDS,
        heartbeat_seconds: int = DEFAULT_HEARTBEAT_SECONDS,
        sleep_gap_threshold_seconds: int = DEFAULT_SLEEP_GAP_THRESHOLD_SECONDS,
        pid_file: str | Path | None = None,
        session_id: str = "phase3-smoke",
        principal: str | None = None,
        host: str | None = None,
    ) -> None:
        home = get_hermes_home()
        self.audit_dir = Path(audit_dir) if audit_dir is not None else home / "audit"
        self.output_dir = (
            Path(output_dir) if output_dir is not None else home / "phase3_smoke"
        )
        self.cadence_seconds = int(cadence_seconds)
        self.heartbeat_seconds = int(heartbeat_seconds)
        self.sleep_gap_threshold_seconds = int(sleep_gap_threshold_seconds)
        self.pid_file = (
            Path(pid_file)
            if pid_file is not None
            else Path.home() / ".lliam-gov" / "phase3_smoke.pid"
        )
        self.session_id = session_id
        self.principal = principal or os.getenv("USER") or os.getenv("LOGNAME") or "unknown"
        self.host = host

    @property
    def heartbeat_file(self) -> Path:
        return self.output_dir / "phase3-smoke-heartbeat.json"

    @property
    def manifest_file(self) -> Path:
        return self.output_dir / "phase3-smoke-manifest.json"

    @property
    def emissions_file(self) -> Path:
        return self.output_dir / "phase3-smoke-emissions.jsonl"

    @property
    def synthetic_state_file(self) -> Path:
        return self.output_dir / "phase3-smoke-state.bin"


class Phase3SmokeResult:
    """Summary returned after a harness run exits."""

    def __init__(self, *, audit_path: Path, record_count: int, last_hash: str) -> None:
        self.audit_path = audit_path
        self.record_count = record_count
        self.last_hash = last_hash


class Phase3SmokeHarness:
    """Emit controlled Phase 3 smoke events on a cadence."""

    def __init__(
        self,
        config: Phase3SmokeConfig,
        *,
        clock: Any = time,
        sleep: Callable[[float], None] | None = None,
        logger: AuditLogger | None = None,
    ) -> None:
        self.config = config
        self.clock = clock
        self._sleep = sleep or clock.sleep
        self.logger = logger or AuditLogger(
            audit_dir=config.audit_dir,
            session_id=config.session_id,
            principal=config.principal,
            host=config.host,
        )
        self._stop_requested = False
        self._stop_signal: int | None = None
        self._heartbeat_count = 0
        self._iteration = 0
        self._sleep_gaps: list[dict[str, Any]] = []
        self._last_record_hash = self.logger.GENESIS_HASH

    def request_stop(self, signum: int | None = None, _frame: Any = None) -> None:
        self._stop_requested = True
        self._stop_signal = signum

    def run(
        self,
        *,
        max_iterations: int | None = None,
        duration_seconds: int | None = None,
    ) -> Phase3SmokeResult:
        self._prepare_runtime_files()
        deadline = None if duration_seconds is None else self.clock.time() + duration_seconds
        try:
            self._write_manifest(status="running")
            while not self._stop_requested:
                if max_iterations is not None and self._iteration >= max_iterations:
                    break
                if deadline is not None and self.clock.time() >= deadline:
                    break
                self._iteration += 1
                self._emit_iteration(self._iteration)
                if max_iterations is not None and self._iteration >= max_iterations:
                    break
                if deadline is not None and self.clock.time() >= deadline:
                    break
                self._cadence_sleep(deadline=deadline)
        finally:
            self._emit_end_event()
            verification = self.logger.verify_current_month()
            self._write_manifest(
                status="stopped",
                final_last_hash=verification.last_hash,
                record_count=verification.record_count,
            )
            self._write_heartbeat(status="stopped")
            self._remove_pid_file()
        return Phase3SmokeResult(
            audit_path=verification.path,
            record_count=verification.record_count,
            last_hash=verification.last_hash,
        )

    def _prepare_runtime_files(self) -> None:
        self.config.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.config.output_dir, 0o700)
        self.config.pid_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.config.pid_file.write_text(str(os.getpid()), encoding="utf-8")
        os.chmod(self.config.pid_file, 0o600)
        self._append_emission(
            {
                "event_type": "phase3_smoke_start",
                "timestamp_unix": self.clock.time(),
                "pid": os.getpid(),
                "cadence_seconds": self.config.cadence_seconds,
                "heartbeat_seconds": self.config.heartbeat_seconds,
                STATE_ENCRYPTION_ENV: os.environ.get(STATE_ENCRYPTION_ENV),
            }
        )
        self._write_heartbeat(status="running")

    def _emit_iteration(self, iteration: int) -> None:
        source = SimpleNamespace(
            user_id=f"phase3-smoke-user-{iteration}",
            user_name="phase3_smoke",
            chat_id=f"phase3-smoke-chat-{iteration}",
            chat_type="dm",
            platform=SimpleNamespace(value="phase3_smoke"),
            is_bot=False,
        )
        audit_gateway_auth(source, authorized=True, logger=self.logger)
        self._capture_last_record("gateway_auth", iteration)

        tool_call_id = f"phase3-smoke-tool-{iteration}"
        self._log_event(
            "tool_call_start",
            iteration,
            tool_name="phase3_smoke.synthetic_tool",
            tool_call_id=tool_call_id,
            params={"iteration": iteration, "action": "synthetic_dispatch"},
        )
        self._log_event(
            "tool_call_end",
            iteration,
            tool_name="phase3_smoke.synthetic_tool",
            tool_call_id=tool_call_id,
            params={"iteration": iteration, "action": "synthetic_dispatch"},
            duration_ms=0,
        )
        self._log_event(
            "session_open",
            iteration,
            params={"iteration": iteration, "synthetic": True},
        )
        self._exercise_encrypted_state(iteration)
        self._log_event(
            "session_close",
            iteration,
            params={"iteration": iteration, "synthetic": True},
        )

    def _log_event(
        self,
        event_type: str,
        iteration: int,
        *,
        params: dict[str, Any] | None = None,
        tool_name: str | None = None,
        tool_call_id: str | None = None,
        duration_ms: int | None = None,
        error: str | None = None,
    ) -> None:
        result = self.logger.log_event(
            event_type=event_type,
            session_id=self.config.session_id,
            principal=self.config.principal,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            params=params or {},
            duration_ms=duration_ms,
            error=error,
        )
        self._last_record_hash = result.record_hash
        self._append_emission(
            {
                "event_type": event_type,
                "iteration": iteration,
                "timestamp_unix": self.clock.time(),
                "audit_path": str(result.path),
                "record_hash": result.record_hash,
                "prev_hash": result.record["prev_hash"],
            }
        )

    def _capture_last_record(self, event_type: str, iteration: int) -> None:
        verification = self.logger.verify_current_month()
        self._last_record_hash = verification.last_hash
        self._append_emission(
            {
                "event_type": event_type,
                "iteration": iteration,
                "timestamp_unix": self.clock.time(),
                "audit_path": str(verification.path),
                "record_hash": verification.last_hash,
            }
        )

    def _exercise_encrypted_state(self, iteration: int) -> None:
        plaintext = json.dumps(
            {
                "iteration": iteration,
                "session_id": self.config.session_id,
                "timestamp_unix": self.clock.time(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        encoded = encode_state_bytes(plaintext)
        self.config.synthetic_state_file.write_bytes(encoded)
        decoded = decode_state_bytes(self.config.synthetic_state_file.read_bytes())
        if decoded != plaintext:
            raise RuntimeError("synthetic encrypted state round-trip mismatch")

    def _cadence_sleep(self, *, deadline: float | None) -> None:
        remaining = float(self.config.cadence_seconds)
        while remaining > 0 and not self._stop_requested:
            if deadline is not None:
                remaining = min(remaining, max(0.0, deadline - self.clock.time()))
                if remaining <= 0:
                    break
            interval = min(float(self.config.heartbeat_seconds), remaining)
            wall_before = self.clock.time()
            mono_before = self.clock.monotonic()
            self._sleep(interval)
            wall_delta = self.clock.time() - wall_before
            mono_delta = self.clock.monotonic() - mono_before
            gap = wall_delta - mono_delta
            if gap >= self.config.sleep_gap_threshold_seconds:
                self._sleep_gaps.append(
                    {
                        "detected_at_unix": self.clock.time(),
                        "gap_seconds": int(gap) if gap.is_integer() else gap,
                        "wall_delta_seconds": wall_delta,
                        "monotonic_delta_seconds": mono_delta,
                    }
                )
                self._write_manifest(status="running")
            remaining -= interval
            self._write_heartbeat(status="running")

    def _emit_end_event(self) -> None:
        if getattr(self, "_end_event_emitted", False):
            return
        self._end_event_emitted = True
        pre_final_hash = self._last_record_hash
        result = self.logger.log_event(
            event_type=END_EVENT_TYPE,
            session_id=self.config.session_id,
            principal=self.config.principal,
            params={
                "pre_final_last_hash": pre_final_hash,
                "iterations": self._iteration,
                "stop_signal": self._stop_signal,
                "sleep_gap_count": len(self._sleep_gaps),
            },
        )
        self._last_record_hash = result.record_hash
        self._append_emission(
            {
                "event_type": END_EVENT_TYPE,
                "timestamp_unix": self.clock.time(),
                "audit_path": str(result.path),
                "prev_hash": result.record["prev_hash"],
                "pre_final_last_hash": pre_final_hash,
                "record_hash": result.record_hash,
                "iterations": self._iteration,
                "stop_signal": self._stop_signal,
            }
        )

    def _write_heartbeat(self, *, status: str) -> None:
        self._heartbeat_count += 1
        payload = {
            "status": status,
            "heartbeat_count": self._heartbeat_count,
            "timestamp_unix": self.clock.time(),
            "iteration": self._iteration,
            "pid": os.getpid(),
        }
        self.config.heartbeat_file.write_text(
            json.dumps(payload, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(self.config.heartbeat_file, 0o600)

    def _write_manifest(
        self,
        *,
        status: str,
        final_last_hash: str | None = None,
        record_count: int | None = None,
    ) -> None:
        payload = {
            "status": status,
            "session_id": self.config.session_id,
            "audit_dir": str(self.config.audit_dir),
            "output_dir": str(self.config.output_dir),
            "cadence_seconds": self.config.cadence_seconds,
            "heartbeat_seconds": self.config.heartbeat_seconds,
            "sleep_gap_threshold_seconds": self.config.sleep_gap_threshold_seconds,
            STATE_ENCRYPTION_ENV: os.environ.get(STATE_ENCRYPTION_ENV),
            "pid_file": str(self.config.pid_file),
            "iterations": self._iteration,
            "sleep_gaps": self._sleep_gaps,
            "final_last_hash": final_last_hash,
            "record_count": record_count,
        }
        self.config.manifest_file.write_text(
            json.dumps(payload, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(self.config.manifest_file, 0o600)

    def _append_emission(self, payload: dict[str, Any]) -> None:
        with self.config.emissions_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
        os.chmod(self.config.emissions_file, 0o600)

    def _remove_pid_file(self) -> None:
        self.config.pid_file.unlink(missing_ok=True)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-dir", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--pid-file", type=Path, default=None)
    parser.add_argument("--cadence-seconds", type=_positive_int, default=300)
    parser.add_argument("--heartbeat-seconds", type=_positive_int, default=60)
    parser.add_argument("--sleep-gap-threshold-seconds", type=_positive_int, default=5)
    parser.add_argument("--duration-seconds", type=_positive_int, default=None)
    parser.add_argument("--max-iterations", type=_positive_int, default=None)
    parser.add_argument("--session-id", default="phase3-smoke")
    parser.add_argument("--principal", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    os.environ[STATE_ENCRYPTION_ENV] = "1"
    config = Phase3SmokeConfig(
        audit_dir=args.audit_dir,
        output_dir=args.output_dir,
        cadence_seconds=args.cadence_seconds,
        heartbeat_seconds=args.heartbeat_seconds,
        sleep_gap_threshold_seconds=args.sleep_gap_threshold_seconds,
        pid_file=args.pid_file,
        session_id=args.session_id,
        principal=args.principal,
    )
    harness = Phase3SmokeHarness(config)
    signal.signal(signal.SIGTERM, harness.request_stop)
    signal.signal(signal.SIGINT, harness.request_stop)
    result = harness.run(
        max_iterations=args.max_iterations,
        duration_seconds=args.duration_seconds,
    )
    print(
        "Phase 3 smoke stopped: "
        f"records={result.record_count} audit_path={result.audit_path} "
        f"last_hash={result.last_hash}"
    )
    verify_audit_chain(result.audit_path, expected_last_hash=result.last_hash)
    return 0


if __name__ == "__main__":
    sys.exit(main())
