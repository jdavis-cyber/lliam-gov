"""Tests for the Phase 3 smoke harness."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys


def _load_phase3_smoke():
    module_path = Path(__file__).parents[2] / "scripts" / "phase3_smoke.py"
    spec = importlib.util.spec_from_file_location("phase3_smoke", module_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeClock:
    def __init__(self) -> None:
        self.wall = 1_800_000_000.0
        self.mono = 50_000.0
        self.wall_extra_on_sleep = 0.0

    def time(self) -> float:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def sleep(self, seconds: float) -> None:
        self.wall += seconds + self.wall_extra_on_sleep
        self.mono += seconds
        self.wall_extra_on_sleep = 0.0


def _records(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_script_help_runs_from_repo_root() -> None:
    repo_root = Path(__file__).parents[2]

    result = subprocess.run(
        [sys.executable, str(repo_root / "scripts" / "phase3_smoke.py"), "--help"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert "--heartbeat-seconds" in result.stdout


def test_config_defaults_match_ai_241_decisions(tmp_path, monkeypatch) -> None:
    phase3_smoke = _load_phase3_smoke()
    monkeypatch.setenv("HOME", str(tmp_path))

    config = phase3_smoke.Phase3SmokeConfig()

    assert config.cadence_seconds == 300
    assert config.heartbeat_seconds == 60
    assert config.sleep_gap_threshold_seconds == 5
    assert config.pid_file == tmp_path / ".lliam-gov" / "phase3_smoke.pid"


def test_run_emits_required_event_types_and_verifies_chain(tmp_path) -> None:
    phase3_smoke = _load_phase3_smoke()
    clock = FakeClock()
    config = phase3_smoke.Phase3SmokeConfig(
        audit_dir=tmp_path / "audit",
        output_dir=tmp_path / "runtime",
        cadence_seconds=5,
        heartbeat_seconds=1,
        pid_file=tmp_path / "phase3.pid",
    )
    harness = phase3_smoke.Phase3SmokeHarness(config, clock=clock, sleep=clock.sleep)

    result = harness.run(max_iterations=2)

    assert result.record_count == 11
    verification = phase3_smoke.verify_audit_chain(
        result.audit_path,
        expected_last_hash=result.last_hash,
    )
    assert verification.record_count == result.record_count
    records = _records(result.audit_path)
    assert [record["event_type"] for record in records] == [
        "gateway_auth",
        "tool_call_start",
        "tool_call_end",
        "session_open",
        "session_close",
        "gateway_auth",
        "tool_call_start",
        "tool_call_end",
        "session_open",
        "session_close",
        "phase3_smoke_end",
    ]


def test_heartbeat_file_updates_on_configured_interval(tmp_path) -> None:
    phase3_smoke = _load_phase3_smoke()
    clock = FakeClock()
    config = phase3_smoke.Phase3SmokeConfig(
        audit_dir=tmp_path / "audit",
        output_dir=tmp_path / "runtime",
        cadence_seconds=3,
        heartbeat_seconds=1,
        pid_file=tmp_path / "phase3.pid",
    )
    harness = phase3_smoke.Phase3SmokeHarness(config, clock=clock, sleep=clock.sleep)

    harness.run(max_iterations=2)

    heartbeat = json.loads(config.heartbeat_file.read_text(encoding="utf-8"))
    assert heartbeat["heartbeat_count"] >= 3
    assert heartbeat["status"] == "stopped"


def test_sleep_gap_is_recorded_in_manifest(tmp_path) -> None:
    phase3_smoke = _load_phase3_smoke()
    clock = FakeClock()
    config = phase3_smoke.Phase3SmokeConfig(
        audit_dir=tmp_path / "audit",
        output_dir=tmp_path / "runtime",
        cadence_seconds=5,
        heartbeat_seconds=5,
        sleep_gap_threshold_seconds=5,
        pid_file=tmp_path / "phase3.pid",
    )
    harness = phase3_smoke.Phase3SmokeHarness(config, clock=clock, sleep=clock.sleep)
    clock.wall_extra_on_sleep = 9

    harness.run(max_iterations=2)

    manifest = json.loads(config.manifest_file.read_text(encoding="utf-8"))
    assert manifest["sleep_gaps"][0]["gap_seconds"] == 9


def test_sigterm_request_writes_final_event_and_removes_pid_file(tmp_path) -> None:
    phase3_smoke = _load_phase3_smoke()
    clock = FakeClock()
    config = phase3_smoke.Phase3SmokeConfig(
        audit_dir=tmp_path / "audit",
        output_dir=tmp_path / "runtime",
        cadence_seconds=10,
        heartbeat_seconds=1,
        pid_file=tmp_path / "phase3.pid",
    )
    harness = phase3_smoke.Phase3SmokeHarness(config, clock=clock, sleep=clock.sleep)

    def stop_after_first_sleep(seconds: float) -> None:
        clock.sleep(seconds)
        harness.request_stop(signal.SIGTERM, None)

    harness = phase3_smoke.Phase3SmokeHarness(
        config, clock=clock, sleep=stop_after_first_sleep
    )

    result = harness.run(max_iterations=10)

    assert not config.pid_file.exists()
    records = _records(result.audit_path)
    assert records[-1]["event_type"] == "phase3_smoke_end"
    assert records[-1]["params_hash"]
    assert "phase3_smoke_end" in config.emissions_file.read_text(encoding="utf-8")
