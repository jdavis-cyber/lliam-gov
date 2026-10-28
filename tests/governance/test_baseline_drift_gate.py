"""Baseline drift gate: sandbox resource/network keys (JER-74).

The gate must pass on the shipped overlay and fail closed when the governed
sandbox ceilings or network lock are removed or weakened.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_GATE = _REPO / "ci" / "governance-ci-gates" / "baseline_drift_gate.py"
_OVERLAY = _REPO / "cli-config.gov.yaml"
_BASELINE = _REPO / "docs" / "governance" / "baseline-critical-keys.yaml"


def _run_gate(overlay: Path, home: Path) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items()
           if k not in ("LLIAM_CONFIG", "HERMES_CONFIG")}
    env["HERMES_HOME"] = str(home)
    env["LLIAM_HOME"] = str(home)
    return subprocess.run(
        [sys.executable, str(_GATE), "--overlay", str(overlay),
         "--baseline", str(_BASELINE), "--phase", "P0"],
        cwd=_REPO, env=env, capture_output=True, text=True, timeout=120,
    )


def _overlay_with(tmp_path: Path, key: str, replacement: str | None) -> Path:
    """Copy the overlay with terminal.<key> removed (None) or re-valued."""
    text = _OVERLAY.read_text(encoding="utf-8")
    pattern = re.compile(rf"^(  {re.escape(key)}:)[^\n]*\n", re.MULTILINE)
    assert pattern.search(text), f"terminal.{key} not found in overlay"
    new = "" if replacement is None else rf"\g<1> {replacement}\n"
    out = tmp_path / "cli-config.gov.yaml"
    out.write_text(pattern.sub(new, text, count=1), encoding="utf-8")
    return out


def test_gate_passes_on_shipped_overlay(tmp_path):
    result = _run_gate(_OVERLAY, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


@pytest.mark.parametrize("key,replacement", [
    ("container_cpu", None),
    ("container_memory", None),
    ("docker_network", None),
    ("container_cpu", "0"),
    ("container_memory", "0"),
    ("docker_network", "true"),
])
def test_gate_fails_closed_when_sandbox_key_drifts(tmp_path, key, replacement):
    overlay = _overlay_with(tmp_path, key, replacement)
    result = _run_gate(overlay, tmp_path / "home")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "CRITICAL baseline drift" in result.stdout
    assert f"terminal.{key}" in result.stdout
