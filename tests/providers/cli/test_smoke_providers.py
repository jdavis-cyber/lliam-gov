"""Smoke-test the provider smoke harness in mocked mode (AI-335).

Runs scripts/smoke-providers.py (mocked, no real CLIs) and asserts it reports
all three providers READY and writes a well-formed evidence artifact.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts" / "smoke-providers.py"


def test_mocked_smoke_all_ready_and_writes_evidence(tmp_path):
    out = tmp_path / "smoke.json"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--out", str(out)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["schema"] == "lliam-gov.qa.provider-smoke"
    assert data["summary"]["total"] == 3
    assert data["summary"]["ready"] == 3
    ids = {p["id"] for p in data["providers"]}
    assert ids == {"claude-code", "codex", "gemini"}
    # Evidence carries the metadata the QA matrix requires.
    assert "os" in data and "desktopVersion" in data and "ranAt" in data
