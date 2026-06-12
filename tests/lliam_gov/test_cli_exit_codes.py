"""Exit-code propagation for governance CLI commands (AI-217 / LG-3.9).

The audit/key subcommands signal failure with integer return codes
(``hermes_cli/audit_cli.py``, ``hermes_cli/key_cli.py``), but ``main()``
historically discarded ``args.func(args)``'s return value, so a failed chain
verification exited 0 — fail-open for every operator script and for the
AI-217 smoke-evidence gates. These tests pin the contract end-to-end through
the real console entry point.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from lliam_gov.security.audit_logger import AuditLogger


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "hermes_cli.main", *args],
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_audit_verify_jsonl_exit_codes(tmp_path: Path) -> None:
    logger = AuditLogger(audit_dir=tmp_path / "audit")
    result = logger.log_event(event_type="tool_call", params={"k": "v"})
    logger.log_event(event_type="tool_call", params={"k": "v2"})
    chain_path = result.path

    ok = _run_cli("audit", "verify-jsonl", "--input", str(chain_path))
    assert ok.returncode == 0, ok.stderr

    # Tamper with the first record: the second record's prev_hash no longer
    # matches, so verification must exit non-zero.
    chain_path.write_text(
        chain_path.read_text(encoding="utf-8").replace("tool_call", "tampered", 1),
        encoding="utf-8",
    )
    bad = _run_cli("audit", "verify-jsonl", "--input", str(chain_path))
    assert bad.returncode != 0
    assert "verification failed" in bad.stderr
