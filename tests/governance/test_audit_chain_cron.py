"""audit_chain_cron.sh must page on a verifier failure (LG-AU-08, spec §10).

The production cron unit's whole job is to alert on a break/error. A prior
`set -e` + ``out="$(...)"`` form exited the script the instant the verifier
returned nonzero — before it could print the captured output or invoke the
alert command. These subprocess tests drive the real script with a fake
verifier (via LLIAM_PYTHON) and a fake alert command, asserting output is
printed, the alert fires with the output on stdin, and the original exit
status is preserved.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_CRON = _REPO / "ci" / "governance-ci-gates" / "audit_chain_cron.sh"


def _fake_python(tmp_path, *, output: str, rc: int) -> Path:
    shim = tmp_path / "fakepython"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" {output!r}\n'
        f"exit {rc}\n"
    )
    shim.chmod(0o755)
    return shim


def _base_env(tmp_path, python: Path, alert: Path | None) -> dict:
    env = {
        **os.environ,
        "HERMES_HOME": str(tmp_path),
        "HERMES_CONFIG": str(tmp_path / "cli-config.gov.yaml"),
        "LLIAM_PYTHON": str(python),
    }
    if alert is not None:
        env["LLIAM_AUDIT_ALERT_CMD"] = str(alert)
    return env


@pytest.mark.parametrize("verifier_rc", [1, 2])
def test_cron_prints_output_and_alerts_on_verifier_failure(tmp_path, verifier_rc):
    py = _fake_python(tmp_path, output="SIMULATED-VERIFIER-OUTPUT", rc=verifier_rc)
    alert_marker = tmp_path / "alert_invoked"
    alert_stdin = tmp_path / "alert_stdin"
    alert = tmp_path / "fakealert"
    alert.write_text(
        "#!/usr/bin/env bash\n"
        f'echo invoked > {str(alert_marker)!r}\n'
        f'cat > {str(alert_stdin)!r}\n'
    )
    alert.chmod(0o755)

    proc = subprocess.run(
        ["bash", str(_CRON)], env=_base_env(tmp_path, py, alert),
        capture_output=True, text=True,
    )

    # Original verifier status preserved (not masked by an early set -e exit).
    assert proc.returncode == verifier_rc
    # Captured verifier output was printed, not swallowed.
    assert "SIMULATED-VERIFIER-OUTPUT" in proc.stdout
    # The alert command fired and received the output on stdin.
    assert alert_marker.exists()
    assert "SIMULATED-VERIFIER-OUTPUT" in alert_stdin.read_text()


def test_cron_clean_pass_returns_zero_and_does_not_alert(tmp_path):
    py = _fake_python(tmp_path, output="CHAIN-OK", rc=0)
    alert_marker = tmp_path / "alert_invoked"
    alert = tmp_path / "fakealert"
    alert.write_text("#!/usr/bin/env bash\n" f'echo invoked > {str(alert_marker)!r}\n')
    alert.chmod(0o755)

    proc = subprocess.run(
        ["bash", str(_CRON)], env=_base_env(tmp_path, py, alert),
        capture_output=True, text=True,
    )

    assert proc.returncode == 0
    assert "CHAIN-OK" in proc.stdout
    assert not alert_marker.exists()  # no alert on a clean pass


def test_cron_fails_closed_without_required_env(tmp_path):
    py = _fake_python(tmp_path, output="unused", rc=0)
    env = {**os.environ, "LLIAM_PYTHON": str(py)}
    env.pop("HERMES_HOME", None)
    env.pop("HERMES_CONFIG", None)
    proc = subprocess.run(
        ["bash", str(_CRON)], env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 2  # fail-closed on unpinned home/overlay
