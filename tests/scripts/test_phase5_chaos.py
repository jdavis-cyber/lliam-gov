"""CI coverage for the Phase 5 chaos / fail-closed scenarios (AI-229).

WHY: the chaos harness is evidence tooling, but the property it asserts —
every control fails CLOSED when its dependency breaks — is a regression
surface. Running the scenarios in CI means a future change that turns a
refusal into a degraded-open path fails here, not only in a manual run.
"""

import importlib.util
from pathlib import Path

import pytest

_HARNESS = (
    Path(__file__).resolve().parents[2] / "scripts" / "phase5_chaos_evidence.py"
)
_spec = importlib.util.spec_from_file_location("phase5_chaos_evidence", _HARNESS)
chaos = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chaos)


@pytest.mark.parametrize("name,fn", chaos.SCENARIOS, ids=[n for n, _ in chaos.SCENARIOS])
def test_scenario_fails_closed(name, fn, monkeypatch):
    # Each scenario sets its own env; isolate so they don't leak into the
    # rest of the suite.
    for var in (
        "HERMES_HOME",
        "LLIAM_GOV_CAPABILITY_ENFORCE",
        "LLIAM_GOV_CAPABILITIES",
        "LLIAM_GOV_EGRESS_ENFORCE",
        "LLIAM_GOV_EGRESS_ALLOWLIST",
        "LLIAM_GOV_SELFMOD_GATE",
        "LLIAM_GOV_PRIVILEGED_USERS",
    ):
        monkeypatch.delenv(var, raising=False)
    ok, detail = fn()
    assert ok, f"{name} did NOT fail closed: {detail}"
