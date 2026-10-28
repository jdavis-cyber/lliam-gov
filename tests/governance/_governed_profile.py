"""Load the SHIPPED governed profile (cli-config.gov.yaml) hermetically.

The P2/P3 corpora drive hand-written strict configs. The tests that use this
helper load the real overlay instead, the way a governed deployment does:
``HERMES_CONFIG`` points at the version-controlled ``cli-config.gov.yaml``,
which ``lliam_cli.config.load_config`` deep-merges over an empty per-test home,
and the policy files resolve from the repo's ``policy/`` directory. Nothing is
mocked except tool handlers, which tests stub so no real side effect runs.

The working directory moves to the test's tmp dir. Overlay values that are not
expanded (see the iscm_sink ``$HERMES_HOME`` note in test_p5_capability_corpus)
then land in the sandbox, not the repo. It also proves policy resolution does
not depend on the caller's cwd.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OVERLAY = REPO / "cli-config.gov.yaml"


@dataclass
class GovernedProfile:
    home: Path
    safe_root: Path

    @property
    def ledger_path(self) -> Path:
        return self.home / "logs" / "agent-audit.log"


def _reset_runtime_state(monkeypatch) -> None:
    import agent.data_protection as dp
    import agent.governance_audit as ga
    import tools.egress_policy as ep
    import tools.injection_defense as idf
    import tools.tool_policy as tp
    from agent import killswitch as ks

    tp.reset_pdp_state()
    idf.reset_injection_state()
    dp.reset_dp_state()
    ep.reset_egress_cache()
    ks.reset_for_tests()
    # Process singletons over the configured ledger / monitor hub: rebuilt
    # from THIS test's config, restored afterwards by monkeypatch.
    monkeypatch.setattr(ga, "_ledger_singleton", None)
    monkeypatch.setattr(ga, "_was_enabled", False)
    monkeypatch.setattr(ga, "_disable_flip_logged", False)
    monkeypatch.setattr(ga, "_monitor_hub", None)
    monkeypatch.setattr(ga, "_monitor_hub_built", False)


def enter_governed_profile(tmp_path: Path, monkeypatch) -> GovernedProfile:
    home = tmp_path / "lliam-home"
    home.mkdir()
    safe_root = tmp_path / "ws"
    safe_root.mkdir()
    monkeypatch.delenv("LLIAM_HOME", raising=False)
    monkeypatch.delenv("LLIAM_CONFIG", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_CONFIG", str(OVERLAY))
    monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", str(safe_root))
    monkeypatch.chdir(tmp_path)
    _reset_runtime_state(monkeypatch)
    return GovernedProfile(home=home, safe_root=safe_root)


def stub_tool_handlers(monkeypatch, result: str = '{"output": "ok"}') -> list:
    """Replace the registry dispatch with a recorder. Returns the call log."""
    from tools.registry import registry

    calls: list = []

    def _dispatch(name, args, **kw):
        calls.append((name, dict(args or {})))
        return result

    monkeypatch.setattr(registry, "dispatch", _dispatch)
    return calls


def call_tool(name: str, args: dict, *, task_id: str = "corpus") -> dict:
    """Dispatch through the public model_tools funnel (PDP + audit gates)."""
    import model_tools

    raw = model_tools.handle_function_call(name, args, task_id=task_id)
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return {"raw": raw}
