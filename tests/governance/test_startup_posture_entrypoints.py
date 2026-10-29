"""Fail-closed startup gates run on EVERY entrypoint (JER-80).

The five strict-posture startup gates used to run only from
``gateway/run.py:start_gateway``. They now live in the shared
``lliam_cli.startup_posture.enforce_startup_posture`` sequence, and every
console script in ``pyproject.toml [project.scripts]`` (plus the gateway, the
TUI backend and the desktop app's dashboard backend) must reach it.

Covers:
  * the shared sequence keeps the gateway's semantics — order, merged-config
    hand-off, blocking errors propagate, other gate faults are non-fatal,
    low-side is a no-op;
  * every ``[project.scripts]`` entrypoint refuses to start (non-zero exit,
    agent never built) when a gate blocks — both with the sequence stubbed to
    fail and with the REAL control-plane gate tripped under strict posture;
  * low-side posture runs every entrypoint unaffected;
  * the CLI's exempt (repair / inspect) commands stay reachable when the gates
    would block, and every built-in subcommand is consciously classified.
"""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from argparse import Namespace
from pathlib import Path

import pytest

import lliam_cli.security_audit_startup as sas
import lliam_cli.startup_posture as sp

_REPO = Path(__file__).resolve().parents[2]

_STRICT = {"security": {"posture": "strict", "api_server_key_required": True,
                        "require_tls": True}}


class _AgentStarted(Exception):
    """Raised by stubs that stand in for 'the entrypoint built an agent'."""


@pytest.fixture(autouse=True)
def _reset_gate_latches(monkeypatch):
    for name in ("_CONTROL_PLANE_CHECKED", "_PROVIDER_ALLOWLIST_CHECKED",
                 "_MODEL_INTEGRITY_CHECKED", "_GOVERNANCE_ARTIFACTS_CHECKED",
                 "_CHAIN_VERIFIED"):
        monkeypatch.setattr(sas, name, False)
    monkeypatch.setattr(sp, "_STARTUP_POSTURE_ENFORCED", False)
    for var in ("LLIAM_SKIP_SSL_GUARD", "HERMES_SKIP_SSL_GUARD",
                "LLIAM_SKIP_SSL_VERIFY", "HERMES_SKIP_SSL_VERIFY",
                "API_SERVER_KEY", "API_SERVER_HOST", "API_SERVER_ENABLED"):
        monkeypatch.delenv(var, raising=False)
    yield


def _console_scripts() -> dict[str, str]:
    data = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))
    return dict(data["project"]["scripts"])


def _block_with_stub(monkeypatch):
    """Make the shared sequence fail as a strict-posture gate would."""
    def _fail(**_kw):
        raise sas.ProviderAllowlistError("primary: provider 'evil' not allowlisted")
    monkeypatch.setattr(sp, "enforce_startup_posture", _fail)


def _block_with_real_gate(monkeypatch):
    """Trip the REAL control-plane gate (first in order) under strict posture."""
    monkeypatch.setenv("API_SERVER_ENABLED", "true")
    monkeypatch.setenv("API_SERVER_HOST", "0.0.0.0")
    monkeypatch.setattr(sp, "_merged_config", lambda _fallback: dict(_STRICT))


def _low_side(monkeypatch):
    """Low-side posture: the hermetic test home's real (overlay-less) config.

    No stubbing of the gates or of config loading — the REAL gate sequence
    runs and must be a no-op. Asserted non-strict so the test cannot pass
    vacuously against a strict ambient config.
    """
    from lliam_cli import config as _cfg
    from lliam_cli import posture_resolver as _pr

    assert not _pr.is_strict(_cfg.load_config())


# ---------------------------------------------------------------------------
# Shared sequence: gateway semantics preserved
# ---------------------------------------------------------------------------

_GATES = (
    "enforce_control_plane_auth_at_startup",
    "enforce_provider_allowlist_at_startup",
    "enforce_model_integrity_at_startup",
    "enforce_governance_artifacts_at_startup",
    "verify_audit_chain_at_startup",
)


def _record_gates(monkeypatch, calls, *, raise_at=None, fault_at=None):
    def _make(name):
        def _gate(*, config=None, **_kw):
            calls.append((name, config))
            if name == raise_at:
                raise sp.STARTUP_GATE_ERRORS[_GATES.index(name)]("blocked")
            if name == fault_at:
                raise ValueError("internal gate fault")
            return None
        return _gate

    monkeypatch.setattr(sas, "emit_agent_identity_at_startup",
                        lambda *, config=None: calls.append(("identity", config)))
    for name in _GATES:
        monkeypatch.setattr(sas, name, _make(name))


def test_sequence_order_and_merged_config(monkeypatch):
    calls: list = []
    _record_gates(monkeypatch, calls)
    merged = {"security": {"posture": "strict"}, "marker": "merged"}
    monkeypatch.setattr(sp, "_merged_config", lambda _fb: merged)
    raw = {"marker": "raw"}

    assert sp.enforce_startup_posture(raw_config=raw) is None

    assert [c[0] for c in calls] == ["identity", *_GATES]
    assert calls[0][1] is raw                      # identity gets the raw config
    assert all(c[1] is merged for c in calls[1:])  # every gate gets the merged one


def test_merged_config_falls_back_to_raw_on_load_failure(monkeypatch):
    calls: list = []
    _record_gates(monkeypatch, calls)

    def _boom(*a, **k):
        raise OSError("config unreadable")

    monkeypatch.setattr("lliam_cli.config.load_config", _boom)
    raw = {"marker": "raw"}
    sp.enforce_startup_posture(raw_config=raw)
    assert all(c[1] is raw for c in calls)


@pytest.mark.parametrize("gate", _GATES)
def test_blocking_gate_error_propagates_and_stops_sequence(monkeypatch, gate):
    calls: list = []
    _record_gates(monkeypatch, calls, raise_at=gate)
    monkeypatch.setattr(sp, "_merged_config", lambda _fb: {})

    with pytest.raises(sp.STARTUP_GATE_ERRORS[_GATES.index(gate)]):
        sp.enforce_startup_posture(raw_config={})

    ran = [c[0] for c in calls]
    assert ran[-1] == gate
    assert ran == ["identity", *_GATES[: _GATES.index(gate) + 1]]
    assert sp._STARTUP_POSTURE_ENFORCED is False  # never latched on failure


@pytest.mark.parametrize("gate", _GATES)
def test_non_blocking_gate_fault_is_non_fatal(monkeypatch, gate):
    calls: list = []
    _record_gates(monkeypatch, calls, fault_at=gate)
    monkeypatch.setattr(sp, "_merged_config", lambda _fb: {})

    assert sp.enforce_startup_posture(raw_config={}) is None
    assert [c[0] for c in calls] == ["identity", *_GATES]


def test_identity_emit_fault_is_non_fatal(monkeypatch):
    calls: list = []
    _record_gates(monkeypatch, calls)

    def _boom(*, config=None):
        raise RuntimeError("ledger down")

    monkeypatch.setattr(sas, "emit_agent_identity_at_startup", _boom)
    monkeypatch.setattr(sp, "_merged_config", lambda _fb: {})
    sp.enforce_startup_posture(raw_config={})
    assert [c[0] for c in calls] == list(_GATES)


def test_sequence_latches_after_success_only(monkeypatch):
    calls: list = []
    _record_gates(monkeypatch, calls)
    monkeypatch.setattr(sp, "_merged_config", lambda _fb: {})
    sp.enforce_startup_posture(raw_config={})
    sp.enforce_startup_posture(raw_config={})
    assert [c[0] for c in calls].count("identity") == 1
    sp.enforce_startup_posture(raw_config={}, force=True)
    assert [c[0] for c in calls].count("identity") == 2


def test_real_gates_low_side_is_noop(monkeypatch):
    _low_side(monkeypatch)
    assert sp.enforce_startup_posture() is None


def test_real_gates_strict_block(monkeypatch):
    _block_with_real_gate(monkeypatch)
    with pytest.raises(sas.ControlPlaneAuthError):
        sp.enforce_startup_posture()


def test_or_exit_refuses_on_stderr_only(monkeypatch, capsys):
    _block_with_real_gate(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        sp.enforce_startup_posture_or_exit("unit")
    assert exc.value.code == sp.STARTUP_POSTURE_EXIT_CODE != 0
    out, err = capsys.readouterr()
    assert out == ""
    assert "refusing to start" in err and "ControlPlaneAuthError" in err


def test_or_exit_does_not_swallow_unrelated_errors(monkeypatch):
    def _boom(**_kw):
        raise KeyError("not a gate error")
    monkeypatch.setattr(sp, "enforce_startup_posture", _boom)
    with pytest.raises(KeyError):
        sp.enforce_startup_posture_or_exit("unit")


# ---------------------------------------------------------------------------
# Every [project.scripts] entrypoint reaches enforce_startup_posture()
# ---------------------------------------------------------------------------

def _run_lliam_cli_main(monkeypatch):
    """`lliam-gov chat -q hi` with the agent launch stubbed."""
    import lliam_cli.main as m

    def _chat(_args):
        raise _AgentStarted("cmd_chat")

    monkeypatch.setattr(m, "cmd_chat", _chat)
    monkeypatch.setattr(m, "_prepare_agent_startup",
                        lambda _a: (_ for _ in ()).throw(_AgentStarted("prepare")))
    monkeypatch.setattr(m, "_try_termux_fast_tui_launch", lambda: False)
    monkeypatch.setattr(m, "_try_termux_fast_cli_launch", lambda: False)
    monkeypatch.setattr("lliam_cli.config.get_container_exec_info", lambda: None)
    monkeypatch.setattr(sys, "argv", ["lliam-gov", "chat", "-q", "hi"])
    m.main()


def _run_run_agent_main(monkeypatch):
    import run_agent

    def _agent(*_a, **_k):
        raise _AgentStarted("AIAgent")

    monkeypatch.setattr(run_agent, "AIAgent", _agent)
    run_agent.main(query="hi")


def _run_acp_main(monkeypatch):
    import acp_adapter.server as acp_server
    from acp_adapter import entry

    def _agent(*_a, **_k):
        raise _AgentStarted("LliamACPAgent")

    monkeypatch.setattr(entry, "_setup_logging", lambda: None)
    monkeypatch.setattr(entry, "_load_env", lambda: None)
    monkeypatch.setattr("tools.mcp_tool.discover_mcp_tools", lambda: None)
    monkeypatch.setattr(acp_server, "LliamACPAgent", _agent)
    entry.main([])


# Keyed by the console-script TARGET so a new [project.scripts] entry with a
# new target fails test_every_console_script_is_covered until it is wired.
_ENTRYPOINT_RUNNERS = {
    "lliam_cli.main:main": _run_lliam_cli_main,
    "run_agent:main": _run_run_agent_main,
    "acp_adapter.entry:main": _run_acp_main,
}


def test_every_console_script_is_covered():
    scripts = _console_scripts()
    assert scripts, "pyproject.toml declares no console scripts?"
    missing = {name: tgt for name, tgt in scripts.items()
               if tgt not in _ENTRYPOINT_RUNNERS}
    assert not missing, (
        f"console scripts with no startup-posture coverage: {missing} — wire "
        "enforce_startup_posture_or_exit() into the entrypoint and add a runner"
    )


@pytest.mark.parametrize("target", sorted(set(_console_scripts().values())))
def test_console_script_source_calls_startup_posture(target):
    """Static: the target function's body reaches the shared gate."""
    module, func = target.split(":")
    path = _REPO / (module.replace(".", "/") + ".py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func)
    called = {
        (c.func.id if isinstance(c.func, ast.Name) else getattr(c.func, "attr", None))
        for c in ast.walk(fn) if isinstance(c, ast.Call)
    }
    assert called & {"enforce_startup_posture", "enforce_startup_posture_or_exit",
                     "_enforce_cli_startup_posture"}, target


@pytest.mark.parametrize("name,target", sorted(_console_scripts().items()))
def test_console_script_refuses_when_gate_blocks(monkeypatch, capsys, name, target):
    _block_with_stub(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        _ENTRYPOINT_RUNNERS[target](monkeypatch)
    assert exc.value.code == sp.STARTUP_POSTURE_EXIT_CODE
    assert "refusing to start" in capsys.readouterr().err


@pytest.mark.parametrize("name,target", sorted(_console_scripts().items()))
def test_console_script_refuses_on_real_strict_gate(monkeypatch, name, target):
    _block_with_real_gate(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        _ENTRYPOINT_RUNNERS[target](monkeypatch)
    assert exc.value.code == sp.STARTUP_POSTURE_EXIT_CODE
    assert isinstance(exc.value.__cause__, sas.ControlPlaneAuthError)


@pytest.mark.parametrize("name,target", sorted(_console_scripts().items()))
def test_console_script_low_side_unaffected(monkeypatch, name, target):
    _low_side(monkeypatch)
    with pytest.raises(_AgentStarted):
        _ENTRYPOINT_RUNNERS[target](monkeypatch)
    assert sp._STARTUP_POSTURE_ENFORCED is True  # the gate actually ran


# ---------------------------------------------------------------------------
# Non-console-script entrypoints: gateway, TUI backend, desktop backend
# ---------------------------------------------------------------------------

def test_gateway_uses_shared_sequence_only():
    # gateway/run.py is ~19k lines; slice out start_gateway textually and parse
    # just that function rather than the whole module.
    src = (_REPO / "gateway" / "run.py").read_text(encoding="utf-8")
    start = src.index("\nasync def start_gateway(")
    nxt = re.search(r"\n(?:async def |def |class )", src[start + 1:])
    body = src[start + 1: start + 1 + nxt.start()] if nxt else src[start + 1:]
    fn = ast.parse(body).body[0]
    calls = {
        (c.func.id if isinstance(c.func, ast.Name) else getattr(c.func, "attr", None))
        for c in ast.walk(fn) if isinstance(c, ast.Call)
    }
    assert "enforce_startup_posture" in calls
    # Single source of truth: no gate is invoked directly from the gateway.
    assert not (calls & set(_GATES))


def test_tui_backend_refuses_when_gate_blocks(monkeypatch):
    from tui_gateway import entry as tui_entry

    _block_with_real_gate(monkeypatch)
    monkeypatch.setattr(tui_entry, "_install_sidecar_publisher",
                        lambda: (_ for _ in ()).throw(_AgentStarted("tui")))
    with pytest.raises(SystemExit) as exc:
        tui_entry.main()
    assert exc.value.code == sp.STARTUP_POSTURE_EXIT_CODE


def test_tui_backend_low_side_unaffected(monkeypatch):
    from tui_gateway import entry as tui_entry

    _low_side(monkeypatch)
    monkeypatch.setattr(tui_entry, "_install_sidecar_publisher",
                        lambda: (_ for _ in ()).throw(_AgentStarted("tui")))
    with pytest.raises(_AgentStarted):
        tui_entry.main()


def test_desktop_backend_is_a_gated_cli_command():
    """The Electron app spawns `<lliam-gov|python -m ...> dashboard ...`."""
    import lliam_cli.main as m

    src = (_REPO / "apps" / "desktop" / "electron" / "main.cjs").read_text(encoding="utf-8")
    spawned = set(re.findall(r"const dashboardArgs = \[([^\]]*)\]", src))
    assert spawned, "desktop backend argv not found in main.cjs"
    for argv in spawned:
        assert "'dashboard'" in argv
    assert m._requires_startup_posture(Namespace(command="dashboard")) is True


def test_dashboard_command_refuses_when_gate_blocks(monkeypatch):
    import lliam_cli.main as m

    _block_with_stub(monkeypatch)
    monkeypatch.setattr(m, "cmd_dashboard",
                        lambda _a: (_ for _ in ()).throw(_AgentStarted("dashboard")))
    monkeypatch.setattr(m, "_try_termux_fast_tui_launch", lambda: False)
    monkeypatch.setattr(m, "_try_termux_fast_cli_launch", lambda: False)
    monkeypatch.setattr("lliam_cli.config.get_container_exec_info", lambda: None)
    monkeypatch.setattr(sys, "argv", ["lliam-gov", "dashboard", "--no-open",
                                      "--host", "127.0.0.1", "--port", "0"])
    with pytest.raises(SystemExit) as exc:
        m.main()
    assert exc.value.code == sp.STARTUP_POSTURE_EXIT_CODE


# ---------------------------------------------------------------------------
# CLI exemptions: repair / inspect commands stay reachable
# ---------------------------------------------------------------------------

# Built-in commands that run an agent turn or open a serving endpoint. Any
# built-in not here must be in _STARTUP_POSTURE_EXEMPT_COMMANDS — a new
# subcommand forces a conscious gated-or-exempt decision.
_EXPECTED_GATED_BUILTINS = {
    "chat", "dashboard", "desktop", "gui", "proxy", "send", "kanban", "curator",
}


def test_every_builtin_subcommand_is_classified():
    import lliam_cli.main as m

    exempt = m._STARTUP_POSTURE_EXEMPT_COMMANDS
    assert not (exempt & _EXPECTED_GATED_BUILTINS)
    assert m._BUILTIN_SUBCOMMANDS - exempt == _EXPECTED_GATED_BUILTINS


@pytest.mark.parametrize("ns,expected", [
    (Namespace(command=None), True),                       # bare / -z / --resume
    (Namespace(command="chat"), True),
    (Namespace(command="rl"), True),
    (Namespace(command="some-plugin-cmd"), True),          # unknown → fail-closed
    (Namespace(command="cron", cron_command="run"), True),
    (Namespace(command="cron", cron_command="tick"), True),
    (Namespace(command="cron", cron_command="list"), False),
    (Namespace(command="mcp", mcp_action="serve"), True),
    (Namespace(command="mcp", mcp_action="add"), False),
    (Namespace(command="gateway", gateway_command="run"), False),  # self-gated
    (Namespace(command="acp"), False),                             # self-gated
    (Namespace(command="setup"), False),
    (Namespace(command="doctor"), False),
    (Namespace(command="config"), False),
    (Namespace(command="model"), False),
    (Namespace(command="auth"), False),
    (Namespace(command="login"), False),
])
def test_requires_startup_posture_classification(ns, expected):
    import lliam_cli.main as m

    assert m._requires_startup_posture(ns) is expected


@pytest.mark.parametrize("argv,handler", [
    (["config", "show"], "cmd_config"),
    (["doctor"], "cmd_doctor"),
    (["setup"], "cmd_setup"),
])
def test_exempt_commands_run_when_gates_would_block(monkeypatch, argv, handler):
    import lliam_cli.main as m

    _block_with_stub(monkeypatch)
    ran = []
    monkeypatch.setattr(m, handler, lambda _a: ran.append(handler))
    monkeypatch.setattr(m, "_try_termux_fast_tui_launch", lambda: False)
    monkeypatch.setattr(m, "_try_termux_fast_cli_launch", lambda: False)
    monkeypatch.setattr("lliam_cli.config.get_container_exec_info", lambda: None)
    monkeypatch.setattr(sys, "argv", ["lliam-gov", *argv])
    m.main()
    assert ran == [handler]


def test_version_flag_runs_when_gates_would_block(monkeypatch):
    import lliam_cli.main as m

    _block_with_stub(monkeypatch)
    ran = []
    monkeypatch.setattr(m, "cmd_version", lambda _a: ran.append("version"))
    monkeypatch.setattr(m, "_try_termux_fast_tui_launch", lambda: False)
    monkeypatch.setattr(m, "_try_termux_fast_cli_launch", lambda: False)
    monkeypatch.setattr("lliam_cli.config.get_container_exec_info", lambda: None)
    monkeypatch.setattr(sys, "argv", ["lliam-gov", "--version"])
    m.main()
    assert ran == ["version"]


@pytest.mark.parametrize("argv", [["--setup"], ["--check"], ["--version"]])
def test_acp_repair_flags_run_when_gates_would_block(monkeypatch, argv):
    from acp_adapter import entry

    _block_with_stub(monkeypatch)
    monkeypatch.setattr(entry, "_run_setup", lambda: None)
    monkeypatch.setattr(entry, "_run_check", lambda: None)
    monkeypatch.setattr(entry, "_print_version", lambda: None)
    entry.main(argv)  # returns normally — no SystemExit
