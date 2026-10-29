"""``lliam-gov killswitch engage|status|release`` (JER-190).

Drives the real top-level parser via ``lliam_cli.main.main()`` against a
per-test home, a throwaway baseline checkout and a real hash-chained ledger.
"""

from __future__ import annotations

import json
import sys

import pytest

import agent.governance_audit as ga
from agent import killswitch as ks
from agent.governance_audit import iter_records
from tests.governance.conftest import make_baseline_repo


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("LLIAM_HOME", raising=False)
    ks.reset_for_tests()
    led = ga.GovernanceLedger(home / "logs" / "agent-audit.log")
    monkeypatch.setattr(ga, "get_ledger", lambda: led)
    led.emit("session.start", action="session.start", source_module="tests")
    repo = make_baseline_repo(tmp_path / "deploy")
    yield home, led, repo
    ks.reset_for_tests()


def _run(monkeypatch, capsys, *argv):
    import lliam_cli.main as main_mod
    monkeypatch.setattr(sys, "argv", ["lliam-gov", "killswitch", *argv])
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    out = capsys.readouterr()
    return exc.value.code, out.out, out.err


def test_engage_status_release_round_trip(env, monkeypatch, capsys):
    home, led, repo = env
    state_file = home / "killswitch.state"
    assert ks._state_path() == state_file

    code, out, _ = _run(monkeypatch, capsys, "status", "--json")
    assert code == 0 and json.loads(out)["engaged"] is False

    code, out, _ = _run(monkeypatch, capsys, "engage", "--reason", "suspected injection",
                        "--actor", "isso@agency.mil", "--json")
    assert code == 0
    payload = json.loads(out)
    assert payload["engaged"] is True and payload["evidence_dir"]
    on_disk = json.loads(state_file.read_text())
    assert on_disk["engaged"] is True
    assert on_disk["actor"] == "isso@agency.mil"
    assert on_disk["reason"] == "suspected injection"
    assert not [p for p in home.iterdir() if p.name.startswith(".killswitch.state.")]

    # tool calls and inference blocked while engaged
    assert ks.guard_tool_dispatch("write_file") is not None
    with pytest.raises(ks.KillSwitchEngaged):
        ks.assert_inference_live()

    code, out, _ = _run(monkeypatch, capsys, "status")
    assert code == 0 and "ENGAGED" in out and "suspected injection" in out

    repo.overlay.write_text("security:\n  posture: permissive\n")
    code, out, _ = _run(monkeypatch, capsys, "release", "--reason", "contained, creds rotated",
                        "--actor", "ao@agency.mil", "--repo-root", str(repo.root),
                        "--yes", "--json")
    assert code == 0, out
    res = json.loads(out)
    assert res["ok"] is True and "cli-config.gov.yaml" in res["restored"]
    assert ks.is_engaged() is False
    assert ks.guard_tool_dispatch("write_file") is None
    assert "posture: strict" in repo.overlay.read_text()

    rec = [r for r in iter_records(led.path) if r["action"] == "killswitch.recover"][-1]
    assert rec["decision"] == "allow"
    assert rec["subject"]["principal"] == "ao@agency.mil"
    assert rec["outcome"]["operator_reason"] == "contained, creds rotated"
    assert rec["outcome"]["released_at"]

    code, out, _ = _run(monkeypatch, capsys, "status")
    assert "not engaged" in out and "ao@agency.mil" in out


def test_release_requires_confirmation_non_interactive(env, monkeypatch, capsys):
    _home, _led, repo = env
    ks.engage(reason="x", actor="isso")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    code, _out, err = _run(monkeypatch, capsys, "release", "--reason", "done",
                           "--repo-root", str(repo.root))
    assert code == 2 and "--yes" in err
    assert ks.is_engaged() is True


def test_release_interactive_confirmation(env, monkeypatch, capsys):
    _home, _led, repo = env
    ks.engage(reason="x", actor="isso")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    code, _out, err = _run(monkeypatch, capsys, "release", "--reason", "done",
                           "--repo-root", str(repo.root))
    assert code == 2 and "aborted" in err
    assert ks.is_engaged() is True

    monkeypatch.setattr("builtins.input", lambda prompt="": "RELEASE")
    code, out, _ = _run(monkeypatch, capsys, "release", "--reason", "done",
                        "--repo-root", str(repo.root))
    assert code == 0, out
    assert ks.is_engaged() is False


def test_release_refused_when_verification_fails(env, monkeypatch, capsys):
    _home, led, repo = env
    ks.engage(reason="x", actor="isso")
    led.path.write_bytes(led.path.read_bytes().replace(b'"session.start"',
                                                       b'"session.stop"', 1))
    code, out, _ = _run(monkeypatch, capsys, "release", "--reason", "done",
                        "--repo-root", str(repo.root), "--yes")
    assert code == 1
    assert "REFUSED" in out
    assert ks.is_engaged() is True


def test_release_reason_is_required(env, monkeypatch, capsys):
    ks.engage(reason="x", actor="isso")
    import lliam_cli.main as main_mod
    monkeypatch.setattr(sys, "argv", ["lliam-gov", "killswitch", "release", "--yes"])
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 2
    assert ks.is_engaged() is True


def test_killswitch_is_a_builtin_subcommand():
    import lliam_cli.main as main_mod
    assert "killswitch" in main_mod._BUILTIN_SUBCOMMANDS


def test_release_dry_run_writes_nothing(env, monkeypatch, capsys):
    _home, _led, repo = env
    ks.engage(reason="x", actor="isso")
    repo.overlay.write_text("security:\n  posture: permissive\n")
    code, out, _ = _run(monkeypatch, capsys, "release", "--reason", "check",
                        "--repo-root", str(repo.root), "--dry-run")
    assert code == 0, out
    assert "would restore: cli-config.gov.yaml" in out
    assert "permissive" in repo.overlay.read_text()
    assert ks.is_engaged() is True
