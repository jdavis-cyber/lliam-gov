"""Tests for the leftover messaging-gateway cleanup in lliam_cli.uninstall.

Earlier releases could register the gateway as a launchd agent (macOS) or a
systemd user unit (Linux). The gateway is gone, so the uninstaller and
``lliam-gov doctor --fix`` must remove those registrations. Every subprocess
call is recorded, never run.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

import lliam_cli.uninstall as uninstall

_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
    <key>Label</key><string>com.secondorderstrategy.lliam-gov.gateway</string>
    <key>ProgramArguments</key><array>
        <string>/opt/venv/bin/python</string>
        <string>-m</string>
        <string>lliam_cli.main</string>
        <string>gateway</string>
        <string>run</string>
        <string>--replace</string>
    </array>
</dict></plist>
"""

_UNIT = """[Unit]
Description=Lliam-GOV Gateway - Messaging Platform Integration

[Service]
ExecStart=/opt/venv/bin/python -m lliam_cli.main gateway run
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Point every path the helper reads at a temp home and record subprocess calls."""
    home = tmp_path / "home"
    lliam_home = home / ".hermes"
    lliam_home.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(uninstall, "_real_user_home", lambda: home)
    monkeypatch.setattr(uninstall, "get_lliam_home", lambda: lliam_home)
    import lliam_constants

    monkeypatch.setattr(lliam_constants, "get_default_lliam_root", lambda: lliam_home)

    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(uninstall.subprocess, "run", fake_run)
    monkeypatch.setattr(uninstall.os, "getuid", lambda: 501, raising=False)
    kills: list[int] = []
    monkeypatch.setattr(uninstall.os, "kill", lambda pid, sig: kills.append(pid))
    return {"home": home, "lliam_home": lliam_home, "calls": calls, "kills": kills}


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_nothing_installed_is_a_no_op(env, monkeypatch, platform):
    monkeypatch.setattr(sys, "platform", platform)

    assert uninstall.find_legacy_gateway_services() == []
    assert uninstall.remove_legacy_gateway_services() is False
    assert env["calls"] == []
    assert env["kills"] == []


def test_launchd_plist_is_unloaded_and_deleted(env, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    agents = env["home"] / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    plist = agents / "com.secondorderstrategy.lliam-gov.gateway.plist"
    plist.write_text(_PLIST)
    profile_plist = agents / "com.secondorderstrategy.lliam-gov.gateway-coder.plist"
    profile_plist.write_text(_PLIST)
    # Same prefix, but not our gateway: must be left alone.
    unrelated = agents / "ai.hermes.gateway-other.plist"
    unrelated.write_text("<plist><string>/usr/bin/something-else</string></plist>")

    assert uninstall.find_legacy_gateway_services() == [plist, profile_plist]
    assert uninstall.remove_legacy_gateway_services() is True

    assert not plist.exists()
    assert not profile_plist.exists()
    assert unrelated.exists()
    assert env["calls"] == [
        ["launchctl", "bootout", "gui/501", str(plist)],
        ["launchctl", "bootout", "gui/501", str(profile_plist)],
    ]


def test_launchd_falls_back_to_unload_when_bootout_fails(env, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    agents = env["home"] / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    plist = agents / "ai.hermes.gateway.plist"
    plist.write_text(_PLIST)

    def fake_run(cmd, *args, **kwargs):
        env["calls"].append(list(cmd))
        code = 5 if cmd[1] == "bootout" else 0
        return subprocess.CompletedProcess(cmd, code, stdout="", stderr="")

    monkeypatch.setattr(uninstall.subprocess, "run", fake_run)

    assert uninstall.remove_legacy_gateway_services() is True
    assert not plist.exists()
    assert env["calls"][-1] == ["launchctl", "unload", str(plist)]


def test_systemd_user_unit_is_disabled_stopped_and_deleted(env, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    unit_dir = env["home"] / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    unit = unit_dir / "hermes-gateway.service"
    unit.write_text(_UNIT)
    unrelated = unit_dir / "hermes-gateway-other.service"
    unrelated.write_text("[Service]\nExecStart=/usr/bin/something-else\n")

    assert uninstall.find_legacy_gateway_services() == [unit]
    assert uninstall.remove_legacy_gateway_services() is True

    assert not unit.exists()
    assert unrelated.exists()
    assert env["calls"] == [
        ["systemctl", "--user", "disable", "hermes-gateway.service"],
        ["systemctl", "--user", "stop", "hermes-gateway.service"],
        ["systemctl", "--user", "daemon-reload"],
    ]


def test_pid_file_stops_only_a_live_gateway(env, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    pid_file = env["lliam_home"] / "gateway.pid"
    pid_file.write_text(json.dumps({"pid": 424242, "kind": "hermes-gateway"}))
    lock_file = env["lliam_home"] / "gateway.lock"
    lock_file.write_text("")
    monkeypatch.setattr(
        uninstall,
        "_process_command_line",
        lambda pid: "/opt/venv/bin/python -m lliam_cli.main gateway run",
    )

    assert uninstall.find_legacy_gateway_services() == [pid_file]
    assert uninstall.remove_legacy_gateway_services() is True

    assert env["kills"] == [424242]
    assert not pid_file.exists()
    assert not lock_file.exists()


def test_pid_file_for_a_reused_pid_is_removed_without_killing(env, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    pid_file = env["lliam_home"] / "gateway.pid"
    pid_file.write_text("424242")
    monkeypatch.setattr(uninstall, "_process_command_line", lambda pid: "/usr/bin/vim notes.txt")

    assert uninstall.remove_legacy_gateway_services() is True
    assert env["kills"] == []
    assert not pid_file.exists()


def test_windows_is_skipped(env, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    (env["lliam_home"] / "gateway.pid").write_text("424242")

    assert uninstall.find_legacy_gateway_services() == []
    assert uninstall.remove_legacy_gateway_services() is False
    assert env["calls"] == []


def _run_doctor(monkeypatch, tmp_path, *, fix, leftover):
    import contextlib
    import io
    import types
    from argparse import Namespace

    import lliam_cli.doctor as doctor_mod

    home = tmp_path / ".hermes"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(doctor_mod, "HERMES_HOME", home)
    monkeypatch.setattr(doctor_mod, "PROJECT_ROOT", tmp_path / "project")
    monkeypatch.setattr(doctor_mod, "_DHH", str(home))
    (tmp_path / "project").mkdir(exist_ok=True)
    monkeypatch.setitem(
        sys.modules,
        "model_tools",
        types.SimpleNamespace(
            check_tool_availability=lambda *a, **kw: ([], []),
            TOOLSET_REQUIREMENTS={},
        ),
    )
    removed: list[bool] = []
    monkeypatch.setattr(uninstall, "find_legacy_gateway_services", lambda: list(leftover))
    monkeypatch.setattr(
        uninstall, "remove_legacy_gateway_services", lambda: removed.append(True) or True
    )

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        doctor_mod.run_doctor(Namespace(fix=fix))
    return buf.getvalue(), removed


@pytest.mark.skipif(sys.platform == "win32", reason="the check is POSIX-only")
def test_doctor_names_leftover_service_and_the_cleanup_command(monkeypatch, tmp_path):
    plist = tmp_path / "com.secondorderstrategy.lliam-gov.gateway.plist"
    out, removed = _run_doctor(monkeypatch, tmp_path, fix=False, leftover=[plist])

    assert f"Leftover gateway service: {plist}" in out
    assert "Remove the leftover gateway service — run 'lliam-gov doctor --fix'" in out
    assert removed == []


@pytest.mark.skipif(sys.platform == "win32", reason="the check is POSIX-only")
def test_doctor_fix_removes_leftover_service(monkeypatch, tmp_path):
    unit = tmp_path / "hermes-gateway.service"
    _, removed = _run_doctor(monkeypatch, tmp_path, fix=True, leftover=[unit])
    assert removed == [True]

    out, removed = _run_doctor(monkeypatch, tmp_path, fix=False, leftover=[])
    assert "Leftover gateway service" not in out
    assert removed == []
