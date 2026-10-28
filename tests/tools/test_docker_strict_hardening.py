"""Strict-posture sandbox lock for the Docker terminal backend (JER-74).

Under ``security.posture: strict`` the container hardening (cap-drop ALL,
no-new-privileges, PID limit, CPU/memory ceilings, network mode) must not be
undone by ``terminal.docker_extra_args`` (appended last to ``docker run``) or
by bind-mounting sensitive host paths. Low-side behaviour stays unchanged.
"""

import os
import subprocess
from pathlib import Path

import pytest
import yaml

from tools.environments import docker as docker_env

_REPO = Path(__file__).resolve().parents[2]


def _mock_subprocess_run(monkeypatch, ps_stdout=""):
    calls = []

    def _run(cmd, **kwargs):
        calls.append(list(cmd) if isinstance(cmd, list) else cmd)
        if isinstance(cmd, list) and len(cmd) >= 2:
            if cmd[1] == "version":
                return subprocess.CompletedProcess(cmd, 0, stdout="Docker version", stderr="")
            if cmd[1] == "run":
                return subprocess.CompletedProcess(cmd, 0, stdout="fake-container-id\n", stderr="")
            if cmd[1] == "ps":
                return subprocess.CompletedProcess(cmd, 0, stdout=ps_stdout, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(docker_env.subprocess, "run", _run)
    return calls


@pytest.fixture
def docker_calls(monkeypatch):
    monkeypatch.setattr(docker_env, "find_docker", lambda: "/usr/bin/docker")
    monkeypatch.setattr(docker_env, "_get_active_profile_name", lambda: "default")
    monkeypatch.setattr(docker_env.DockerEnvironment, "init_session", lambda self: None)
    return _mock_subprocess_run(monkeypatch)


def _make_env(*, strict, extra_args=None, cpu=2, memory=4096, network=False, **kwargs):
    return docker_env.DockerEnvironment(
        image="python:3.11",
        cwd=kwargs.pop("cwd", "/root"),
        timeout=60,
        cpu=cpu,
        memory=memory,
        disk=0,
        task_id=kwargs.pop("task_id", "strict-test"),
        network=network,
        extra_args=extra_args,
        strict_posture=strict,
        **kwargs,
    )


def _run_argv(calls):
    runs = [c for c in calls if isinstance(c, list) and len(c) >= 2 and c[1] == "run"]
    assert runs, "docker run should have been called"
    return runs[0]


def _home():
    return os.path.expanduser("~")


# ── denylisted flags are refused under strict ──────────────────────

_DENIED = [
    ["--privileged"],
    ["--privileged=true"],
    ["--cap-add", "ALL"],
    ["--cap-add=SYS_ADMIN"],
    ["--security-opt", "seccomp=unconfined"],
    ["--security-opt=apparmor=unconfined"],
    ["--security-opt", "no-new-privileges=false"],
    ["--network", "host"],
    ["--network=host"],
    ["--net", "host"],
    ["--net=bridge"],
    ["--network", "container:other"],
    ["--pid", "host"],
    ["--pid=host"],
    ["--pid", "container:other"],
    ["--ipc=host"],
    ["--uts", "host"],
    ["--userns", "host"],
    ["--userns=host"],
    ["--cgroupns", "host"],
    ["--device", "/dev/kvm"],
    ["--device=/dev/sda"],
    ["--device-cgroup-rule", "c *:* rmw"],
    ["--gpus", "all"],
    ["-v", "/:/host"],
    ["-v/:/host"],
    ["-v=/:/host"],
    ["-dv", "/:/host"],
    ["--volume", "/:/host"],
    ["--volume=/etc:/hostetc:ro"],
    ["-v", "/var/run/docker.sock:/var/run/docker.sock"],
    ["-v", "/run/containerd/containerd.sock:/c.sock"],
    ["-v", "/var:/hostvar"],
    ["-v", "/proc:/hostproc"],
    ["--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock"],
    ["--mount=type=bind,src=/,dst=/host,readonly"],
    ["--mount", "type=volume,dst=/x,volume-opt=type=none,volume-opt=o=bind,volume-opt=device=/"],
    ["--volumes-from", "other-container"],
    ["-m", "0"],
    ["-m0"],
    ["--memory=0"],
    ["--memory-swap", "-1"],
    ["--cpus", "0"],
    ["--cpu-quota=-1"],
    ["--pids-limit", "-1"],
    ["--oom-kill-disable"],
    ["--storage-opt", "size=0"],
    ["--cgroup-parent", "/"],
    ["--runtime", "runc"],
    ["-p", "8080:80"],
    ["--publish=0.0.0.0:2222:22"],
    ["-P"],
    # A value-taking flag cannot smuggle a denied flag past the scan.
    ["--env", "--privileged"],
    ["--env=A=1", "--cap-add", "NET_ADMIN"],
    ["--label", "a=b", "--security-opt", "seccomp=unconfined"],
]


@pytest.mark.parametrize("extra_args", _DENIED, ids=lambda a: " ".join(a))
def test_strict_refuses_denylisted_extra_args(docker_calls, extra_args):
    with pytest.raises(docker_env.DockerHardeningError) as excinfo:
        _make_env(strict=True, extra_args=extra_args)

    message = str(excinfo.value)
    assert "security.posture=strict" in message
    assert "docker_extra_args" in message
    # Refused before Docker is touched — nothing is started.
    assert docker_calls == []


@pytest.mark.parametrize("sub", [".ssh", ".aws", ".docker", ".kube"])
def test_strict_refuses_mounting_home_credentials(docker_calls, sub):
    src = os.path.join(_home(), sub)
    with pytest.raises(docker_env.DockerHardeningError):
        _make_env(strict=True, extra_args=["-v", f"{src}:/creds:ro"])


def test_strict_refuses_mounting_entire_home(docker_calls):
    with pytest.raises(docker_env.DockerHardeningError, match="parent of sensitive host path"):
        _make_env(strict=True, extra_args=["--volume", f"{_home()}:/h"])


def test_strict_refuses_mounting_lliam_env_file(docker_calls):
    from lliam_constants import get_lliam_home

    env_file = get_lliam_home() / ".env"
    with pytest.raises(docker_env.DockerHardeningError, match="sensitive host file"):
        _make_env(strict=True, extra_args=["-v", f"{env_file}:/secrets.env:ro"])


def test_strict_error_lists_every_violation(docker_calls):
    with pytest.raises(docker_env.DockerHardeningError) as excinfo:
        _make_env(strict=True, extra_args=["--privileged", "--pid=host", "-v", "/:/host"])
    message = str(excinfo.value)
    assert "--privileged" in message
    assert "--pid" in message
    assert "host root filesystem" in message


# ── benign extra args still accepted under strict ──────────────────


def _benign_cases(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    return [
        ["--env", "FOO=bar"],
        ["-e", "FOO=bar"],
        ["-eFOO=bar"],
        ["--env=FOO=bar"],
        ["--label", "team=gov"],
        ["-l", "team=gov"],
        ["--label=team=gov"],
        ["--add-host", "db.internal:10.0.0.5"],
        ["--hostname", "sandbox"],
        ["--shm-size", "256m"],
        ["--network", "none"],
        ["--network=none"],
        ["--ipc", "private"],
        ["--cap-drop", "NET_RAW"],
        ["-v", f"{data}:/data"],
        ["-v", "named-cache:/cache"],
        ["--mount", f"type=bind,src={data},dst=/data,readonly"],
        ["--mount", "type=tmpfs,dst=/scratch"],
        ["--mount", "type=volume,src=named-cache,dst=/cache"],
    ]


def test_strict_accepts_benign_extra_args(monkeypatch, tmp_path):
    monkeypatch.setattr(docker_env, "find_docker", lambda: "/usr/bin/docker")
    monkeypatch.setattr(docker_env, "_get_active_profile_name", lambda: "default")
    monkeypatch.setattr(docker_env.DockerEnvironment, "init_session", lambda self: None)
    for extra in _benign_cases(tmp_path):
        calls = _mock_subprocess_run(monkeypatch)
        _make_env(strict=True, extra_args=extra)
        argv = _run_argv(calls)
        image_idx = argv.index("python:3.11")
        assert argv[image_idx - len(extra):image_idx] == extra, extra


def test_strict_accepts_benign_docker_volumes(docker_calls, tmp_path):
    data = tmp_path / "proj"
    data.mkdir()
    _make_env(strict=True, volumes=[f"{data}:/workspace/proj"])
    assert f"{data}:/workspace/proj" in _run_argv(docker_calls)


# ── docker_volumes / cwd auto-mount use the same mount policy ──────


@pytest.mark.parametrize("volume", [
    "/:/host",
    "/var/run/docker.sock:/var/run/docker.sock",
    "/etc:/hostetc:ro",
])
def test_strict_refuses_sensitive_docker_volumes(docker_calls, volume):
    with pytest.raises(docker_env.DockerHardeningError, match="docker_volumes"):
        _make_env(strict=True, volumes=[volume])
    assert docker_calls == []


def test_strict_refuses_auto_mounting_home_as_cwd(docker_calls):
    with pytest.raises(docker_env.DockerHardeningError, match="docker_mount_cwd_to_workspace"):
        _make_env(strict=True, cwd="/workspace", host_cwd=_home(), auto_mount_cwd=True)


# ── resource ceilings + network in the actual docker run argv ──────


@pytest.mark.parametrize("cpu,memory", [(0, 4096), (2, 0), (0, 0), (-1, 4096)])
def test_strict_refuses_unbounded_resources(docker_calls, cpu, memory):
    with pytest.raises(docker_env.DockerHardeningError, match="unbounded"):
        _make_env(strict=True, cpu=cpu, memory=memory)
    assert docker_calls == []


def test_strict_run_argv_carries_limits_and_no_network(docker_calls):
    _make_env(strict=True, cpu=2, memory=4096, network=False,
              extra_args=["--env", "FOO=bar"])
    argv = _run_argv(docker_calls)

    assert argv[argv.index("--cpus") + 1] == "2"
    assert argv[argv.index("--memory") + 1] == "4096m"
    assert "--network=none" in argv
    # Hardening is present and nothing later in argv re-opens it.
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv.count("--security-opt") == 1
    assert argv.count("--cpus") == 1
    assert argv.count("--memory") == 1
    assert not any(a.startswith(("--network", "--net")) and a != "--network=none" for a in argv)
    assert "--privileged" not in argv


def test_strict_reuse_is_pinned_to_hardened_run_fingerprint(monkeypatch):
    monkeypatch.setattr(docker_env, "find_docker", lambda: "/usr/bin/docker")
    monkeypatch.setattr(docker_env, "_get_active_profile_name", lambda: "default")
    monkeypatch.setattr(docker_env.DockerEnvironment, "init_session", lambda self: None)
    calls = _mock_subprocess_run(monkeypatch)

    env = _make_env(strict=True)

    fingerprint = env._labels.get("hermes-run-sha")
    assert fingerprint
    ps = [c for c in calls if isinstance(c, list) and c[1:2] == ["ps"]]
    assert ps and f"label=hermes-run-sha={fingerprint}" in ps[0]
    assert f"hermes-run-sha={fingerprint}" in _run_argv(calls)


def test_strict_fingerprint_changes_with_run_args(docker_calls):
    a = _make_env(strict=True, memory=4096)
    b = _make_env(strict=True, memory=2048)
    assert a._labels["hermes-run-sha"] != b._labels["hermes-run-sha"]


# ── strict posture is resolved from the effective config ──────────


def test_posture_resolved_from_config_when_not_passed(docker_calls, monkeypatch):
    from lliam_cli import config as cfg

    monkeypatch.setattr(cfg, "load_config", lambda: {"security": {"posture": "strict"}})
    with pytest.raises(docker_env.DockerHardeningError):
        docker_env.DockerEnvironment(
            image="python:3.11", cpu=2, memory=4096, task_id="t",
            extra_args=["--privileged"],
        )


def test_permissive_posture_resolved_from_config(docker_calls, monkeypatch):
    from lliam_cli import config as cfg

    monkeypatch.setattr(cfg, "load_config", lambda: {"security": {"posture": "permissive"}})
    docker_env.DockerEnvironment(
        image="python:3.11", task_id="t", extra_args=["--privileged"],
    )
    assert "--privileged" in _run_argv(docker_calls)


# ── low-side behaviour unchanged ───────────────────────────────────


def test_low_side_passes_extra_args_verbatim(docker_calls):
    extra = ["--privileged", "--cap-add", "ALL", "-v", "/:/host", "--network", "host"]
    _make_env(strict=False, extra_args=extra, cpu=0, memory=0, network=True)
    argv = _run_argv(docker_calls)

    image_idx = argv.index("python:3.11")
    assert argv[image_idx - len(extra):image_idx] == extra
    assert "--cpus" not in argv
    assert "--memory" not in argv
    assert "--network=none" not in argv
    assert not any(a.startswith("hermes-run-sha=") for a in argv)


def test_low_side_accepts_sensitive_docker_volumes(docker_calls):
    _make_env(strict=False, volumes=["/var/run/docker.sock:/var/run/docker.sock"])
    assert "/var/run/docker.sock:/var/run/docker.sock" in _run_argv(docker_calls)


# ── governed overlay -> terminal_tool -> docker run ────────────────


def test_gov_overlay_terminal_settings_reach_docker_run(docker_calls, monkeypatch):
    """The overlay's terminal.* values, bridged to TERMINAL_* env vars the way
    startup does, produce a strict docker run with the ceilings and no network."""
    from lliam_cli.config import TERMINAL_CONFIG_ENV_MAP, _terminal_env_value
    from tools import terminal_tool

    overlay = yaml.safe_load((_REPO / "cli-config.gov.yaml").read_text(encoding="utf-8"))
    terminal = overlay["terminal"]
    assert terminal["container_cpu"] == 2
    assert terminal["container_memory"] == 4096
    assert terminal["docker_network"] is False

    for key, value in terminal.items():
        env_var = TERMINAL_CONFIG_ENV_MAP.get(key)
        if env_var:
            monkeypatch.setenv(env_var, _terminal_env_value(value))
    monkeypatch.setattr(docker_env, "_strict_posture_active", lambda: True)

    config = terminal_tool._get_env_config()
    assert config["env_type"] == "docker"
    assert config["docker_network"] is False

    container_config = {
        "container_cpu": config["container_cpu"],
        "container_memory": config["container_memory"],
        "container_disk": 0,
        "container_persistent": False,
        "docker_extra_args": config["docker_extra_args"],
        "docker_network": config["docker_network"],
        "docker_orphan_reaper": False,
    }
    terminal_tool._create_environment(
        env_type="docker", image="python:3.11", cwd="/root", timeout=60,
        container_config=container_config, task_id="gov-overlay",
    )
    argv = _run_argv(docker_calls)
    assert float(argv[argv.index("--cpus") + 1]) == 2
    assert argv[argv.index("--memory") + 1] == "4096m"
    assert "--network=none" in argv


def test_docker_network_defaults_on_for_low_side(monkeypatch):
    from tools import terminal_tool

    monkeypatch.setenv("TERMINAL_ENV", "docker")
    monkeypatch.delenv("TERMINAL_DOCKER_NETWORK", raising=False)
    assert terminal_tool._get_env_config()["docker_network"] is True
