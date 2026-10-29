"""AI-1178 (DEF-018 part 2): shell writes into .env files are refused outright.

A redirect (``>``, ``>>``, ``>|``, ``&>``, ``>&``) or ``tee``/``tee -a`` whose
target is a protected environment file (``.env``, ``.env.<anything>`` except
``.env.example`` / ``.env.sample``, ``.envrc``) used to be an approval rule.
It is now a hard floor like the hardline list: no prompt, and yolo,
approvals.mode=off and cron approve mode do not lift it. Reads stay allowed.
"""

import pytest

import tools.approval as approval_module
from tools.approval import (
    check_all_command_guards,
    check_dangerous_command,
    detect_env_file_write,
)

BLOCKED = [
    "echo KEY=1 > .env",
    "echo KEY=1 >> .env",
    "echo KEY=1>.env",
    "printf 'K=v\\n' >| .env",
    "make 2>&1 &> .env",
    "echo x >& .env",
    "echo x > .env.local",
    "echo x > .env.production",
    "echo x > ./x/.env",
    "echo x > /srv/app/.env",
    "echo x > ~/.lliam/.env",
    "echo x > \"$HOME/proj/.env\"",
    "echo x > '.env'",
    "echo x > \".env.local\"",
    "echo x > .e\\nv",
    "echo x > .e\"\"nv",
    "echo x > .ENV",
    "echo x > .envrc",
    "cat secrets | tee .env",
    "cat secrets | tee -a .env",
    "cat secrets | sudo tee -a ./x/.env.production",
    "cat secrets | tee out.log .env",
    "cat secrets |& tee .env",
    "ls; tee .env < secrets",
    "ls\ntee .env < secrets",
    "true && echo k=v > .env && ls",
    "(echo k=v) > .env",
    "echo $(cat key) > .env",
    "cat <<EOF > .env\nK=v\nit's here\nEOF",
    "cmd >(tee .env)",
    "/usr/bin/tee .env < secrets",
    "env FOO=1 tee .env < secrets",
    "echo x 1> .env",
    "echo x 2>> .env",
    "echo x &>> .env",
    "tee --append .env < secrets",
    'bash -c "echo x > .env"',
    "sh -c 'cat k | tee -a .env.local'",
    "sudo bash -lc 'echo k >> ./x/.env'",
    "eval 'echo k > .env'",
]

ALLOWED = [
    "cat .env",
    "grep KEY .env",
    "source .env",
    ". ./.env",
    "python app.py < .env",
    "diff .env .env.example",
    "echo x > .env.example",
    "echo x > .env.sample",
    "echo x > env.txt",
    "echo x > my.env",
    "echo x > .environment",
    "echo 'see > .env in docs' > notes.txt",
    "echo tee .env",
    "ls 2>&1",
    "echo done >&2",
    "cat secrets | tee out.log",
    'bash -c "cat .env"',
    "sh -c 'grep KEY .env > out.txt'",
]


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for name in ("LLIAM_INTERACTIVE", "LLIAM_GATEWAY_SESSION", "LLIAM_EXEC_ASK",
                 "LLIAM_CRON_SESSION", "LLIAM_YOLO_MODE", "LLIAM_SESSION_PLATFORM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: {"security": {}})
    monkeypatch.setattr(approval_module, "_get_approval_config", lambda: {})
    monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", False)
    approval_module._permanent_approved.clear()
    approval_module.clear_session("default")
    yield
    approval_module._permanent_approved.clear()
    approval_module.clear_session("default")


@pytest.mark.parametrize("command", BLOCKED)
def test_env_write_detected(command):
    blocked, description = detect_env_file_write(command)
    assert blocked, command
    assert ".env" in description.lower()


@pytest.mark.parametrize("command", ALLOWED)
def test_reads_and_other_files_not_detected(command):
    assert detect_env_file_write(command) == (False, None), command


def _assert_hard_refusal(result):
    assert result["approved"] is False
    assert result.get("hardline") is True
    assert result.get("status") not in {"approval_required", "pending_approval"}
    assert "protected environment file" in result["message"]


@pytest.mark.parametrize("guard", [check_all_command_guards, check_dangerous_command])
def test_refused_without_prompt_even_interactive(monkeypatch, guard):
    monkeypatch.setenv("LLIAM_INTERACTIVE", "1")
    calls = []

    def _callback(*args, **kwargs):
        calls.append(args)
        return "once"

    result = guard("echo K=v >> .env", "local", approval_callback=_callback)
    _assert_hard_refusal(result)
    assert calls == []


@pytest.mark.parametrize("guard", [check_all_command_guards, check_dangerous_command])
def test_gateway_does_not_queue_it(monkeypatch, guard):
    monkeypatch.setenv("LLIAM_EXEC_ASK", "1")
    monkeypatch.setenv("LLIAM_GATEWAY_SESSION", "1")
    _assert_hard_refusal(guard("cat k | tee -a .env", "local"))


@pytest.mark.parametrize("guard", [check_all_command_guards, check_dangerous_command])
def test_yolo_does_not_lift_it(monkeypatch, guard):
    monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", True)
    _assert_hard_refusal(guard("echo K=v > .env.local", "local"))


def test_session_yolo_does_not_lift_it():
    token = approval_module.set_current_session_key("env-yolo")
    try:
        approval_module.enable_session_yolo("env-yolo")
        _assert_hard_refusal(check_all_command_guards("echo K=v > .env", "local"))
    finally:
        approval_module.clear_session("env-yolo")
        approval_module.reset_current_session_key(token)


def test_approvals_mode_off_does_not_lift_it(monkeypatch):
    monkeypatch.setattr(approval_module, "_get_approval_config", lambda: {"mode": "off"})
    _assert_hard_refusal(check_all_command_guards("echo K=v > .env", "local"))


def test_cron_approve_does_not_lift_it(monkeypatch):
    monkeypatch.setattr("tools.approval._get_cron_approval_mode", lambda: "approve")
    token = approval_module.set_cron_session()
    try:
        _assert_hard_refusal(check_all_command_guards("echo K=v > .env", "local"))
    finally:
        approval_module.reset_cron_session(token)


def test_permanent_approval_does_not_lift_it():
    for key, _desc in approval_module.detect_all_dangerous_commands("echo K=v > .env"):
        approval_module.approve_permanent(key)
    _assert_hard_refusal(check_all_command_guards("echo K=v > .env", "local"))


def test_reads_still_run_under_yolo(monkeypatch):
    monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", True)
    assert check_all_command_guards("cat .env", "local")["approved"] is True


def test_container_backend_unchanged():
    assert check_all_command_guards("echo K=v > .env", "docker")["approved"] is True
