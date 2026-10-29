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
    # Wrapper flags parsed per wrapper (Codex P2 on #145: sudo -n takes no value).
    "sudo -n tee .env < secrets",
    "sudo -u root tee .env < secrets",
    "sudo -E tee .env < secrets",
    "sudo -- tee .env < secrets",
    "sudo -n -u root -E -- tee -a .env < secrets",
    "sudo -nE tee .env < secrets",
    "sudo -uroot tee .env < secrets",
    "sudo --non-interactive --user=root tee .env < secrets",
    "sudo --user root tee .env < secrets",
    "sudo --some-future-flag tee .env < secrets",
    "sudo -Z tee .env < secrets",
    "doas -n -u root tee .env < secrets",
    "env -i PATH=/bin tee .env < secrets",
    "env -u HOME tee .env < secrets",
    "env -S 'tee .env' < secrets",
    "nice -n 5 tee .env < secrets",
    "nice -5 tee .env < secrets",
    "timeout 5 tee .env < secrets",
    "timeout -s KILL 5s tee .env < secrets",
    "timeout --signal=KILL -k 2 5 tee .env < secrets",
    "nohup tee .env < secrets",
    "stdbuf -oL tee .env < secrets",
    "stdbuf -o L -e 0 tee .env < secrets",
    "ionice -c 3 tee .env < secrets",
    "setsid -w tee .env < secrets",
    "command -p tee .env < secrets",
    "exec -a name tee .env < secrets",
    "sudo -n bash -c 'echo k > .env'",
    "sudo 2>/dev/null tee .env < secrets",
    # A quoted operator next to a real redirect still counts the real one.
    "echo '>' > .env",
    "grep '|' notes | tee .env",
    # A # inside a word or in quotes is not a comment; code before a comment counts.
    "echo a#b > .env",
    "echo '#' > .env",
    'echo "x # y" > .env',
    "echo x\\#y > .env",
    "echo hi > .env # note",
    "echo hi # note\necho k > .env",
    "bash -c 'echo k > .env # note'",
    # Heredocs (Codex P2 on #145, round 4): the heredoc's own line is still
    # checked, and so is a body a shell runs or one with a command substitution.
    "cat <<'EOF' > .env\nK=v\nEOF",
    "cat > .env <<'EOF'\nK=v\nEOF",
    "cat <<'EOF' | tee .env\nK=v\nEOF",
    "cat <<'EOF' > README.md\nx\nEOF\necho k > .env",
    "cat <<'EOF' > README.md\nx\nEOF\ntee .env < README.md",
    "cat <<EOF > README.md\n$(echo k > .env)\nEOF",
    "cat <<EOF > README.md\n`echo k > .env`\nEOF",
    "bash <<'EOF'\necho k > .env\nEOF",
    "sudo bash <<'EOF'\necho k > .env\nEOF",
    "sudo -s <<'EOF'\necho k > .env\nEOF",
    "cat <<'EOF' | sh\necho k > .env\nEOF",
    "cat <<'EOF' |\necho k > .env\nEOF\nbash",
    "cat <<'A' > out; bash <<'B'\necho k > .env\nA\necho j > .env\nB",
    # A command substitution inside double quotes or backquotes still runs.
    'echo "$(echo k > .env)"',
    "echo `echo k > .env`",
    "x=`echo k >.env`",
    'echo "`echo k > .env`"',
    'echo "$(printf "%s" ")" > .env)"',
    # Codex P1/P2 on #145 (round 5): a heredoc body is input only when its
    # whole pipeline clearly reads data; subshells and groups don't count.
    "cat <<'EOF' | (sh)\necho K=v > .env\nEOF",
    "cat <<'EOF' | { sh; }\necho K=v > .env\nEOF",
    "cat <<'EOF' | (bash -s)\necho K=v > .env\nEOF",
    "cat <<'EOF' | (true; sh)\necho K=v > .env\nEOF",
    "(cat <<'EOF') | sh\necho K=v > .env\nEOF",
    "{ cat <<'EOF'; } | sh\necho K=v > .env\nEOF",
    "cat <<'EOF' | xargs -I{} sh -c '{}'\necho K=v > .env\nEOF",
    "cat <<'EOF' | sed e\necho K=v > .env\nEOF",
    "cat() { sh; }; cat <<'EOF'\necho K=v > .env\nEOF",
    "hash -p /bin/sh cat; cat <<'EOF'\necho K=v > .env\nEOF",
    "PATH=/tmp/x cat <<'EOF'\necho K=v > .env\nEOF",
    "while read l; do eval \"$l\"; done <<'EOF'\necho K=v > .env\nEOF",
    # Codex P2 on #145 (round 5): an unquoted body expands $(...) and `...`
    # even after # and inside ' characters.
    "cat <<EOF\n# $(echo K=v > .env)\nEOF",
    "cat <<EOF > README.md\n'$(echo K=v > .env)'\nEOF",
    "cat <<EOF > README.md\n# `echo K=v > .env`\nEOF",
    "cat <<EOF > README.md\nx $(echo $(echo K=v > .env))\nEOF",
    # A substitution whose end is unsure falls back to the raw-text check.
    "cat <<EOF > README.md\n$(true # )\necho K=v > .env\n)\nEOF",
    "cat <<EOF > README.md\n$(case x in a) echo K=v > .env;; esac)\nEOF",
    # GitHub Codex P1 on #145: the word after a reserved word is a command.
    "if true; then tee .env < secrets; fi",
    "if true; then tee .env <<< K=v; fi",
    "! tee .env <<< K=v",
    "{ tee .env <<< K=v; }",
    "while true; do tee .env < secrets; done",
    "if tee .env < secrets; then :; fi",
    "until false; do bash -c 'echo k > .env'; done",
    "if true; then eval 'echo k > .env'; else :; fi",
    "coproc tee .env < secrets",
    "function f { tee .env < secrets; }",
    # GitHub Codex P2 on #145: $'...' is decoded and $"..." reads as "...".
    "echo K=v > $'.env'",
    "echo K=v > $'.e\\x6ev'",
    "echo K=v > $'.e\\156v'",
    "echo K=v > $'.e\\u006ev'",
    "echo K=v > $'.env\\0junk'",
    'echo K=v > $".env"',
    "echo K=v | tee $'.env.local'",
    # A glob target can expand to a protected file, so it fails closed.
    "echo K=v > .en?",
    "echo K=v > .env*",
    "echo K=v > .[e]nv",
    # GitHub Codex P1 on #145 (round 7): a here-string a shell runs is a script.
    "bash <<< 'echo K=v > .env'",
    'sh <<< "echo K=v > .env"',
    "sudo bash <<< 'echo K=v > .env'",
    "bash -s <<< 'tee .env < secrets'",
    "eval \"$(cat)\" <<< 'echo K=v > .env'",
    "cat <<< 'echo K=v > .env' | sh",
    "python3 <<< 'echo K=v > .env'",
    # GitHub Codex P1 on #147 (round 7): tee run by xargs or find -exec.
    "printf x | xargs tee .env",
    "find . -maxdepth 0 -exec tee .env \\; <<< K=v",
    "find . -execdir tee .env {} +",
    "find . -ok tee -a .env.local \\;",
    "xargs -n1 sudo tee .env",
    "xargs sh -c 'echo k > .env'",
    "find . -exec bash -c 'echo k > .env' \\;",
    # GitHub Codex P2 on #145 (round 7): a glob is checked against every
    # protected name, not a list of examples.
    "echo K=v > .[e]nv.staging",
    "echo K=v > .ENV.st[a]ging",
    "echo K=v > .env.*",
    "echo K=v > .e*",
    "echo K=v > .*",
    "echo K=v > .[a-z]nv",
    "echo K=v > .[!x]nv",
    "echo K=v > .envr?",
    "echo K=v > .env.sampl?",
    "shopt -s dotglob; echo K=v > ?env",
    # GitHub Codex P1 on #147 (round 8): the shell's -c script is the first
    # word after all its options; -- and - end them.
    "bash -c -- 'tee .env'",
    "bash -c - 'tee .env'",
    "bash -ec 'tee .env'",
    "bash -xc 'echo k > .env'",
    "bash -c -e 'echo k > .env'",
    "bash -o pipefail -c 'echo k > .env'",
    "bash -c -o pipefail 'echo k > .env'",
    "bash +o histexpand -c 'echo k > .env'",
    "bash -O extglob -c 'echo k > .env'",
    "bash --norc --noprofile -c 'echo k > .env'",
    "bash --rcfile /dev/null -c 'echo k > .env'",
    "bash --unknown-option -c x 'echo k > .env'",
    "busybox sh -c -- 'tee .env'",
    "sudo bash -c -- 'tee .env'",
    # GitHub Codex P1/P2 on #147/#145 (round 9): unquoted brace alternatives
    # are expanded before the name checks.
    "tee .env{,.local} <<< K=v",
    "tee .env{,rc} <<< K=v",
    "tee .e{n,x}v < secrets",
    "tee .{e,f}nv < secrets",
    "tee .env.{a,b} < secrets",
    "tee {a,{b,.env}} < secrets",
    "echo K=v > {.env,}",
    "echo K=v >> {a,.envrc}",
    "tee .env{1..2000} < secrets",
    # GitHub Codex P2 on #145 (round 9): env -S words join the invocation.
    "env -S tee .env <<< K=v",
    "env -S 'bash -c' 'echo K=v > .env'",
    "env -S 'tee -a' .env.local < secrets",
    "env -iS tee .env < secrets",
    "env -Stee .env < secrets",
    "env --split-string=tee .env < secrets",
    "env -S 'FOO=1 tee' .env < secrets",
    "env -u X -S tee .env < secrets",
    "sudo env -S tee .env < secrets",
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
    # Quoted or escaped punctuation is an argument, not an operator (Codex P2 on #145).
    "grep '>' .env",
    'grep ">" .env',
    "grep \\> .env",
    "grep '>>' .env",
    "grep \\>\\> .env",
    'grep ">|" .env',
    "grep '|' .env",
    "grep \\| .env",
    "awk '$1 > 2' .env",
    "echo '|' tee .env",
    "echo 'x; tee .env'",
    "echo \\; tee .env",
    'echo "a && tee .env"',
    "sudo -n cat .env",
    "sudo -u root grep KEY .env",
    # A commented-out redirect is not a write (Codex P2 on #145, round 2).
    "cat .env # > .env",
    "cat .env #> .env",
    "grep KEY .env # | tee .env",
    "ls\n# echo x > .env",
    "bash -c 'cat .env # > .env'",
    # A heredoc body is input, not commands (Codex P2 on #145, round 4).
    "cat <<'EOF' > README.md\necho K=v > .env\nEOF",
    'cat <<"EOF" > README.md\necho K=v > .env\nEOF',
    "cat <<\\EOF > README.md\necho K=v > .env\nEOF",
    "cat <<EOF > README.md\necho K=v > .env\nEOF",
    "cat <<-'EOF' > README.md\n\techo K=v > .env\n\tEOF",
    "cat <<'EOF' > README.md\nit's fine > .env\nEOF\necho done",
    "cat <<'EOF' > README.md # docs\necho K=v > .env\nEOF",
    "cat <<'EOF' | grep x\necho k > .env\nEOF",
    "cat <<'A' <<'B' > out\necho k > .env\nA\necho j > .env\nB",
    "bash -c \"cat <<'EOF' > README.md\necho K=v > .env\nEOF\"",
    "cat <<<'echo k > .env'",
    "echo '$(echo k > .env)'",
    'echo "$(cat .env)"',
    # Still input (round 5): a data-only pipeline, an escaped or quoted-off $(.
    "cat <<EOF > README.md\n\\$(echo K=v > .env)\nEOF",
    "cat <<'EOF' > README.md\n# $(echo K=v > .env)\nEOF",
    "cat <<EOF > README.md\nit's $(date) > .env\nEOF",
    "mkdir -p docs && cat <<'EOF' > docs/README.md\necho K=v > .env\nEOF",
    "cat <<'EOF' | sudo tee docs/README.md\necho K=v > .env\nEOF",
    "cat <<'EOF' | grep K | sort\necho K=v > .env\nEOF",
    "if true; then cat .env; fi",
    "{ grep KEY .env; }",
    "echo $'a > .env'",
    "echo K=v > $'.env.example'",
    "echo K=v > *.log",
    "for f in tee .env; do echo $f; done",
    "cat <<< 'echo k > .env'",
    "grep k <<< 'echo k > .env'",
    "cat <<< 'echo k > .env' > notes.txt",
    "xargs echo tee .env",
    "find . -exec echo tee .env \\;",
    "xargs tee out.log",
    "echo K=v > ?env",
    "echo K=v > *",
    "echo K=v > .[x]nv",
    "echo K=v > notes[12].txt",
    "bash -c -- 'cat .env'",
    "bash -c 'cat .env' -- '> .env'",
    "bash script.sh -c 'echo k > .env'",
    "tee '.env{,.local}' < secrets",
    "tee .env\\{,.local\\} < secrets",
    "tee notes{,2}.txt < secrets",
    "tee x{,.env} < secrets",
    "tee {a..z}.env < secrets",
    "echo {.env,x}",
    "echo K=v > {a,b}",
    "env -S cat .env",
    "env -S 'grep KEY' .env",
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


@pytest.mark.parametrize("guard", [check_all_command_guards, check_dangerous_command])
@pytest.mark.parametrize("command", [
    "grep '>' .env", 'grep ">>" .env', "grep \\| .env",
    "cat <<'EOF' > README.md\necho K=v > .env\nEOF",
    "cat <<< 'echo k > .env'",
])
def test_quoted_operator_read_runs_under_yolo(monkeypatch, guard, command):
    # Codex P2 on #145: a quoted > made both guards hard-block a plain read.
    monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", True)
    result = guard(command, "local")
    assert result["approved"] is True, result
    assert not result.get("hardline")


def test_container_backend_unchanged():
    assert check_all_command_guards("echo K=v > .env", "docker")["approved"] is True
