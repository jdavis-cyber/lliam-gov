"""AI-1171: approval resolutions remain visible with the ledger disabled."""

import json
import logging
import threading
from datetime import datetime, timezone

import pytest

import lliam_logging
from agent import governance_audit, governance_audit_hooks
from lliam_constants import get_lliam_home
from tools import approval
from tools.hitl_oversight import LOCAL_OPERATOR_AUTH


SESSION = "approval-log-session"
APPROVER = "local-operator:rome@desktop"


def parse_record(line):
    metadata, command = line.split("approval.decision ", 1)[1].split(" command=", 1)
    record = json.loads(metadata)
    record["command"] = command
    return record


@pytest.fixture
def approval_log(monkeypatch, request):
    ledger_enabled = getattr(request, "param", False)
    home = get_lliam_home()
    (home / "config.yaml").write_text(
        "approvals:\n  mode: manual\n  gateway_timeout: 1\n  timeout: 0\n"
        "security:\n  tirith_enabled: false\n  require_authenticated_approver: true\n"
        f"audit:\n  ledger_enabled: {str(ledger_enabled).lower()}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")
    monkeypatch.setattr(governance_audit, "_ledger_singleton", None)
    monkeypatch.setattr(governance_audit, "_was_enabled", False)
    assert (governance_audit.get_ledger() is not None) is ledger_enabled
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    monkeypatch.setattr(lliam_logging, "_logging_initialized", False)
    session_token = approval.set_current_session_key(SESSION)
    log_dir = lliam_logging.setup_logging(lliam_home=home, force=True)
    try:
        yield log_dir / "agent.log"
    finally:
        approval.unregister_gateway_notify(SESSION)
        approval.clear_session(SESSION)
        approval.reset_current_session_key(session_token)
        for handler in list(root.handlers):
            if handler not in handlers:
                root.removeHandler(handler)
                handler.close()
        root.setLevel(level)


def resolve_from_desktop(choice):
    """Carry the desktop identity on the resolver thread, as the WS layer does."""
    results = []

    def resolve():
        governance_audit_hooks.set_operator_subject(APPROVER, auth=LOCAL_OPERATOR_AUTH)
        try:
            results.append(approval.resolve_gateway_approval(SESSION, choice))
        finally:
            governance_audit_hooks.set_operator_subject(None)

    thread = threading.Thread(target=resolve)
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert results == [1]


@pytest.mark.parametrize("choice,decision", [("once", "approve"), ("deny", "deny"), (None, "timeout")])
def test_resolution_writes_one_complete_record(approval_log, choice, decision):
    command = "rm -rf ./build"
    approval.register_gateway_notify(
        SESSION, lambda data: resolve_from_desktop(choice) if choice else None,
    )
    before = datetime.now(timezone.utc)
    result = approval.check_all_command_guards(command, "local")
    after = datetime.now(timezone.utc)

    assert result["approved"] is (decision == "approve")
    if decision != "approve":
        assert result["outcome"] == ("denied" if decision == "deny" else "timeout")
    lines = [line for line in approval_log.read_text().splitlines()
             if "approval.decision " in line]
    assert len(lines) == 1
    record = parse_record(lines[0])
    assert before <= datetime.fromisoformat(record.pop("timestamp")) <= after
    assert record == {
        "session_id": SESSION,
        "command": command,
        "decision": decision,
        "approver": APPROVER if choice else None,
    }


@pytest.mark.parametrize("choice", ["once", "deny", None])
def test_command_secret_never_reaches_record(approval_log, monkeypatch, caplog, choice):
    from agent import redact

    # Approval evidence must stay redacted even if general log redaction is off.
    monkeypatch.setattr(redact, "_REDACT_ENABLED", False)
    secret = "sk-approvalSecret1234567890"
    command = f"rm -rf ./build\necho {secret}"
    approval.register_gateway_notify(
        SESSION, lambda data: resolve_from_desktop(choice) if choice else None,
    )
    approval.check_all_command_guards(command, "local")

    text = approval_log.read_text()
    assert secret not in text
    records = [r for r in caplog.records if r.getMessage().startswith("approval.decision ")]
    assert len(records) == 1
    assert secret not in records[0].getMessage()
    record = parse_record(records[0].getMessage())
    assert record["command"].startswith(r"rm -rf ./build\necho ")
    assert record["command"] != command
    assert len([line for line in text.splitlines() if "approval.decision " in line]) == 1


@pytest.mark.parametrize("approval_log", [True], indirect=True)
@pytest.mark.parametrize("choice,decision", [("once", "approve"), ("deny", "deny"), (None, "timeout")])
def test_enabled_ledger_keeps_one_attributed_decision(approval_log, choice, decision):
    approval.register_gateway_notify(
        SESSION, lambda data: resolve_from_desktop(choice) if choice else None,
    )
    approval.check_all_command_guards("rm -rf ./build", "local")

    records = [r for r in governance_audit.iter_records()
               if r["event"] == "approval.decision"]
    assert len(records) == 1
    assert records[0]["decision"] == decision
    assert records[0]["parameters"] == {"target": "rm -rf ./build"}
    assert records[0]["approver"] == ({
        "id": APPROVER, "authenticated": True, "method": LOCAL_OPERATOR_AUTH,
    } if choice else {})
    assert governance_audit.verify_chain().ok
    lines = [line for line in approval_log.read_text().splitlines()
             if "approval.decision " in line]
    assert len(lines) == 1


def test_refused_attempt_is_not_a_second_resolution(approval_log):
    def notify(data):
        assert approval.resolve_gateway_approval(SESSION, "once") == 0
        assert approval.has_blocking_approval(SESSION)
        assert "approval.decision " not in approval_log.read_text()
        resolve_from_desktop("deny")

    approval.register_gateway_notify(SESSION, notify)
    result = approval.check_all_command_guards("rm -rf ./build", "local")

    assert result["approved"] is False
    lines = [line for line in approval_log.read_text().splitlines()
             if "approval.decision " in line]
    assert len(lines) == 1
    record = parse_record(lines[0])
    assert record["decision"] == "deny"
    assert record["approver"] == APPROVER


def test_environment_assignment_keeps_all_fields_with_default_redaction(approval_log):
    approval.register_gateway_notify(SESSION, lambda data: resolve_from_desktop("once"))
    approval.check_all_command_guards("rm -rf ./build; API_KEY=secret123", "local")

    text = approval_log.read_text()
    assert "secret123" not in text
    lines = [line for line in text.splitlines() if "approval.decision " in line]
    assert len(lines) == 1
    record = parse_record(lines[0])
    assert record["command"] == "rm -rf ./build; API_KEY=***"
    assert record["decision"] == "approve"
    assert record["session_id"] == SESSION
    assert record["approver"] == APPROVER
    assert datetime.fromisoformat(record["timestamp"]).tzinfo is not None


@pytest.mark.parametrize("guard", [approval.check_all_command_guards, approval.check_dangerous_command])
@pytest.mark.parametrize("choice,decision", [("once", "approve"), ("deny", "deny"), (None, "timeout")])
def test_cli_resolution_writes_one_record(approval_log, monkeypatch, guard, choice, decision):
    monkeypatch.delenv("HERMES_GATEWAY_SESSION")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    finished = threading.Event()
    monkeypatch.setattr("builtins.input", lambda prompt: finished.wait(5) and "deny")
    governance_audit_hooks.set_operator_subject(APPROVER, auth=LOCAL_OPERATOR_AUTH)
    try:
        callback = (lambda *args, **kwargs: choice) if choice else None
        result = guard("rm -rf ./build", "local", approval_callback=callback)
    finally:
        finished.set()
        governance_audit_hooks.set_operator_subject(None)

    assert result["approved"] is (decision == "approve")
    lines = [line for line in approval_log.read_text().splitlines()
             if "approval.decision " in line]
    assert len(lines) == 1
    record = parse_record(lines[0])
    assert record["command"] == "rm -rf ./build"
    assert record["decision"] == decision
    assert record["session_id"] == SESSION
    assert record["approver"] == (APPROVER if choice else None)


def test_callback_timeout_is_recorded_as_timeout(approval_log, monkeypatch):
    # The CLI and ACP callbacks return "deny" when nobody answers; the record
    # must not attribute that refusal to the bound operator.
    monkeypatch.delenv("HERMES_GATEWAY_SESSION")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")

    def unanswered(*args, **kwargs):
        approval.mark_approval_timed_out()
        return "deny"

    governance_audit_hooks.set_operator_subject(APPROVER, auth=LOCAL_OPERATOR_AUTH)
    try:
        result = approval.check_dangerous_command(
            "rm -rf ./build", "local", approval_callback=unanswered
        )
        approval.check_dangerous_command(
            "rm -rf ./dist", "local", approval_callback=lambda *a, **k: "deny"
        )
    finally:
        governance_audit_hooks.set_operator_subject(None)

    assert result["approved"] is False
    records = [parse_record(line) for line in approval_log.read_text().splitlines()
               if "approval.decision " in line]
    assert [(r["decision"], r["approver"]) for r in records] == [
        ("timeout", None), ("deny", APPROVER),
    ]
