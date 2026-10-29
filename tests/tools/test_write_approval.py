"""Tests for the memory/skill write-approval gate (tools/write_approval.py)
and the shared slash-command handlers (lliam_cli/write_approval_commands.py).

Covers the optional memory gate, mandatory skill approval, pending store CRUD,
review commands, and durable operator decisions before apply/discard.
"""

import json
import os
import tempfile
import shutil

import pytest


@pytest.fixture
def lliam_home(monkeypatch):
    d = tempfile.mkdtemp(prefix="hermes_wa_test_")
    home = os.path.join(d, ".hermes")
    os.makedirs(home)
    monkeypatch.setenv("HERMES_HOME", home)
    yield home
    shutil.rmtree(d, ignore_errors=True)


def _set_approval(subsystem, enabled):
    import lliam_cli.config as cfg
    c = cfg.load_config()
    c.setdefault(subsystem, {})["write_approval"] = enabled
    cfg.save_config(c)


# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------

def test_only_memory_gate_defaults_off(lliam_home):
    from tools import write_approval as wa
    # Default: gate off → writes flow freely.
    assert wa.write_approval_enabled("memory") is False
    assert wa.write_approval_enabled("skills") is True


@pytest.mark.parametrize("setting", [False, True, "off", None])
def test_skill_approval_setting_is_ignored(lliam_home, setting):
    from tools import write_approval as wa
    _set_approval("skills", setting)
    assert wa.write_approval_enabled("skills") is True
    assert wa.evaluate_gate("skills").stage


def test_invalid_subsystem_is_off(lliam_home):
    from tools import write_approval as wa
    assert wa.write_approval_enabled("bogus") is False


def test_normalize_enabled_coerces_values():
    from tools import write_approval as wa
    # Real bools pass through.
    assert wa._normalize_enabled(True) is True
    assert wa._normalize_enabled(False) is False
    # Truthy strings → True (incl. legacy 'approve').
    assert wa._normalize_enabled("on") is True
    assert wa._normalize_enabled("approve") is True
    assert wa._normalize_enabled("true") is True
    # Everything else → False (gate off is the safe default).
    assert wa._normalize_enabled("off") is False
    assert wa._normalize_enabled("garbage") is False
    assert wa._normalize_enabled(None) is False


# ---------------------------------------------------------------------------
# Memory gate
# ---------------------------------------------------------------------------

def test_memory_gate_off_allows_write(lliam_home):
    # Default (gate off) → write straight through, no staging.
    from tools.memory_tool import memory_tool, MemoryStore
    from tools import write_approval as wa
    store = MemoryStore(); store.load_from_disk()
    r = json.loads(memory_tool("add", "user", "save me", store=store))
    assert r["success"] is True
    assert r["entry_count"] == 1
    assert wa.pending_count("memory") == 0


def test_memory_gate_on_no_interactive_stages(lliam_home):
    # Gate on, no approval callback / not a gateway context → stage.
    from tools.memory_tool import memory_tool, MemoryStore
    from tools import write_approval as wa
    _set_approval("memory", True)
    store = MemoryStore(); store.load_from_disk()
    r = json.loads(memory_tool("add", "memory", "stage me", store=store))
    assert r.get("staged") is True
    assert r.get("pending_id")
    # Not written to the live store yet.
    assert store.memory_entries == []
    pend = wa.list_pending("memory")
    assert len(pend) == 1
    assert pend[0]["id"] == r["pending_id"]


def test_memory_gate_on_then_apply(lliam_home):
    from tools.memory_tool import memory_tool, MemoryStore, apply_memory_pending
    from tools import write_approval as wa
    _set_approval("memory", True)
    store = MemoryStore(); store.load_from_disk()
    r = json.loads(memory_tool("add", "user", "approved entry", store=store))
    pid = r["pending_id"]
    rec = wa.get_pending("memory", pid)
    result = apply_memory_pending(rec["payload"], store)
    assert result["success"] is True
    assert "approved entry" in store.user_entries[0]


def test_cli_memory_approve_without_live_agent_uses_fresh_store(lliam_home, capsys):
    """#46783: ``/memory approve`` from a context with no live agent (e.g. the
    Desktop GUI) passed ``memory_store=None`` into the shared handler, which
    returned "memory store unavailable" and applied nothing. The CLI handler must
    fall back to a freshly loaded on-disk store, like the gateway path does."""
    import json
    from tools.memory_tool import memory_tool, MemoryStore
    from tools import write_approval as wa
    from lliam_cli.cli_commands_mixin import CLICommandsMixin

    _set_approval("memory", True)
    staging = MemoryStore(); staging.load_from_disk()
    r = json.loads(memory_tool("add", "memory", "remember the launch date", store=staging))
    assert r.get("pending_id"), r
    assert wa.pending_count("memory") == 1

    # Bare CLI handler with no live agent → store resolves to None pre-fix.
    handler = CLICommandsMixin.__new__(CLICommandsMixin)
    handler.agent = None
    handler._handle_memory_command("/memory approve all")

    out = capsys.readouterr().out
    assert "memory store unavailable" not in out, out
    assert "Approved 1" in out, out
    assert wa.pending_count("memory") == 0
    # The approved write landed in a freshly loaded on-disk store (MEMORY.md).
    reloaded = MemoryStore(); reloaded.load_from_disk()
    assert any("remember the launch date" in e for e in reloaded.memory_entries)


def test_load_on_disk_store_honors_configured_char_limits(lliam_home, monkeypatch):
    """load_on_disk_store() must read memory.memory_char_limit /
    user_char_limit from config so approvals applied without a live agent
    enforce the SAME caps as the live agent (agent_init.py). Falls back to
    defaults when config can't be loaded.
    """
    from tools.memory_tool import load_on_disk_store

    # Config override path: helper picks up the configured limits.
    monkeypatch.setattr(
        "lliam_cli.config.load_config",
        lambda: {"memory": {"memory_char_limit": 999, "user_char_limit": 444}},
    )
    store = load_on_disk_store()
    assert store.memory_char_limit == 999
    assert store.user_char_limit == 444

    # Failure path: config raises → defaults, never blows up.
    def _boom():
        raise RuntimeError("no config")

    monkeypatch.setattr("lliam_cli.config.load_config", _boom)
    fallback = load_on_disk_store()
    assert fallback.memory_char_limit == 2200
    assert fallback.user_char_limit == 1375


# ---------------------------------------------------------------------------
# Skill gate
# ---------------------------------------------------------------------------

_SKILL = (
    "---\nname: test-skill\ndescription: A test skill\nversion: 1.0.0\n---\n"
    "# Test\nbody\n"
)


def test_skill_gate_off_still_requires_operator_approval(lliam_home):
    # Agent skill proposals require approval even with the optional gate off.
    import importlib
    import tools.skill_manager_tool as smt
    importlib.reload(smt)
    from tools import write_approval as wa
    r = json.loads(smt.skill_manage("create", "free-skill", content=_SKILL))
    assert r.get("success") is True
    assert r["staged"] is True
    assert smt._find_skill("free-skill") is None
    assert wa.pending_count("skills") == 1


def test_skill_gate_on_always_stages(lliam_home):
    # Skills stage even in the foreground (too big to review inline).
    from tools.skill_manager_tool import skill_manage
    from tools import write_approval as wa
    _set_approval("skills", True)
    r = json.loads(skill_manage("create", "staged-skill", content=_SKILL))
    assert r.get("staged") is True
    assert "staged-skill" in r.get("gist", "")
    assert wa.pending_count("skills") == 1


def test_skill_gate_on_then_apply_writes_file(lliam_home):
    # SKILLS_DIR is resolved at import time, so reload the skill module under
    # this test's HERMES_HOME to exercise the real on-disk write path.
    import importlib
    import tools.skill_manager_tool as smt
    importlib.reload(smt)
    from tools import write_approval as wa
    _set_approval("skills", True)
    r = json.loads(smt.skill_manage("create", "applied-skill", content=_SKILL))
    rec = wa.get_pending("skills", r["pending_id"])
    wa.record_write_decision("skills", rec, "approve", operator=wa.issue_operator_capability())
    res = json.loads(smt.apply_skill_pending(rec["id"]))
    assert res["success"] is True
    assert smt._find_skill("applied-skill") is not None


def test_skill_create_diff_is_full_content(lliam_home):
    from tools.skill_manager_tool import skill_manage
    from tools import write_approval as wa
    _set_approval("skills", True)
    r = json.loads(skill_manage("create", "diff-skill", content=_SKILL))
    rec = wa.get_pending("skills", r["pending_id"])
    diff = wa.skill_pending_diff(rec)
    assert "name: test-skill" in diff


# ---------------------------------------------------------------------------
# Pending store CRUD
# ---------------------------------------------------------------------------

def test_pending_store_roundtrip(lliam_home):
    from tools import write_approval as wa
    rec = wa.stage_write("memory", {"action": "add", "target": "user", "content": "x"},
                         summary="add x", origin="foreground")
    assert wa.pending_count("memory") == 1
    got = wa.get_pending("memory", rec["id"])
    assert got["payload"]["content"] == "x"
    assert wa.discard_pending("memory", rec["id"]) is True
    assert wa.pending_count("memory") == 0
    assert wa.get_pending("memory", rec["id"]) is None


# ---------------------------------------------------------------------------
# Shared command handler
# ---------------------------------------------------------------------------

def test_handle_pending_list_empty(lliam_home):
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    out = handle_pending_subcommand(wa.MEMORY, ["pending"])
    assert "No pending memory" in out


def test_handle_approve_all(lliam_home):
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools.memory_tool import MemoryStore
    from tools import write_approval as wa
    store = MemoryStore(); store.load_from_disk()
    wa.stage_write("memory", {"action": "add", "target": "user", "content": "a"},
                   summary="a", origin="foreground")
    wa.stage_write("memory", {"action": "add", "target": "user", "content": "b"},
                   summary="b", origin="foreground")
    out = handle_pending_subcommand(wa.MEMORY, ["approve", "all"], memory_store=store)
    assert "Approved 2" in out
    assert wa.pending_count("memory") == 0
    assert len(store.user_entries) == 2


def test_handle_reject(lliam_home):
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    rec = wa.stage_write("skills", {"action": "create", "name": "s"},
                         summary="create s", origin="background_review")
    out = handle_pending_subcommand(wa.SKILLS, ["reject", rec["id"]])
    assert "Rejected" in out
    assert wa.pending_count("skills") == 0


def test_handle_approval_on(lliam_home):
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    captured = {}
    out = handle_pending_subcommand(
        wa.MEMORY, ["approval", "on"],
        set_mode_fn=lambda enabled: captured.update(enabled=enabled),
    )
    assert captured["enabled"] is True
    assert "on" in out


@pytest.mark.parametrize("mode", ["on", "off"])
def test_skill_approval_toggle_does_not_persist(lliam_home, mode):
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    captured = {}
    out = handle_pending_subcommand(
        wa.SKILLS, ["approval", mode],
        set_mode_fn=lambda enabled: captured.update(enabled=enabled),
    )
    assert captured == {}
    assert "always" in out.lower() and "approval" in out.lower()
    assert "always" in handle_pending_subcommand(wa.SKILLS, []).lower()


def test_handle_mode_alias_still_works(lliam_home):
    # 'mode' is kept as a back-compat alias for 'approval'.
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    captured = {}
    out = handle_pending_subcommand(
        wa.MEMORY, ["mode", "on"],
        set_mode_fn=lambda enabled: captured.update(enabled=enabled),
    )
    assert captured["enabled"] is True
    assert "on" in out


def test_handle_approval_invalid(lliam_home):
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    out = handle_pending_subcommand(wa.MEMORY, ["approval", "bogus"],
                                    set_mode_fn=lambda enabled: None)
    assert "Invalid value" in out


def test_handle_unknown_subcommand_returns_none(lliam_home):
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    # An unrecognized /skills subcommand (e.g. 'search') must return None so
    # the CLI falls through to the skills hub.
    out = handle_pending_subcommand(wa.SKILLS, ["search", "foo"])
    assert out is None


# ---------------------------------------------------------------------------
# Inline (interactive CLI) approval path — regression for the bug where the
# per-thread approval callback was never passed to prompt_dangerous_approval,
# so every gated foreground memory write was silently denied.
# ---------------------------------------------------------------------------

@pytest.fixture
def approval_callback_cleanup():
    yield
    from tools.terminal_tool import set_approval_callback
    set_approval_callback(None)


def test_memory_inline_approve_writes(lliam_home, approval_callback_cleanup):
    from tools.memory_tool import memory_tool, MemoryStore
    from tools.terminal_tool import set_approval_callback
    from tools import write_approval as wa
    _set_approval("memory", True)

    calls = []
    def approve_cb(command, description, **kw):
        calls.append((command, description))
        return "once"
    set_approval_callback(approve_cb)

    store = MemoryStore(); store.load_from_disk()
    r = json.loads(memory_tool("add", "memory", "approved fact", store=store))
    assert r["success"] is True
    assert r.get("staged") is None  # real write, not staged
    assert store.memory_entries == ["approved fact"]
    assert wa.pending_count("memory") == 0
    # The registered callback must actually be invoked (not the input() path).
    assert len(calls) == 1
    assert "approved fact" in calls[0][0]


def test_memory_inline_deny_blocks(lliam_home, approval_callback_cleanup):
    from tools.memory_tool import memory_tool, MemoryStore
    from tools.terminal_tool import set_approval_callback
    from tools import write_approval as wa
    _set_approval("memory", True)
    set_approval_callback(lambda command, description, **kw: "deny")

    store = MemoryStore(); store.load_from_disk()
    r = json.loads(memory_tool("add", "memory", "denied fact", store=store))
    assert r["success"] is False
    assert "denied" in r["error"].lower()
    assert store.memory_entries == []
    assert wa.pending_count("memory") == 0  # denied, not staged


def test_memory_inline_callback_error_stages(lliam_home, approval_callback_cleanup):
    # If the prompt machinery fails, fall back to staging — never drop silently.
    from tools.memory_tool import memory_tool, MemoryStore
    from tools.terminal_tool import set_approval_callback
    from tools import write_approval as wa
    _set_approval("memory", True)
    def broken_cb(command, description, **kw):
        raise RuntimeError("boom")
    set_approval_callback(broken_cb)

    store = MemoryStore(); store.load_from_disk()
    r = json.loads(memory_tool("add", "memory", "fallback fact", store=store))
    assert r.get("staged") is True
    assert wa.pending_count("memory") == 1


def test_gateway_context_stages_not_prompts(lliam_home, monkeypatch):
    # A gateway session has no per-thread CLI callback; the dangerous-command
    # /approve round-trip lives in the pending-queue machinery which the gate
    # does not use. The gate must stage, never attempt an inline prompt
    # (which would hit the input() fallback and silently deny).
    from tools.memory_tool import memory_tool, MemoryStore
    from tools import write_approval as wa
    _set_approval("memory", True)
    monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")

    store = MemoryStore(); store.load_from_disk()
    r = json.loads(memory_tool("add", "memory", "gateway fact", store=store))
    assert r.get("staged") is True
    assert store.memory_entries == []
    assert wa.pending_count("memory") == 1


def test_skills_never_prompt_inline_even_with_callback(lliam_home, approval_callback_cleanup):
    # Skills always stage — even when an interactive callback is registered.
    from tools.skill_manager_tool import skill_manage
    from tools.terminal_tool import set_approval_callback
    from tools import write_approval as wa
    _set_approval("skills", True)

    calls = []
    set_approval_callback(lambda c, d, **kw: calls.append(1) or "once")

    r = json.loads(skill_manage(
        action="create", name="test-inline-skill",
        content="---\nname: test-inline-skill\ndescription: x\n---\nbody\n"))
    assert r.get("staged") is True
    assert calls == []  # never prompted
    assert wa.pending_count("skills") == 1


def test_memory_invalid_params_rejected_before_staging(lliam_home):
    # Param validation must run BEFORE the gate so a broken write is rejected
    # immediately instead of staged and failing at approve time.
    from tools.memory_tool import memory_tool, MemoryStore
    from tools import write_approval as wa
    _set_approval("memory", True)
    store = MemoryStore(); store.load_from_disk()
    r = json.loads(memory_tool("add", "memory", None, store=store))
    assert r["success"] is False
    assert wa.pending_count("memory") == 0


@pytest.mark.parametrize("subsystem", ["memory", "skills"])
def test_stage_write_raises_on_disk_failure(lliam_home, subsystem):
    from pathlib import Path
    from tools import write_approval as wa
    (Path(lliam_home) / "pending").write_text("blocked", encoding="utf-8")
    with pytest.raises(OSError):
        wa.stage_write(subsystem, {"action": "add"}, summary="test", origin="foreground")
    assert wa.list_pending(subsystem) == []


@pytest.mark.parametrize("subsystem", ["memory", "skills"])
@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_decisions_are_durable_before_mutation(lliam_home, monkeypatch, subsystem, decision):
    import hashlib
    import getpass
    from datetime import datetime
    from pathlib import Path
    from tools import write_approval as wa, skill_manager_tool as manager
    from tools.memory_tool import MemoryStore
    from lliam_cli.write_approval_commands import handle_pending_subcommand

    monkeypatch.setattr(manager, "SKILLS_DIR", Path(lliam_home) / "skills")
    payload = ({"action": "add", "target": "user", "content": "reviewed fact"}
               if subsystem == "memory" else
               {"action": "create", "name": "reviewed-skill", "content": _SKILL})
    rec = wa.stage_write(subsystem, payload, summary="review this", origin="background_review")
    log = Path(lliam_home) / "logs/write-approvals.jsonl"
    store = MemoryStore()
    store.load_from_disk()

    # Observe the actual filesystem boundary, including pending-record deletion.
    original_unlink = Path.unlink
    original_write = Path.write_text
    original_replace = os.replace
    observed = []

    def check_record():
        entries = [json.loads(line) for line in log.read_text().splitlines()]
        entry = entries[0]
        assert entry["result"] == "pending"
        assert entry["decision"] == decision
        assert entry["subsystem"] == subsystem
        assert entry["pending_id"] == rec["id"]
        assert entry["action"] == payload["action"]
        assert entry["name"] == payload.get("name", payload.get("target"))
        assert entry["origin"] == "background_review"
        assert entry["summary"] == "review this"
        assert entry["sha256"] == hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        assert entry["approver"] == getpass.getuser()
        assert datetime.fromisoformat(entry["ts"]).utcoffset().total_seconds() == 0
        observed.append(True)

    def unlink(path, *args, **kwargs):
        if path.name == f"{rec['id']}.json":
            check_record()
        return original_unlink(path, *args, **kwargs)

    def write(path, *args, **kwargs):
        if path.name == "SKILL.md":
            check_record()
        return original_write(path, *args, **kwargs)

    def replace(src, dst, *args, **kwargs):
        if Path(dst).name == "USER.md":
            check_record()
        return original_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", unlink)
    monkeypatch.setattr(Path, "write_text", write)
    monkeypatch.setattr(os, "replace", replace)
    handle_pending_subcommand(subsystem, [decision, rec["id"]], memory_store=store,
                              operator=wa.issue_operator_capability())
    assert observed
    assert wa.get_pending(subsystem, rec["id"]) is None
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    assert [entry["result"] for entry in entries] == ["pending", "applied" if decision == "approve" else "discarded"]
    if subsystem == "memory":
        assert store.user_entries == (["reviewed fact"] if decision == "approve" else [])
    else:
        assert (manager.SKILLS_DIR / "reviewed-skill/SKILL.md").exists() == (decision == "approve")


@pytest.mark.parametrize("subsystem", ["memory", "skills"])
@pytest.mark.parametrize("decision", ["approve", "reject"])
@pytest.mark.parametrize("target_all", [False, True])
def test_unwritable_decision_log_refuses_mutation(lliam_home, monkeypatch, subsystem, decision, target_all):
    from pathlib import Path
    from tools import write_approval as wa, skill_manager_tool as manager
    from tools.memory_tool import MemoryStore
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    monkeypatch.setattr(manager, "SKILLS_DIR", Path(lliam_home) / "skills")
    payload = ({"action": "add", "target": "user", "content": "keep pending"}
               if subsystem == "memory" else
               {"action": "create", "name": "keep-pending", "content": _SKILL})
    rec = wa.stage_write(subsystem, payload, summary="keep", origin="foreground")
    (Path(lliam_home) / "logs").write_text("blocked", encoding="utf-8")
    store = MemoryStore()
    store.load_from_disk()
    out = handle_pending_subcommand(subsystem, [decision, "all" if target_all else rec["id"]], memory_store=store)
    assert wa.get_pending(subsystem, rec["id"]) == rec
    assert store.user_entries == []
    assert not (manager.SKILLS_DIR / "keep-pending").exists()
    assert "Failed" in out


@pytest.mark.parametrize("decision", ["approve", "reject"])
@pytest.mark.parametrize("ledger_enabled", [False, True])
def test_decision_uses_bound_principal_and_emits_oversight(lliam_home, monkeypatch, decision, ledger_enabled):
    from pathlib import Path
    from agent import governance_audit_hooks as hooks
    from agent.governance_audit import GovernanceLedger, iter_records
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    from tools.memory_tool import MemoryStore

    ledger = GovernanceLedger(Path(lliam_home) / "audit.jsonl")
    monkeypatch.setattr(hooks, "_enabled_ledger", lambda: ledger if ledger_enabled else None)
    rec = wa.stage_write("memory", {"action": "add", "target": "user", "content": "a fact"},
                         summary="a fact", origin="foreground")
    hooks.set_operator_subject("authenticated-reviewer", auth="dashboard_auth:password")
    try:
        store = MemoryStore()
        store.load_from_disk()
        handle_pending_subcommand("memory", [decision, rec["id"]], memory_store=store)
    finally:
        hooks.set_operator_subject(None)
    entries = [json.loads(line) for line in (Path(lliam_home) / "logs/write-approvals.jsonl").read_text().splitlines()]
    assert all(entry["approver"] == "authenticated-reviewer" for entry in entries)
    if ledger_enabled:
        records = [record for record in iter_records(ledger.path) if record["event"] == "approval.decision"]
        assert len(records) == 1
        assert records[0]["decision"] == ("approve" if decision == "approve" else "deny")
        assert records[0]["approver"]["id"] == "authenticated-reviewer"
        assert records[0]["approver"]["authenticated"] is True
    else:
        assert not ledger.path.exists()


def test_failed_replay_keeps_proposal_and_records_outcome(lliam_home):
    from pathlib import Path
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    rec = wa.stage_write("memory", {"action": "add", "target": "user", "content": "a fact"},
                         summary="a fact", origin="foreground")
    out = handle_pending_subcommand("memory", ["approve", rec["id"]])
    assert "Failed" in out
    assert wa.get_pending("memory", rec["id"]) == rec
    entries = [json.loads(line) for line in (Path(lliam_home) / "logs/write-approvals.jsonl").read_text().splitlines()]
    assert [entry["result"] for entry in entries] == ["pending", "failed"]
    assert "memory store unavailable" in entries[-1]["error"]


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_sync_failure_refuses_decision(lliam_home, monkeypatch, decision):
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    rec = wa.stage_write("memory", {"action": "add", "target": "user", "content": "a fact"},
                         summary="a fact", origin="foreground")
    def fail_sync(fd):
        raise OSError("disk sync failed")
    monkeypatch.setattr(os, "fsync", fail_sync)
    out = handle_pending_subcommand("memory", [decision, rec["id"]])
    assert "Failed" in out
    assert wa.get_pending("memory", rec["id"]) == rec


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_torn_decision_log_refuses_later_retry(lliam_home, monkeypatch, decision):
    from pathlib import Path
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    from tools.memory_tool import MemoryStore
    rec = wa.stage_write("memory", {"action": "add", "target": "user", "content": "keep pending"},
                         summary="keep pending", origin="foreground")
    store = MemoryStore()
    store.load_from_disk()
    write = os.write
    with monkeypatch.context() as short_write:
        short_write.setattr(os, "write", lambda fd, data: write(fd, data[:len(data) // 2]))
        out = handle_pending_subcommand("memory", [decision, rec["id"]], memory_store=store)
        assert "Failed" in out
    log = Path(lliam_home) / "logs/write-approvals.jsonl"
    torn = log.read_bytes()
    assert torn and not torn.endswith(b"\n")
    out = handle_pending_subcommand("memory", [decision, rec["id"]], memory_store=store)
    assert "Failed" in out
    assert log.read_bytes() == torn
    assert wa.get_pending("memory", rec["id"]) == rec
    assert store.user_entries == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory fsync")
@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_directory_sync_failure_refuses_decision(lliam_home, monkeypatch, decision):
    import stat
    from lliam_cli.write_approval_commands import handle_pending_subcommand
    from tools import write_approval as wa
    from tools.memory_tool import MemoryStore
    rec = wa.stage_write("memory", {"action": "add", "target": "user", "content": "keep pending"},
                         summary="keep pending", origin="foreground")
    store = MemoryStore()
    store.load_from_disk()
    fsync = os.fsync
    def fail_directory_sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory sync failed")
        return fsync(fd)
    monkeypatch.setattr(os, "fsync", fail_directory_sync)
    out = handle_pending_subcommand("memory", [decision, rec["id"]], memory_store=store)
    assert "Failed" in out
    assert wa.get_pending("memory", rec["id"]) == rec
    assert store.user_entries == []
