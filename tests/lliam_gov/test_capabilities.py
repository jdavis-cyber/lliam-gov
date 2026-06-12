"""Capability-tagged tool dispatch — LG-4.2 / AI-219.

WHY: SP 800-171 3.1.2 limits system access to authorized transactions and
functions. These tests pin the conservative defaults: the governed baseline
excludes shell/network/selfmod, UNCLASSIFIED tools are denied (new surface
area fails closed until consciously classified), and a denial both blocks
the dispatch AND lands in the audit chain.
"""

import json

import pytest

from lliam_gov.security.capabilities import (
    CAPABILITIES_ENV,
    CAPABILITY_ENFORCE_ENV,
    GOVERNED_BASELINE,
    UNCLASSIFIED,
    CapabilityDenied,
    active_capabilities,
    capability_for_tool,
    check_dispatch,
)


@pytest.fixture
def enforced(monkeypatch, tmp_path):
    home = tmp_path / "lliam-home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv(CAPABILITY_ENFORCE_ENV, "1")
    monkeypatch.delenv(CAPABILITIES_ENV, raising=False)
    return home


# ── classification ──────────────────────────────────────────────────────────


def test_governed_baseline_is_conservative():
    """The named default must not quietly grow teeth."""
    assert GOVERNED_BASELINE == {"fs_read", "fs_write", "messaging", "memory_write"}
    for risky in ("shell_exec", "network", "selfmod", "system_admin", "media_gen"):
        assert risky not in GOVERNED_BASELINE


def test_toolset_classification():
    assert capability_for_tool("execute_command", "terminal") == "shell_exec"
    assert capability_for_tool("browser_navigate", "browser") == "network"
    assert capability_for_tool("create_skill", "skills") == "selfmod"
    assert capability_for_tool("ha_call", "homeassistant") == "system_admin"


def test_per_tool_override_beats_toolset():
    assert capability_for_tool("read_file", "file") == "fs_read"
    assert capability_for_tool("write_file", "file") == "fs_write"


def test_unknown_toolset_is_unclassified():
    assert capability_for_tool("mystery_tool", "brand_new_toolset") == UNCLASSIFIED
    assert capability_for_tool("mystery_tool", None) == UNCLASSIFIED


def test_unclassified_is_not_grantable(monkeypatch):
    monkeypatch.setenv(CAPABILITIES_ENV, f"fs_read,{UNCLASSIFIED}")
    assert UNCLASSIFIED not in active_capabilities()


# ── enforcement semantics ───────────────────────────────────────────────────


def test_no_enforcement_allows_everything(monkeypatch):
    monkeypatch.delenv(CAPABILITY_ENFORCE_ENV, raising=False)
    check_dispatch("execute_command", "terminal")


def test_baseline_allows_workspace_io(enforced):
    check_dispatch("read_file", "file")
    check_dispatch("write_file", "file")
    check_dispatch("send_message", "messaging")


def test_baseline_denies_shell_and_network(enforced):
    with pytest.raises(CapabilityDenied, match="shell_exec"):
        check_dispatch("execute_command", "terminal")
    with pytest.raises(CapabilityDenied, match="network"):
        check_dispatch("browser_navigate", "browser")


def test_explicit_grant_admits_capability(enforced, monkeypatch):
    monkeypatch.setenv(CAPABILITIES_ENV, "fs_read,shell_exec")
    check_dispatch("execute_command", "terminal")
    with pytest.raises(CapabilityDenied):
        check_dispatch("write_file", "file")  # not granted in explicit set


def test_unclassified_tool_denied_under_enforcement(enforced):
    with pytest.raises(CapabilityDenied, match="no capability classification"):
        check_dispatch("mystery_tool", "brand_new_toolset")


# ── registry + dispatch integration ────────────────────────────────────────


def test_tool_entry_carries_capability_tag():
    from tools.registry import ToolEntry

    entry = ToolEntry(
        name="execute_command", toolset="terminal", schema={}, handler=None,
        check_fn=None, requires_env=None, is_async=False,
        description="", emoji="",
    )
    assert entry.capability == "shell_exec"


def test_dispatch_denial_is_audited_and_blocked(enforced):
    from model_tools import handle_function_call

    result = json.loads(
        handle_function_call(
            "execute_command",
            {"command": "id"},
            session_id="cap-test",
            tool_call_id="tc-1",
        )
    )
    assert "capability" in result["error"]

    audit_files = list((enforced / "audit").glob("*.jsonl"))
    assert audit_files, "denial must produce an audit record"
    records = [
        json.loads(line)
        for f in audit_files
        for line in f.read_text().splitlines()
    ]
    blocked = [
        r
        for r in records
        if r["event_type"] == "tool_call_blocked"
        and r["tool_name"] == "execute_command"
    ]
    assert blocked and blocked[-1]["blocked"] is True
    assert blocked[-1]["block_reason"].startswith("capability_denied")
