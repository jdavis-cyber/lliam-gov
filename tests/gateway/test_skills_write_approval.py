"""Gateway operators can review skill proposals with the retired setting off."""

import json
from types import SimpleNamespace

import pytest

from gateway.slash_commands import GatewaySlashCommandsMixin
from lliam_cli.commands import gateway_help_lines, telegram_bot_commands
from tools import write_approval as wa


@pytest.mark.asyncio
async def test_skills_review_available_with_setting_off(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = tmp_path / "config.yaml"
    config.write_text("skills:\n  write_approval: false\n", encoding="utf-8")
    original_config = config.read_bytes()
    runner = SimpleNamespace(_session_key_for_source=lambda source: "test")

    async def command(args):
        event = SimpleNamespace(get_command_args=lambda: args, source=None)
        return await GatewaySlashCommandsMixin._handle_skills_command(runner, event)

    assert any("/skills" in line for line in gateway_help_lines())
    assert any(name == "skills" for name, _ in telegram_bot_commands())
    assert "always" in (await command("")).lower()
    assert "No pending" in await command("pending")
    from tools import skill_manager_tool as manager
    monkeypatch.setattr(manager, "SKILLS_DIR", tmp_path / "skills")
    content = "---\nname: gateway-skill\ndescription: Gateway test\n---\n# Steps\nDo the task.\n"
    proposal = json.loads(manager.skill_manage("create", "gateway-skill", content=content))
    pid = proposal["pending_id"]
    assert pid in await command("pending")
    assert content in await command(f"diff {pid}")
    await command(f"approve {pid}")
    assert (tmp_path / "skills/gateway-skill/SKILL.md").read_text() == content
    rec = wa.stage_write("skills", {"action": "delete", "name": "gateway-skill"},
                         summary="delete skill", origin="foreground")
    await command(f"reject {rec['id']}")
    assert wa.list_pending("skills") == []
    assert (tmp_path / "skills/gateway-skill/SKILL.md").exists()
    for unsupported in ("install x", "search x", "approval off", "mode on"):
        assert "Unknown" in await command(unsupported)
    assert config.read_bytes() == original_config


def test_skills_slack_route_preserves_existing_native_commands(tmp_path, monkeypatch):
    from lliam_cli.commands import slack_native_slashes, slack_subcommand_map
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text("skills:\n  write_approval: false\n", encoding="utf-8")
    assert slack_subcommand_map()["skills"] == "/skills"
    assert {"version", "approve", "curator"} <= {name for name, _, _ in slack_native_slashes()}
