"""Operators can review skill proposals with the retired setting off.

Ported from tests/gateway/test_skills_write_approval.py (AI-1174 / AI-1183)
when the messaging gateway was removed (JER-198): the same review flow now
runs through the surviving operator surface, the CLI ``/skills`` handler
that the terminal chat and the desktop slash worker both use.
"""

import json

from lliam_cli.cli_commands_mixin import CLICommandsMixin
from lliam_cli.commands import resolve_command
from tools import write_approval as wa


def test_skills_review_available_with_setting_off(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("LLIAM_HOME", str(tmp_path))
    config = tmp_path / "config.yaml"
    config.write_text("skills:\n  write_approval: false\n", encoding="utf-8")
    original_config = config.read_bytes()
    handler = CLICommandsMixin.__new__(CLICommandsMixin)

    def command(args):
        handler._handle_skills_command(f"/skills {args}".rstrip())
        return capsys.readouterr().out

    assert resolve_command("skills") is not None
    assert "always need approval" in command("approval")
    assert "No pending" in command("pending")
    from tools import skill_manager_tool as manager
    monkeypatch.setattr(manager, "SKILLS_DIR", tmp_path / "skills")
    content = "---\nname: operator-skill\ndescription: Operator test\n---\n# Steps\nDo the task.\n"
    proposal = json.loads(manager.skill_manage("create", "operator-skill", content=content))
    pid = proposal["pending_id"]
    assert pid in command("pending")
    assert content in command(f"diff {pid}")
    command(f"approve {pid}")
    assert (tmp_path / "skills/operator-skill/SKILL.md").read_text() == content
    rec = wa.stage_write("skills", {"action": "delete", "name": "operator-skill"},
                         summary="delete skill", origin="foreground")
    command(f"reject {rec['id']}")
    assert wa.list_pending("skills") == []
    assert (tmp_path / "skills/operator-skill/SKILL.md").exists()
    for toggle in ("approval off", "mode on"):
        assert "always need approval" in command(toggle)
    assert config.read_bytes() == original_config
