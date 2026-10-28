"""DEF-021: agent skill proposals stay outside the loadable library."""

import json
import logging

import pytest

from agent.background_review import summarize_background_review_actions
from lliam_cli.write_approval_commands import handle_pending_subcommand
from tools import skill_manager_tool as manager
from tools import skills_tool, write_approval
from tools.skill_provenance import reset_current_write_origin, set_current_write_origin


CONTENT = "---\nname: local-file-tasks\ndescription: Local file tasks\n---\n# Tasks\nOriginal instructions.\n"


@pytest.fixture
def library(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skills = tmp_path / "skills"
    skills.mkdir()
    monkeypatch.setattr(manager, "SKILLS_DIR", skills)
    monkeypatch.setattr(skills_tool, "SKILLS_DIR", skills)
    return skills


@pytest.mark.parametrize("origin", ["foreground", "assistant_tool", "background_review"])
@pytest.mark.parametrize("approval_setting", [None, False, True])
def test_create_requires_operator_approval(library, origin, approval_setting, caplog):
    if approval_setting is not None:
        (library.parent / "config.yaml").write_text(
            f"skills:\n  write_approval: {str(approval_setting).lower()}\n", encoding="utf-8"
        )
    caplog.set_level(logging.INFO, logger=manager.__name__)
    token = set_current_write_origin(origin)
    try:
        result = json.loads(manager.skill_manage("create", "local-file-tasks", content=CONTENT))
    finally:
        reset_current_write_origin(token)

    assert result["staged"] is True
    assert not (library / "local-file-tasks").exists()
    assert json.loads(skills_tool.skill_view("local-file-tasks"))["success"] is False
    assert json.loads(skills_tool.skills_list())["skills"] == []
    record = write_approval.get_pending("skills", result["pending_id"])
    assert record is not None
    assert record["origin"] == origin
    assert record["payload"]["content"] == CONTENT
    assert "Skill write approved" not in caplog.text

    reply = handle_pending_subcommand("skills", ["approve", result["pending_id"]])
    assert reply == "Approved 1 skills write(s)."
    assert (library / "local-file-tasks" / "SKILL.md").read_text(encoding="utf-8") == CONTENT
    assert json.loads(skills_tool.skill_view("local-file-tasks"))["success"] is True
    assert write_approval.pending_count("skills") == 0
    assert "Skill write approved" in caplog.text
    assert result["pending_id"] in caplog.text
    from tools.skill_usage import get_record
    assert (get_record("local-file-tasks").get("created_by") == "agent") == (origin == "background_review")


@pytest.mark.parametrize("action, kwargs", [
    ("edit", {"content": CONTENT.replace("Original", "Changed")}),
    ("patch", {"old_string": "Original", "new_string": "Changed"}),
    ("write_file", {"file_path": "references/notes.md", "file_content": "Changed"}),
    ("remove_file", {"file_path": "references/notes.md"}),
    ("delete", {}),
])
def test_pending_changes_leave_operator_authored_skill_untouched(library, action, kwargs):
    skill = library / "local-file-tasks"
    (skill / "references").mkdir(parents=True)
    (skill / "SKILL.md").write_text(CONTENT, encoding="utf-8")
    (skill / "references" / "notes.md").write_text("Original", encoding="utf-8")
    assert json.loads(skills_tool.skill_view("local-file-tasks"))["success"] is True

    result = json.loads(manager.skill_manage(action, "local-file-tasks", **kwargs))
    assert result["staged"] is True
    assert (skill / "SKILL.md").read_text(encoding="utf-8") == CONTENT
    assert (skill / "references" / "notes.md").read_text(encoding="utf-8") == "Original"
    reply = handle_pending_subcommand("skills", ["reject", result["pending_id"]])
    assert reply is not None
    assert "Rejected" in reply
    assert write_approval.pending_count("skills") == 0
    assert (skill / "SKILL.md").read_text(encoding="utf-8") == CONTENT

    # The same mutation becomes effective only through operator approval.
    proposal = json.loads(manager.skill_manage(action, "local-file-tasks", **kwargs))
    assert handle_pending_subcommand("skills", ["approve", proposal["pending_id"]]) == "Approved 1 skills write(s)."
    if action == "delete":
        assert not skill.exists()
    elif action == "remove_file":
        assert not (skill / "references" / "notes.md").exists()
    elif action == "write_file":
        assert (skill / "references" / "notes.md").read_text(encoding="utf-8") == "Changed"
    else:
        assert (skill / "SKILL.md").read_text(encoding="utf-8") == CONTENT.replace("Original", "Changed")
    assert write_approval.pending_count("skills") == 0


def test_failed_pending_store_does_not_save_skill(library, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("disk unavailable")

    monkeypatch.setattr(write_approval, "stage_write", fail)
    result = json.loads(manager.skill_manage("create", "local-file-tasks", content=CONTENT))
    assert result["success"] is False
    assert not (library / "local-file-tasks").exists()


def test_best_effort_staging_failure_is_reported(library):
    # The backend catches disk errors; its returned record is not proof of save.
    (library.parent / "pending").write_text("not a directory", encoding="utf-8")
    result = json.loads(manager.skill_manage("create", "local-file-tasks", content=CONTENT))
    assert result["success"] is False
    assert not (library / "local-file-tasks").exists()


def test_approval_replay_requires_pending_record(library, caplog):
    caplog.set_level(logging.INFO, logger=manager.__name__)
    result = json.loads(manager.apply_skill_pending({
        "action": "create", "name": "local-file-tasks", "content": CONTENT,
    }))
    assert result["success"] is False
    assert not (library / "local-file-tasks").exists()
    assert "Skill write approved" not in caplog.text


def test_duplicate_proposals_log_the_selected_approval(library, caplog):
    first = json.loads(manager.skill_manage("create", "local-file-tasks", content=CONTENT))
    second = json.loads(manager.skill_manage("create", "local-file-tasks", content=CONTENT))
    caplog.set_level(logging.INFO, logger=manager.__name__)
    reply = handle_pending_subcommand("skills", ["approve", second["pending_id"]])
    assert reply == "Approved 1 skills write(s)."
    assert f"Skill write approved: id={second['pending_id']}" in caplog.text
    assert f"Skill write approved: id={first['pending_id']}" not in caplog.text
    assert write_approval.get_pending("skills", first["pending_id"]) is not None


def test_staging_does_not_clear_prompt_cache(library, monkeypatch):
    from agent import prompt_builder
    from unittest.mock import Mock

    clear_cache = Mock()
    monkeypatch.setattr(prompt_builder, "clear_skills_system_prompt_cache", clear_cache)
    result = json.loads(manager.skill_manage("create", "local-file-tasks", content=CONTENT))
    assert result["staged"] is True
    clear_cache.assert_not_called()
    handle_pending_subcommand("skills", ["approve", result["pending_id"]])
    clear_cache.assert_called_once_with(clear_snapshot=True)


def test_real_background_review_stages_before_operator_approval(library, monkeypatch, caplog):
    """Run the review fork and tool loop with only the model response stubbed."""
    from types import SimpleNamespace
    from unittest.mock import Mock

    from agent.background_review import spawn_background_review_thread
    from run_agent import AIAgent
    from tools.skill_provenance import get_current_write_origin

    def response(content, tool_calls=None):
        return SimpleNamespace(
            choices=[SimpleNamespace(
                message=SimpleNamespace(content=content, tool_calls=tool_calls,
                                        reasoning=None, reasoning_content=None),
                finish_reason="tool_calls" if tool_calls else "stop",
            )], model="test-model", usage=None,
        )

    tool_call = SimpleNamespace(id="proposal", type="function", function=SimpleNamespace(
        name="skill_manage", arguments=json.dumps({
            "action": "create", "name": "local-file-tasks", "content": CONTENT,
        }),
    ))
    api = Mock(side_effect=[response(None, [tool_call]), response("Proposal submitted.")])
    monkeypatch.setattr(AIAgent, "_interruptible_api_call", api)
    monkeypatch.setattr(AIAgent, "_interruptible_streaming_api_call", api)
    (library.parent / "config.yaml").write_text("model:\n  context_length: 128000\n", encoding="utf-8")
    caplog.set_level(logging.INFO, logger=manager.__name__)
    parent = AIAgent(model="test-model", provider="openai", api_key="test-key",
                     base_url="http://127.0.0.1:1/v1", enabled_toolsets=["skills"],
                     quiet_mode=True, skip_context_files=True, skip_memory=True)
    monkeypatch.setattr(parent, "_cached_system_prompt", "Review reusable procedures.")
    notifications = []
    monkeypatch.setattr(parent, "background_review_callback", notifications.append)
    token = set_current_write_origin(get_current_write_origin())
    try:
        target, _ = spawn_background_review_thread(parent, [], review_skills=True)
        target()
    finally:
        reset_current_write_origin(token)
        parent.close()

    assert api.call_count == 2
    records = write_approval.list_pending("skills")
    assert len(records) == 1
    assert records[0]["origin"] == "background_review"
    assert json.loads(skills_tool.skill_view("local-file-tasks"))["success"] is False
    assert "Skill write approved" not in caplog.text
    assert notifications and "pending approval" in str(notifications)
    assert handle_pending_subcommand("skills", ["approve", records[0]["id"]]) == "Approved 1 skills write(s)."
    assert json.loads(skills_tool.skill_view("local-file-tasks"))["success"] is True
    assert "Skill write approved" in caplog.text


@pytest.mark.parametrize("mode", ["on", "verbose"])
def test_background_notification_describes_pending_change(library, mode):
    result = manager.skill_manage("create", "local-file-tasks", content=CONTENT)
    messages = [
        {"role": "assistant", "tool_calls": [{"id": "proposal", "function": {
            "name": "skill_manage", "arguments": json.dumps({"action": "create", "name": "local-file-tasks"}),
        }}]},
        {"role": "tool", "tool_call_id": "proposal", "content": result},
    ]
    actions = summarize_background_review_actions(messages, [], notification_mode=mode)
    assert len(actions) == 1
    assert "pending approval" in actions[0].lower()
    assert "local-file-tasks" in actions[0]
    assert "/skills" in actions[0]
    assert "created" not in actions[0]
