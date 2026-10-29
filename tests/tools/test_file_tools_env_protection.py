"""Environment-file denials through real file tools and local file operations."""

import json
import shutil
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.tools.test_file_read_guards import _make_safe_tempdir
from tools import file_tools, terminal_tool
from tools.environments.local import LocalEnvironment
from tools.file_operations import ShellFileOperations


@pytest.fixture
def workspace(monkeypatch):
    # macOS's default temp directory is under the protected /private/var tree.
    root = Path(_make_safe_tempdir("env-protection-")).resolve()
    try:
        monkeypatch.setenv("HERMES_HOME", str(root / "home"))
        monkeypatch.setenv("LLIAM_HOME", str(root / "home"))
        monkeypatch.setenv("TERMINAL_ENV", "local")
        monkeypatch.setenv("TERMINAL_CWD", str(root))
        monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", "")
        monkeypatch.setenv("LLIAM_WRITE_SAFE_ROOT", "")
        # A cwd-only override shares the "default" environment, so isolate the
        # environment and file-ops caches; otherwise the deleted workspace
        # leaks into later tests as the default task's cwd.
        monkeypatch.setattr(terminal_tool, "_active_environments", {})
        monkeypatch.setattr(file_tools, "_file_ops_cache", {})
        monkeypatch.setattr(file_tools, "_last_known_cwd", {})
        terminal_tool.register_task_env_overrides("env-protection", {"cwd": str(root)})
        try:
            yield root
        finally:
            terminal_tool.clear_task_env_overrides("env-protection")
    finally:
        shutil.rmtree(root)


@pytest.fixture(autouse=True)
def no_prompt(monkeypatch):
    from tools import approval

    prompt = Mock(side_effect=AssertionError("Environment files must not prompt"))
    monkeypatch.setattr(approval, "prompt_dangerous_approval", prompt)
    monkeypatch.setattr("builtins.input", prompt)
    yield
    prompt.assert_not_called()


def mutate(operation, path, *, ops=None, cross_profile=False):
    if operation in {"create", "overwrite"}:
        if ops is not None:
            return ops.write_file(path, "TEST_VALUE=2\n").to_dict()
        return json.loads(file_tools.write_file_tool(
            path, "TEST_VALUE=2\n", task_id="env-protection", cross_profile=cross_profile,
        ))
    if operation == "replace":
        if ops is not None:
            return ops.patch_replace(path, "TEST_VALUE=1", "TEST_VALUE=2").to_dict()
        return json.loads(file_tools.patch_tool(
            path=path, old_string="TEST_VALUE=1", new_string="TEST_VALUE=2",
            task_id="env-protection", cross_profile=cross_profile,
        ))
    if operation == "add":
        body = f"*** Add File: {path}\n+TEST_VALUE=2\n"
    elif operation == "update":
        body = f"*** Update File: {path}\n@@\n-TEST_VALUE=1\n+TEST_VALUE=2\n"
    else:
        body = f"*** Move File: source.txt -> {path}\n"
    patch = f"*** Begin Patch\n{body}*** End Patch"
    if ops is not None:
        return ops.patch_v4a(patch).to_dict()
    return json.loads(file_tools.patch_tool(
        mode="patch", patch=patch, task_id="env-protection", cross_profile=cross_profile,
    ))


@pytest.mark.parametrize("basename, allowed", [
    (".env", False),
    (".env.local", False),
    (".env.production.local", False),
    (".env.development.local", False),
    (".env.custom", False),
    (".env.secret", False),
    (".ENV.PRODUCTION.LOCAL", False),
    (".env.custom ", False),
    (".envrc", False),
    (".env.example", True),
    (".env.sample", True),
    (".env.EXAMPLE", True),
    ("ordinary.txt", True),
])
@pytest.mark.parametrize("operation", ["read", "write"])
def test_env_read_write_policy(workspace, basename, allowed, operation):
    target = workspace / basename
    target.write_text("TEST_VALUE=1\n", encoding="utf-8")

    if operation == "read":
        result = json.loads(file_tools.read_file_tool(basename, task_id="env-protection"))
    else:
        result = json.loads(file_tools.write_file_tool(
            basename, "TEST_VALUE=2\n", task_id="env-protection",
        ))

    if allowed:
        assert not result.get("error"), result
        if operation == "read":
            assert "TEST_VALUE=1" in result["content"]
        else:
            assert target.read_text(encoding="utf-8") == "TEST_VALUE=2\n"
    else:
        assert "denied" in result.get("error", "").lower(), result
        assert "TEST_VALUE=1" not in json.dumps(result)
        assert target.read_text(encoding="utf-8") == "TEST_VALUE=1\n"


@pytest.mark.parametrize("basename", [
    ".env", ".env.local", ".env.development", ".env.production",
    ".env.test", ".env.staging", ".envrc", ".ENV.LOCAL",
    ".env.custom", ".env.example", ".env.sample",
])
@pytest.mark.parametrize("operation", ["create", "overwrite", "replace", "add", "update", "move"])
@pytest.mark.parametrize("layer", ["tool", "operations"])
def test_env_mutations_follow_read_policy(workspace, basename, operation, layer):
    target = workspace / "scratch" / basename
    existing = operation in {"overwrite", "replace", "update"}
    if existing:
        target.parent.mkdir()
        target.write_text("TEST_VALUE=1\n", encoding="utf-8")
    elif operation == "move" and basename in {".env.example", ".env.sample"}:
        target.parent.mkdir()
    source = workspace / "source.txt"
    source.write_text("TEST_VALUE=1\n", encoding="utf-8")
    ops = ShellFileOperations(LocalEnvironment(cwd=str(workspace))) if layer == "operations" else None

    result = mutate(operation, f"scratch/{basename}", ops=ops, cross_profile=True)

    if basename in {".env.example", ".env.sample"}:
        assert not result.get("error"), result
        expected = "TEST_VALUE=1" if operation == "move" else "TEST_VALUE=2"
        assert target.read_text(encoding="utf-8").strip() == expected
        read = json.loads(file_tools.read_file_tool(str(target), task_id="env-protection"))
        assert not read.get("error"), read
        assert expected in read["content"]
        return

    assert "denied" in result.get("error", "").lower(), result
    assert not result.get("success")
    assert source.read_text(encoding="utf-8") == "TEST_VALUE=1\n"
    if existing:
        assert target.read_text(encoding="utf-8") == "TEST_VALUE=1\n"
    else:
        assert not target.exists()
        assert not target.parent.exists()


@pytest.mark.parametrize("operation", ["create", "overwrite", "replace", "add", "update", "move"])
def test_ordinary_files_still_writable(workspace, operation):
    target = workspace / "ordinary.txt"
    if operation in {"overwrite", "replace", "update"}:
        target.write_text("TEST_VALUE=1\n", encoding="utf-8")
    (workspace / "source.txt").write_text("TEST_VALUE=2\n", encoding="utf-8")
    result = mutate(operation, str(target))
    assert not result.get("error"), result
    assert target.read_text(encoding="utf-8").strip() == "TEST_VALUE=2"


@pytest.mark.parametrize("basename", [
    ".env", ".env.local", ".env.development", ".env.production",
    ".env.test", ".env.staging", ".envrc", ".ENV.LOCAL",
])
def test_reads_remain_refused(workspace, basename):
    target = workspace / basename
    target.write_text("TEST_VALUE=1\n", encoding="utf-8")
    result = json.loads(file_tools.read_file_tool(basename, task_id="env-protection"))
    assert "Access denied" in result.get("error", ""), result
    assert "TEST_VALUE=1" not in json.dumps(result)


@pytest.mark.parametrize("path", [
    ".env ", ".env.", ".env.local. ", ".env::$DATA", ".env:stream",
    r"scratch\.env", "．ｅｎｖ", "．ＥＮＶ．ＬＯＣＡＬ",
])
@pytest.mark.parametrize("operation", ["read", "write"])
def test_env_name_variants_refused(workspace, path, operation):
    target = workspace / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("TEST_VALUE=1\n", encoding="utf-8")

    if operation == "read":
        result = json.loads(file_tools.read_file_tool(path, task_id="env-protection"))
    else:
        result = mutate("overwrite", path)

    assert "denied" in result.get("error", "").lower(), result
    assert "TEST_VALUE=1" not in json.dumps(result)
    assert target.read_text(encoding="utf-8") == "TEST_VALUE=1\n"


@pytest.mark.parametrize("basename", [".ENV.LOCAL", ".env "])
@pytest.mark.parametrize("suffix", [".txt", ".ipynb"])
def test_env_named_symlink_read_refused_before_extraction(workspace, basename, suffix):
    target = workspace / f"ordinary{suffix}"
    content = "TEST_VALUE=1"
    if suffix == ".ipynb":
        content = json.dumps({"cells": [{"cell_type": "markdown", "source": content}]})
    target.write_text(content, encoding="utf-8")
    (workspace / basename).symlink_to(target)

    result = json.loads(file_tools.read_file_tool(basename, task_id="env-protection"))

    assert "Access denied" in result.get("error", ""), result
    assert "TEST_VALUE=1" not in json.dumps(result)


@pytest.mark.parametrize("basename", [".env", ".env.local", ".env.custom", ".envrc"])
def test_safe_root_does_not_override_env_denial(workspace, monkeypatch, basename):
    monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", str(workspace))
    monkeypatch.setenv("LLIAM_WRITE_SAFE_ROOT", str(workspace))
    result = mutate("create", basename)
    assert "denied" in result.get("error", "").lower(), result
    assert not (workspace / basename).exists()
    assert not mutate("create", "ordinary.txt").get("error")


@pytest.mark.skipif(sys.platform == "win32", reason="Symlinks require Windows privileges")
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("layer", ["tool", "operations"])
def test_symlink_names_and_targets_refused(workspace, reverse, existing, layer):
    target = workspace / ("ordinary.txt" if reverse else ".env.local")
    alias = workspace / (".env.local" if reverse else "alias.txt")
    if existing:
        target.write_text("TEST_VALUE=1\n", encoding="utf-8")
    alias.symlink_to(target)
    ops = ShellFileOperations(LocalEnvironment(cwd=str(workspace))) if layer == "operations" else None
    result = mutate("overwrite", alias.name, ops=ops)
    assert "denied" in result.get("error", "").lower(), result
    assert alias.is_symlink()
    if existing:
        assert target.read_text(encoding="utf-8") == "TEST_VALUE=1\n"
    else:
        assert not target.exists()


@pytest.mark.parametrize("operation", ["overwrite", "replace", "add", "update", "move"])
def test_relative_symlink_guard_follows_live_cwd(workspace, operation):
    live = workspace / "live"
    live.mkdir()
    target = live / ".env.local"
    target.write_text("TEST_VALUE=1\n", encoding="utf-8")
    (live / "alias.txt").symlink_to(target)
    (live / "source.txt").write_text("TEST_VALUE=1\n", encoding="utf-8")
    env = LocalEnvironment(cwd=str(workspace))
    ops = ShellFileOperations(env)
    env.cwd = str(live)

    result = mutate(operation, "alias.txt", ops=ops)

    assert "denied" in result.get("error", "").lower(), result
    assert target.read_text(encoding="utf-8") == "TEST_VALUE=1\n"
    assert (live / "source.txt").read_text(encoding="utf-8") == "TEST_VALUE=1\n"
    assert (live / "alias.txt").is_symlink()
    assert not (workspace / "alias.txt").exists()


@pytest.mark.parametrize("operation", ["delete", "move"])
@pytest.mark.parametrize("layer", ["tool", "operations", "direct"])
def test_env_delete_and_move_source_refused(workspace, operation, layer):
    target = workspace / ".env"
    target.write_text("TEST_VALUE=1\n", encoding="utf-8")
    ops = ShellFileOperations(LocalEnvironment(cwd=str(workspace)))
    body = "*** Delete File: .env\n" if operation == "delete" else "*** Move File: .env -> ordinary.txt\n"
    patch = f"*** Begin Patch\n{body}*** End Patch"

    if layer == "tool":
        result = json.loads(file_tools.patch_tool(
            mode="patch", patch=patch, task_id="env-protection", cross_profile=True,
        ))
    elif layer == "operations":
        result = ops.patch_v4a(patch).to_dict()
    elif operation == "delete":
        result = ops.delete_file(".env").to_dict()
    else:
        result = ops.move_file(".env", "ordinary.txt").to_dict()

    assert "denied" in result.get("error", "").lower(), result
    assert target.read_text(encoding="utf-8") == "TEST_VALUE=1\n"
    assert not (workspace / "ordinary.txt").exists()


@pytest.mark.parametrize("layer", ["tool", "operations"])
def test_patch_preflight_prevents_partial_writes(workspace, layer):
    patch = (
        "*** Begin Patch\n*** Add File: ordinary.txt\n+ordinary\n"
        "***Add File: .env.local\n+TEST_VALUE=2\n*** End Patch"
    )
    if layer == "operations":
        ops = ShellFileOperations(LocalEnvironment(cwd=str(workspace)))
        result = ops.patch_v4a(patch).to_dict()
    else:
        result = json.loads(file_tools.patch_tool(
            mode="patch", patch=patch, task_id="env-protection",
        ))
    assert "denied" in result.get("error", "").lower(), result
    assert not (workspace / "ordinary.txt").exists()
    assert not (workspace / ".env.local").exists()
