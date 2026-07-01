"""Regression tests for the Lliam-GOV skill deny-tag backstop (tools/tool_policy).

Covers the LG-SC-01/02 requirement that the tag-scan chokepoint mirrors the
loader's nested-aware skill discovery. A re-vendored offensive skill placed in a
supported *nested* category (``category/name/SKILL.md``) is discoverable by
Hermes skill registration, so the deny-tag scan must reach it too — a one-level
``*/SKILL.md`` glob would silently miss it under strict posture.
"""

from pathlib import Path

import pytest

import tools.tool_policy as tool_policy


def _write_skill(root: Path, rel: str, *, tags: str) -> None:
    md = root / rel / "SKILL.md"
    md.parent.mkdir(parents=True, exist_ok=True)
    md.write_text(
        f"---\nname: {Path(rel).name}\ntags: [{tags}]\ndescription: test skill\n---\n# body\n",
        encoding="utf-8",
    )


@pytest.fixture(autouse=True)
def _reset_tag_cache():
    tool_policy._TAG_SCAN_CACHE.clear()
    yield
    tool_policy._TAG_SCAN_CACHE.clear()


def test_nested_offensive_skill_is_deny_tagged(tmp_path, monkeypatch):
    skills = tmp_path / "skills"
    # Top-level and nested (categorized) offensive skills, plus a benign one.
    _write_skill(skills, "godmodish", tags="jailbreak")
    _write_skill(skills, "offense/revendored", tags="jailbreak")
    _write_skill(skills, "writing/haiku", tags="poetry")
    # A support dir under a real skill must be ignored (progressive-disclosure data).
    _write_skill(skills, "writing/haiku/references/archived", tags="jailbreak")

    monkeypatch.setattr(tool_policy, "_skill_dirs", lambda: [skills])
    monkeypatch.setattr(tool_policy, "deny_tags", lambda: {"jailbreak"})

    denied = tool_policy._tag_denied_installed_names()

    assert "godmodish" in denied      # top-level still caught
    assert "revendored" in denied     # nested category now caught (the fix)
    assert "haiku" not in denied       # benign skill untouched
    assert "archived" not in denied    # references/ support dir excluded


def test_scan_is_empty_when_no_deny_tags(tmp_path, monkeypatch):
    skills = tmp_path / "skills"
    _write_skill(skills, "offense/revendored", tags="jailbreak")
    monkeypatch.setattr(tool_policy, "_skill_dirs", lambda: [skills])
    monkeypatch.setattr(tool_policy, "deny_tags", lambda: set())
    assert tool_policy._tag_denied_installed_names() == set()
