"""DEF-022: shipped document-reading guidance must not install packages."""

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = REPO_ROOT / "skills/productivity/ocr-and-documents"
SKILL = SKILL_DIR / "SKILL.md"
ENGLISH_DOC = REPO_ROOT / (
    "website/docs/user-guide/skills/bundled/productivity/"
    "productivity-ocr-and-documents.md"
)
CHINESE_DOC = REPO_ROOT / (
    "website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/"
    "user-guide/skills/bundled/productivity/productivity-ocr-and-documents.md"
)
PACKAGE_COMMAND = re.compile(
    r"\b(?:pip3?|npm|npx|brew|conda)\s+install\b"
    r"|\buv\s+(?:pip|run)\b"
    r"|\b(?:uvx|pipx)\b"
    r"|--with\b",
    re.IGNORECASE,
)


def test_skill_uses_builtin_file_reader():
    assert "read_file" in SKILL.read_text(encoding="utf-8")


@pytest.mark.parametrize("path", [SKILL, ENGLISH_DOC, CHINESE_DOC], ids=["skill", "english", "chinese"])
def test_document_guidance_contains_no_package_commands(path):
    # Check the entire shipped document, including prose and code fences.
    text = re.sub(r"\\\r?\n", " ", path.read_text(encoding="utf-8"))
    assert not PACKAGE_COMMAND.search(text), f"Package command found in {path}"


def test_skill_has_no_external_extraction_scripts():
    assert not (SKILL_DIR / "scripts").exists()
