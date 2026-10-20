"""JER-189 — every repo-relative path a policy file names must exist.

The governed config names its records by path: registers in policy/*.yaml,
``security.*_path`` / ``governance.registers.*`` in cli-config.gov.yaml, card
and policy pointers in the model cards index and the AI-BOM. A pointer to a
file that was never created reads as evidence that does not exist, so a
dangling pointer fails CI here.

Scope: parsed YAML string values only (comments are prose, not pointers).
A token counts as a repo path when its first segment is a top-level entry of
this repository, or when it is a relative ``dir/file.ext`` path. Absolute,
home (``~``), ``$ENV`` and URL values are runtime locations and are skipped.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, Tuple

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]

_SCANNED = (
    *sorted(p.relative_to(_REPO).as_posix() for p in (_REPO / "policy").glob("*.yaml")),
    "cli-config.gov.yaml",
    "model_manifest.yaml",
    "evidence/bom/ai-bom.yaml",
    "docs/governance/model-cards/model-cards.yaml",
)

# A dangling pointer that cannot be repointed in this repository alone.
# policy/provider-allowlist.yaml is a fairness-tracked artifact
# (ci/governance-ci-gates/fairness_gate.py hashes it byte-for-byte), so even a
# one-line repoint needs a new fairness-evaluation record from the AI risk
# owner. The entry names the exact dangling value and the existing record it
# must point to; once the file is corrected the stale entry fails below and
# has to be deleted, so this list can only shrink.
#   (file, key path) -> (dangling value, existing record to point at)
_PENDING_OWNER_REPOINT = {
    ("policy/provider-allowlist.yaml", "metadata.review.register"): (
        "docs/governance/provider-vetting-register.md",
        "docs/governance/supplier-vetting-register.md",
    ),
}

_TOKEN = re.compile(r"[^\s\"'`(),;\[\]{}<>]+")
_FILE_EXT = re.compile(r"\.[A-Za-z0-9]{1,5}$")
_LINE_SUFFIX = re.compile(r":\d+(?:-\d+)?$")


def _top_level_entries(repo: Path) -> set:
    return {p.name for p in repo.iterdir() if p.name != ".git"}


def _string_values(node, trail=()) -> Iterator[Tuple[str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _string_values(value, (*trail, str(key)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _string_values(value, (*trail, str(index)))
    elif isinstance(node, str):
        yield ".".join(trail), node


def path_references(doc, top_level: set) -> Iterator[Tuple[str, str]]:
    """Yield (key path, repo-relative path) for every path-like token."""
    for where, value in _string_values(doc):
        for token in _TOKEN.findall(value):
            token = _LINE_SUFFIX.sub("", token).rstrip(".:")
            if token.startswith("./"):
                token = token[2:]
            if not token or token.startswith(("/", "~", "$")) or "://" in token:
                continue
            first = token.split("/", 1)[0]
            if first in top_level and ("/" in token or _FILE_EXT.search(token)):
                yield where, token
            elif "/" in token and _FILE_EXT.search(token):
                yield where, token


def _all_references():
    top = _top_level_entries(_REPO)
    refs = []
    for rel in _SCANNED:
        doc = yaml.safe_load((_REPO / rel).read_text(encoding="utf-8"))
        for where, path in path_references(doc, top):
            refs.append((rel, where, path))
    return refs


def test_scanned_files_exist():
    missing = [rel for rel in _SCANNED if not (_REPO / rel).is_file()]
    assert not missing, f"path-reference scan inputs missing: {missing}"


def test_every_policy_path_reference_exists():
    dangling = []
    for rel, where, path in _all_references():
        if (_REPO / path).exists():
            continue
        if _PENDING_OWNER_REPOINT.get((rel, where), (None,))[0] == path:
            continue
        dangling.append(f"{rel}: {where} -> {path}")
    assert not dangling, "dangling repo path references:\n  " + "\n  ".join(dangling)


@pytest.mark.parametrize("key, entry", sorted(_PENDING_OWNER_REPOINT.items()))
def test_pending_owner_repoints_are_still_needed(key, entry):
    rel, where = key
    dangling, replacement = entry
    doc = yaml.safe_load((_REPO / rel).read_text(encoding="utf-8"))
    current = dict(_string_values(doc)).get(where)
    assert current == dangling, (
        f"{rel}: {where} is now {current!r}; delete its _PENDING_OWNER_REPOINT entry")
    assert not (_REPO / dangling).exists(), f"{dangling} now exists; delete the entry"
    assert (_REPO / replacement).is_file(), f"replacement record {replacement} is missing"


def test_scan_finds_the_known_pointers():
    # Guard against the extractor silently matching nothing.
    refs = {(rel, path) for rel, _where, path in _all_references()}
    assert ("cli-config.gov.yaml", "policy/provider-allowlist.yaml") in refs
    assert ("cli-config.gov.yaml", "model_manifest.yaml") in refs
    assert ("evidence/bom/ai-bom.yaml", "docs/governance/supplier-vetting-register.md") in refs
    assert ("policy/tool-risk-policy.yaml", "agent/tool_executor.py") in refs
    assert len(refs) >= 40


def test_extractor_flags_a_dangling_pointer(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "real.md").write_text("x", encoding="utf-8")
    doc = {
        "review": {"register": "docs/missing-register.md"},
        "ok": "docs/real.md (LG-XX-01)",
        "elsewhere": "governance/other.yaml",
        "runtime": ["~/.lliam/audit.jsonl", "$HOME/x/y.yaml", "/etc/z.conf",
                    "https://example.test/a/b.md", "docker"],
    }
    refs = list(path_references(doc, _top_level_entries(tmp_path)))
    assert ("review.register", "docs/missing-register.md") in refs
    assert ("ok", "docs/real.md") in refs
    assert ("elsewhere", "governance/other.yaml") in refs
    assert len(refs) == 3
    assert not (tmp_path / "docs" / "missing-register.md").exists()
