"""CUI marking + audit-only chain of custody — LG-4.6 / AI-223.

WHY: the §5.6 decision is marking + audit + governance ONLY. These tests
pin both halves: custody events carry marker/destination/params_hash and
land in the chain, AND a CUI marker alone never blocks an otherwise
allowed operation — gating regressions fail here loudly.
"""

import json

import pytest

from lliam_gov.security.cui import (
    CuiError,
    combine_markers,
    load_manifest,
    mark_path,
    marker_for_path,
    sanitize_delete,
    scan_args_for_cui,
)


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "lliam-home"
    h.mkdir(mode=0o700)
    monkeypatch.setenv("HERMES_HOME", str(h))
    return h


def _records(home):
    return [
        json.loads(line)
        for f in (home / "audit").glob("*.jsonl")
        for line in f.read_text().splitlines()
    ]


# ── marking + propagation ───────────────────────────────────────────────────


def test_mark_and_resolve_prefix(home, tmp_path):
    docs = tmp_path / "cui-docs"
    mark_path(docs, "CUI//SP-PRIV")
    assert marker_for_path(docs / "nested/deep/file.pdf") == "CUI//SP-PRIV"
    assert marker_for_path(tmp_path / "other.txt") is None


def test_most_specific_prefix_wins(home, tmp_path):
    mark_path(tmp_path, "CUI")
    mark_path(tmp_path / "special", "CUI//SP-EXPT")
    assert marker_for_path(tmp_path / "special" / "f") == "CUI//SP-EXPT"
    assert marker_for_path(tmp_path / "f") == "CUI"


def test_manifest_file_is_0600(home, tmp_path):
    import os

    mark_path(tmp_path, "CUI")
    manifest = home / "cui-manifest.json"
    assert (os.stat(manifest).st_mode & 0o777) == 0o600


def test_empty_marker_refused(home, tmp_path):
    with pytest.raises(CuiError):
        mark_path(tmp_path, "  ")


def test_combine_markers_propagates_cui():
    assert combine_markers(None, None) is None
    assert combine_markers("CUI", None) == "CUI"
    assert combine_markers("CUI", "CUI//SP-PRIV") == "CUI//SP-PRIV"


# ── custody events ──────────────────────────────────────────────────────────


def test_scan_emits_cui_access_with_marker_destination_hash(home, tmp_path):
    mark_path(tmp_path / "cui-zone", "CUI")
    scan_args_for_cui(
        "read_file",
        {"path": str(tmp_path / "cui-zone" / "doc.txt"), "limit": 5},
        session_id="cui-test",
    )
    access = [r for r in _records(home) if r["event_type"] == "cui_access"]
    assert len(access) == 1
    rec = access[0]
    assert rec["marker"] == "CUI"
    assert rec["destination"] == "read_file"
    assert rec["params_hash"]
    assert "doc.txt" not in json.dumps(rec), "raw paths/payloads stay out of the chain"


def test_scan_noop_without_manifest(home):
    scan_args_for_cui("read_file", {"path": "/anywhere/file"}, session_id="x")
    assert not (home / "audit").exists()


def test_unmarked_path_emits_nothing(home, tmp_path):
    mark_path(tmp_path / "cui-zone", "CUI")
    scan_args_for_cui("read_file", {"path": str(tmp_path / "open/file")})
    assert [r for r in _records(home) if r["event_type"] == "cui_access"] == []


# ── NO GATING — the authoritative scope decision ───────────────────────────


def test_cui_status_never_blocks_dispatch(home, tmp_path):
    """A marked path flows through dispatch normally; custody is recorded
    but the tool executes and returns its result."""
    from model_tools import handle_function_call
    from tools.registry import registry

    mark_path(tmp_path / "cui-zone", "CUI")
    target = str(tmp_path / "cui-zone" / "doc.txt")

    registry.register(
        name="cui_probe_tool",
        toolset="file",
        schema={"name": "cui_probe_tool", "parameters": {"type": "object", "properties": {}}},
        handler=lambda *a, **kw: "tool-ran",
        check_fn=None,
        requires_env=None,
        is_async=False,
        description="probe",
        emoji="",
    )
    try:
        result = handle_function_call(
            "cui_probe_tool", {"path": target}, session_id="cui-test"
        )
        assert "tool-ran" in result, "CUI marker must not deny allowed routing"
        access = [r for r in _records(home) if r["event_type"] == "cui_access"]
        assert access and access[-1]["marker"] == "CUI"
    finally:
        registry.deregister("cui_probe_tool")


# ── sanitized delete ────────────────────────────────────────────────────────


def test_sanitize_delete_removes_and_audits(home, tmp_path):
    mark_path(tmp_path / "cui-zone", "CUI")
    f = tmp_path / "cui-zone" / "secret.txt"
    f.parent.mkdir(parents=True)
    f.write_text("controlled content")
    assert sanitize_delete(f) is True
    assert not f.exists()
    deletes = [r for r in _records(home) if r["event_type"] == "cui_delete"]
    assert deletes and deletes[-1]["marker"] == "CUI"


def test_sanitize_delete_missing_file_returns_false(home, tmp_path):
    assert sanitize_delete(tmp_path / "absent") is False
