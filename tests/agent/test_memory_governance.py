"""P2.6 — Memory governance: partition, retention, purge, reset (LG-MC-02/04..07).

MC-01 (sanitize-before-memory) and MC-03 (provenance) landed at P0.5/P1.2;
MC-04 staged write-approval is on since P0.2. This step adds the NEW governance
module agent/memory_governance.py:

  * LG-MC-02 — per-session/identity partitioned memory paths + permission-aware
    visibility (session A's memory is not visible to session B).
  * LG-MC-04 — a CRITICAL memory write routes to HITL (composes with the
    existing write_approval staging).
  * LG-MC-05 — purpose-limited retention TTL + PII-exclusion policy.
  * LG-MC-06 — secure purge/sanitization (overwrite then unlink).
  * LG-MC-07 — reset/wipe context between unrelated tasks/sessions.

No-op on low-side postures (capability preserving).
"""

from __future__ import annotations

import pytest


_STRICT = {"security": {"posture": "strict"}}


@pytest.fixture
def strict_mem(monkeypatch):
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: _STRICT)
    import agent.memory_governance as mg

    yield mg


# ---------------------------------------------------------------------------
# 1. LG-MC-02 — per-session partition + visibility
# ---------------------------------------------------------------------------

def test_partition_path_is_per_session(strict_mem, tmp_path):
    a = strict_mem.partition_path(tmp_path, session_id="sess-A", identity="agent1")
    b = strict_mem.partition_path(tmp_path, session_id="sess-B", identity="agent1")
    assert a != b
    assert "sess-A" in str(a) or a.parent != b.parent


def test_session_a_memory_not_visible_to_session_b(strict_mem):
    entry = {"session_id": "sess-A", "identity": "agent1", "scope": "session"}
    assert strict_mem.entry_visible(entry, session_id="sess-A", identity="agent1") is True
    assert strict_mem.entry_visible(entry, session_id="sess-B", identity="agent1") is False


def test_shared_scope_entry_visible_across_sessions(strict_mem):
    entry = {"session_id": "sess-A", "identity": "agent1", "scope": "shared"}
    assert strict_mem.entry_visible(entry, session_id="sess-B", identity="agent1") is True


def test_cross_identity_never_visible(strict_mem):
    entry = {"session_id": "sess-A", "identity": "agent1", "scope": "shared"}
    assert strict_mem.entry_visible(entry, session_id="sess-A", identity="agent2") is False


def test_low_side_partition_is_shared(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    import agent.memory_governance as mg

    # Low-side: no partitioning (shipped single-store behavior) — capability.
    a = mg.partition_path(tmp_path, session_id="sess-A", identity="agent1")
    b = mg.partition_path(tmp_path, session_id="sess-B", identity="agent1")
    assert a == b


# ---------------------------------------------------------------------------
# 2. LG-MC-04 — critical writes route to HITL
# ---------------------------------------------------------------------------

def test_critical_memory_write_requires_hitl(strict_mem):
    assert strict_mem.write_requires_hitl("critical") is True
    assert strict_mem.write_requires_hitl("routine") is False


def test_low_side_write_never_requires_hitl(monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    import agent.memory_governance as mg

    assert mg.write_requires_hitl("critical") is False


# ---------------------------------------------------------------------------
# 3. LG-MC-05 — retention TTL + PII exclusion
# ---------------------------------------------------------------------------

def test_expired_entries_swept(strict_mem):
    now = 1_000_000
    entries = [
        {"id": "keep", "ts": now - 10, "content": "recent"},
        {"id": "drop", "ts": now - 10_000, "content": "old"},
    ]
    kept = strict_mem.sweep_expired(entries, ttl_seconds=100, now=now)
    ids = {e["id"] for e in kept}
    assert ids == {"keep"}


def test_pii_content_excluded_from_persistence(strict_mem):
    assert strict_mem.pii_excluded("POC SSN 123-45-6789") is True
    assert strict_mem.pii_excluded("just a note about the build") is False


def test_low_side_never_sweeps_or_excludes(monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    import agent.memory_governance as mg

    now = 1_000_000
    entries = [{"id": "old", "ts": now - 10_000, "content": "x"}]
    assert mg.sweep_expired(entries, ttl_seconds=100, now=now) == entries
    assert mg.pii_excluded("SSN 123-45-6789") is False


def test_posture_resolution_failure_keeps_memory_partitioned(tmp_path, monkeypatch):
    import agent.memory_governance as mg

    def _broken_config(*_args, **_kwargs):
        raise RuntimeError("bad config")

    monkeypatch.setattr("lliam_cli.config.load_config", _broken_config)
    path = mg.partition_path(tmp_path, session_id="session-a", identity="agent1")
    assert path != tmp_path
    assert path.parts[-3:] == ("partitions", "agent1", "session-a")


# ---------------------------------------------------------------------------
# 4. LG-MC-06 — secure purge
# ---------------------------------------------------------------------------

def test_secure_purge_overwrites_and_unlinks(strict_mem, tmp_path):
    f = tmp_path / "mem" / "secret.md"
    f.parent.mkdir()
    f.write_text("CUI secret payload", encoding="utf-8")
    assert f.exists()
    strict_mem.secure_purge(f)
    assert not f.exists()


def test_secure_purge_missing_file_is_noop(strict_mem, tmp_path):
    # Must not raise on an already-absent path.
    strict_mem.secure_purge(tmp_path / "nope.md")


# ---------------------------------------------------------------------------
# 5. LG-MC-07 — reset/wipe context between tasks
# ---------------------------------------------------------------------------

def test_reset_context_purges_session_partition(strict_mem, tmp_path):
    part = strict_mem.partition_path(tmp_path, session_id="sess-A", identity="agent1")
    part.mkdir(parents=True, exist_ok=True)
    (part / "note.md").write_text("session A working memory", encoding="utf-8")
    strict_mem.reset_session_context(tmp_path, session_id="sess-A", identity="agent1")
    assert not (part / "note.md").exists()


def test_memory_store_uses_runtime_session_partition(strict_mem, tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("LLIAM_HOME", str(tmp_path))
    from tools.memory_tool import MemoryStore

    a = MemoryStore(session_id="session-a", identity="agent1")
    b = MemoryStore(session_id="session-b", identity="agent1")
    a.load_from_disk()
    b.load_from_disk()
    assert a.add("memory", "session A note")["success"]
    assert "session A note" not in a._metadata_path("memory").read_text()
    b.load_from_disk()
    assert "session A note" not in b.memory_entries
    assert a._path_for("memory") != b._path_for("memory")


def test_memory_store_rejects_pii_before_persistence(strict_mem, tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("LLIAM_HOME", str(tmp_path))
    from tools.memory_tool import MemoryStore

    store = MemoryStore(session_id="session-a")
    store.load_from_disk()
    result = store.add("memory", "POC SSN 123-45-6789")
    assert result["success"] is False
    assert not store._path_for("memory").exists()
