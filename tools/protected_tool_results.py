"""Encrypted, task-scoped spill files for governed tool results."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import closing

from agent.data_protection import decrypt_at_rest, encrypt_at_rest
from lliam_constants import get_lliam_home

REFERENCE_PREFIX = "lliam-result://"


def _database():
    return get_lliam_home() / "tool-results" / "protected.sqlite3"


def _expire(connection, now):
    connection.execute(
        "DELETE FROM results WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,)
    )


def expire_results():
    """Remove expired encrypted results even when no new tool call is made."""
    database = _database()
    if database.is_file():
        with closing(sqlite3.connect(database)) as conn, conn:
            _expire(conn, time.time())


def store_result(content: str, task_id: str, ttl: int | None) -> str:
    database = _database()
    database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    identifier = uuid.uuid4().hex
    now = time.time()
    expiry = now + ttl if ttl is not None else None
    # Bind the task, identifier and expiry to the authenticated ciphertext.
    payload = json.dumps([identifier, task_id, expiry, content]).encode()
    encrypted = encrypt_at_rest(payload)
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS results "
            "(id TEXT PRIMARY KEY, expires_at REAL, payload BLOB NOT NULL)"
        )
        _expire(conn, now)
        conn.execute("INSERT INTO results VALUES (?, ?, ?)", (identifier, expiry, encrypted))
    return REFERENCE_PREFIX + identifier


def read_page(reference: str, task_id: str, offset: int, limit: int) -> dict:
    """Read a generated result reference; caller input never becomes a host path."""
    unavailable = {"error": "Tool result is unavailable."}
    identifier = reference.removeprefix(REFERENCE_PREFIX)
    database = _database()
    if len(identifier) != 32 or not database.is_file():
        return unavailable
    now = time.time()
    with closing(sqlite3.connect(database)) as conn, conn:
        _expire(conn, now)
        row = conn.execute("SELECT payload FROM results WHERE id = ?", (identifier,)).fetchone()
    if row is None:
        return unavailable
    stored_id, owner, expiry, content = json.loads(decrypt_at_rest(row[0]))
    if stored_id != identifier or owner != task_id or (expiry is not None and expiry <= now):
        return unavailable
    from tools.read_extract import split_long_line
    from tools.tool_output_limits import get_max_line_length

    width = get_max_line_length()
    lines = [chunk for line in content.splitlines() for chunk in split_long_line(line, width)]
    page = lines[offset - 1:offset - 1 + limit]
    return {
        "content": "\n".join(f"{i}|{line}" for i, line in enumerate(page, offset)),
        "total_lines": len(lines),
        "file_size": len(content.encode()),
        "truncated": offset - 1 + limit < len(lines),
    }
