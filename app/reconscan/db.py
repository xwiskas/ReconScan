"""Tiny SQLite data layer.

We use Python's built-in sqlite3 (no ORM) to keep the code short and readable
for someone learning. JSON is stored as TEXT in a couple of columns.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from . import config


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS projects (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    authorization_note TEXT NOT NULL,
    created_at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    value      TEXT NOT NULL,
    type       TEXT NOT NULL,
    in_scope   INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tool         TEXT NOT NULL,
    goal         TEXT NOT NULL,
    target       TEXT NOT NULL,
    command_args TEXT NOT NULL,   -- JSON list
    preview      TEXT NOT NULL,
    status       TEXT NOT NULL,   -- queued|running|done|failed|canceled
    is_demo      INTEGER NOT NULL,
    exit_code    INTEGER,
    stdout       TEXT DEFAULT '',
    stderr       TEXT DEFAULT '',
    created_at   TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id                  TEXT PRIMARY KEY,
    scan_id             TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target              TEXT NOT NULL,
    type                TEXT NOT NULL,   -- port|service|os|vuln|web
    data                TEXT NOT NULL,   -- JSON object
    interpretation      TEXT,
    suggested_next_step TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id         TEXT PRIMARY KEY,
    project_id TEXT,
    user_id    TEXT,
    action     TEXT NOT NULL,
    command    TEXT,
    timestamp  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS templates (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    tool       TEXT NOT NULL,
    goal       TEXT NOT NULL,
    options    TEXT NOT NULL,   -- JSON object
    note       TEXT,
    use_count  INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS schedules (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    tool          TEXT NOT NULL,
    goal          TEXT NOT NULL,
    target        TEXT NOT NULL,
    options       TEXT NOT NULL,   -- JSON object
    is_demo       INTEGER NOT NULL DEFAULT 1,
    every_minutes INTEGER NOT NULL,
    max_runs      INTEGER,
    run_count     INTEGER NOT NULL DEFAULT 0,
    enabled       INTEGER NOT NULL DEFAULT 1,
    next_run_at   TEXT NOT NULL,
    last_run_at   TEXT,
    last_scan_id  TEXT,
    last_error    TEXT,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quiz_answers (
    id          TEXT PRIMARY KEY,
    question_id TEXT NOT NULL,
    topic       TEXT NOT NULL,
    correct     INTEGER NOT NULL,
    answered_at TEXT NOT NULL
);
"""

# Columns added after the first release. SQLite has no "ADD COLUMN IF NOT EXISTS",
# so we look at the table and add what is missing - existing databases upgrade in
# place rather than needing to be thrown away.
ADDED_COLUMNS = {
    "scans": [("options", "TEXT NOT NULL DEFAULT '{}'"),
              ("schedule_id", "TEXT")],
}


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        for table, cols in ADDED_COLUMNS.items():
            have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            for name, decl in cols:
                if name not in have:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


# --- small helpers ----------------------------------------------------------

def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for k in ("command_args", "data", "options"):
        if k in d and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except (ValueError, TypeError):
                pass
    for k in ("in_scope", "is_demo", "enabled"):
        if k in d and d[k] is not None:
            d[k] = bool(d[k])
    return d


def rows_to_list(rows: Iterable[sqlite3.Row]) -> list[dict]:
    return [row_to_dict(r) for r in rows]


def audit(action: str, *, project_id: str | None = None,
          user_id: str | None = None, command: str | None = None) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit (id, project_id, user_id, action, command, timestamp)"
            " VALUES (?,?,?,?,?,?)",
            (new_id(), project_id, user_id, action, command, now()),
        )
