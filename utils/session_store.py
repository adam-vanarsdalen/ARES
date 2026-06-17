"""
SQLite-backed session metadata store for ARES.

Schema: sessions(id TEXT PK, target TEXT, mode TEXT, status TEXT,
                 created_at TEXT, completed_at REAL, results_json TEXT,
                 report_path TEXT, abort INTEGER)

The in-memory event queue is NOT persisted - it is ephemeral by design.
"""

import json
import sqlite3
import threading
import time

from utils.config import DB_PATH

_DB_PATH = DB_PATH
_lock = threading.Lock()
_memory_conn: sqlite3.Connection | None = None


def _conn():
    global _memory_conn
    if _DB_PATH == ":memory:":
        if _memory_conn is None:
            _memory_conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
            _memory_conn.row_factory = sqlite3.Row
        return _memory_conn
    c = sqlite3.connect(_DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _lock:
        c = _conn()
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id           TEXT PRIMARY KEY,
                target       TEXT NOT NULL,
                mode         TEXT NOT NULL DEFAULT 'full',
                status       TEXT NOT NULL DEFAULT 'running',
                created_at   TEXT NOT NULL,
                completed_at REAL,
                results_json TEXT,
                report_path  TEXT,
                abort        INTEGER NOT NULL DEFAULT 0
            )
        """)
        c.commit()
        if _DB_PATH != ":memory:":
            c.close()


def create_session(session_id: str, target: str, mode: str, created_at: str):
    with _lock:
        c = _conn()
        c.execute(
            "INSERT INTO sessions(id, target, mode, status, created_at) VALUES (?,?,?,?,?)",
            (session_id, target, mode, "running", created_at),
        )
        c.commit()
        if _DB_PATH != ":memory:":
            c.close()


def _row_to_session(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["results"] = json.loads(d.pop("results_json") or "{}")
    d["abort"] = bool(d["abort"])
    return d


def get_session(session_id: str) -> dict | None:
    with _lock:
        c = _conn()
        row = c.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if _DB_PATH != ":memory:":
            c.close()
    if not row:
        return None
    return _row_to_session(row)


_ALLOWED_SESSION_COLS = frozenset(
    {"status", "completed_at", "results_json", "report_path", "abort"}
)


def update_session(session_id: str, **kwargs):
    """Update session columns. results dict is serialised automatically."""
    if "results" in kwargs:
        kwargs["results_json"] = json.dumps(kwargs.pop("results"))
    if "abort" in kwargs:
        kwargs["abort"] = int(bool(kwargs["abort"]))
    if not kwargs:
        return
    bad = set(kwargs) - _ALLOWED_SESSION_COLS
    if bad:
        raise ValueError(f"Disallowed session column(s): {bad}")
    cols = ", ".join(f"{k}=?" for k in kwargs)
    vals = list(kwargs.values()) + [session_id]
    with _lock:
        c = _conn()
        c.execute(f"UPDATE sessions SET {cols} WHERE id=?", vals)
        c.commit()
        if _DB_PATH != ":memory:":
            c.close()


def delete_session(session_id: str):
    with _lock:
        c = _conn()
        c.execute("DELETE FROM sessions WHERE id=?", (session_id,))
        c.commit()
        if _DB_PATH != ":memory:":
            c.close()


def list_recent_sessions(limit: int = 20) -> list[dict]:
    with _lock:
        c = _conn()
        rows = c.execute(
            "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        if _DB_PATH != ":memory:":
            c.close()
    return [_row_to_session(row) for row in rows]


def prune_old_sessions(ttl_seconds: int) -> list[str]:
    cutoff = time.time() - ttl_seconds
    with _lock:
        c = _conn()
        rows = c.execute(
            "SELECT id FROM sessions WHERE completed_at IS NOT NULL AND completed_at < ?",
            (cutoff,),
        ).fetchall()
        deleted_ids = [row["id"] for row in rows]
        c.execute(
            "DELETE FROM sessions WHERE completed_at IS NOT NULL AND completed_at < ?",
            (cutoff,),
        )
        c.commit()
        if _DB_PATH != ":memory:":
            c.close()
    return deleted_ids
