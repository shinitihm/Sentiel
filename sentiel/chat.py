import json
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .triage import DEFAULT_TIMEOUT, call_llm

MAX_ROWS = 200
TIMEOUT_S = 5
ALLOWED_TABLES = {"logs", "alerts"}
_ALLOWED_OPS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}


class UnsafeQuery(Exception):
    pass


def open_readonly(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{Path(db_path).resolve().as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def describe_schema(conn: sqlite3.Connection) -> str:
    parts = []
    for table in sorted(ALLOWED_TABLES):
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
        parts.append(f"{table}({', '.join(cols[:80])}{', ...' if len(cols) > 80 else ''})")
    return "\n".join(parts)


def lock_down(conn: sqlite3.Connection) -> None:
    """Allow only SELECT over logs/alerts. Done with the authorizer, not by inspecting the SQL text."""
    def authorizer(op, arg1, arg2, db, source):
        if op not in _ALLOWED_OPS:
            return sqlite3.SQLITE_DENY
        if op == sqlite3.SQLITE_READ and arg1 not in ALLOWED_TABLES:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    conn.set_authorizer(authorizer)

