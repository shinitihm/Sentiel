import json
import re
import sqlite3
from collections.abc import Iterable
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from .models import Alert, Event, Triage

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY, ts TEXT NOT NULL, source TEXT NOT NULL, host TEXT,
    hash TEXT UNIQUE NOT NULL, raw TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS logs_ts ON logs(ts);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY, rule_id TEXT NOT NULL, rule_title TEXT NOT NULL, sigma_level TEXT NOT NULL,
    mitre TEXT NOT NULL, ts TEXT NOT NULL, event_ids TEXT NOT NULL, first_event_id INTEGER NOT NULL,
    triage TEXT, model TEXT, cost_usd REAL, latency_ms INTEGER, notified INTEGER NOT NULL DEFAULT 0,
    UNIQUE(rule_id, first_event_id));
CREATE TABLE IF NOT EXISTS ip_cache (ip TEXT PRIMARY KEY, data TEXT NOT NULL, fetched_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
RESERVED = {"id", "ts", "source", "host", "hash", "raw"}
MAX_COLUMNS = 1900  # SQLite's default hard limit is 2000


def fmt_ts(dt: datetime) -> str:
    """Fixed-width UTC format so string comparison in SQL == chronological order."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


def quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _regexp(pattern: str, value) -> bool:
    return value is not None and re.search(pattern, str(value)) is not None


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.create_function("REGEXP", 2, _regexp, deterministic=True)
    conn.executescript(SCHEMA)
    return conn


def _columns(conn: sqlite3.Connection) -> set[str]:
    return {r[1].lower() for r in conn.execute("PRAGMA table_info(logs)")}


def ensure_column(conn: sqlite3.Connection, name: str) -> None:
    # NUMERIC: "4625" and 4625 compare equal; NOCASE: Sigma matching is case-insensitive
    conn.execute(f"ALTER TABLE logs ADD COLUMN {quote(name)} NUMERIC COLLATE NOCASE")


def query_tolerant(conn: sqlite3.Connection, sql: str, params: list | tuple = ()) -> list[sqlite3.Row]:
    """Run a rule query; a field no event has yet becomes an all-NULL column instead of failing the whole rule."""
    for _ in range(50):
        try:
            return conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError as e:
            m = re.match(r"no such column: (\w+)$", str(e))
            if not m:
                raise
            ensure_column(conn, m[1])
    raise sqlite3.OperationalError("rule references too many unknown fields")


def insert_events(conn: sqlite3.Connection, events: Iterable[Event]) -> int:
    """Insert events, adding one column per new field. Returns how many were new."""
    cols = _columns(conn)
    new = 0
    for ev in events:
        fields: dict[str, str | int | None] = {}
        for k, v in ev.fields.items():
            low = k.lower()
            if low in RESERVED or any(low == f.lower() for f in fields):
                continue
            if low not in cols:
                if len(cols) >= MAX_COLUMNS:
                    continue  # ponytail: extra fields stay only in `raw`; split tables if this ever bites
                ensure_column(conn, k)
                cols.add(low)
            fields[k] = v
        ts = fmt_ts(ev.ts)
        raw = json.dumps({"ts": ts, "host": ev.host, "fields": ev.fields}, sort_keys=True, default=str)
        digest = sha256((ev.source + raw).encode()).hexdigest()
        names = ["ts", "source", "host", "hash", "raw", *fields]
        cur = conn.execute(
            f"INSERT OR IGNORE INTO logs ({','.join(map(quote, names))}) VALUES ({','.join('?' * len(names))})",
            [ts, ev.source, ev.host, digest, raw, *fields.values()],
        )
        new += cur.rowcount
    conn.commit()
    return new


def get_events(conn: sqlite3.Connection, ids: list[int]) -> list[dict]:
    if not ids:
        return []
    rows = conn.execute(
        f"SELECT id, source, raw FROM logs WHERE id IN ({','.join('?' * len(ids))}) ORDER BY id", ids
    ).fetchall()
    return [{"id": r["id"], "source": r["source"], **json.loads(r["raw"])} for r in rows]


def insert_alerts(conn: sqlite3.Connection, alerts: Iterable[Alert]) -> int:
    new = 0
    for a in alerts:
        cur = conn.execute(
            "INSERT OR IGNORE INTO alerts (rule_id, rule_title, sigma_level, mitre, ts, event_ids, first_event_id)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (a.rule_id, a.rule_title, a.sigma_level, json.dumps(a.mitre), fmt_ts(a.ts),
             json.dumps(a.event_ids), a.event_ids[0]),
        )
        new += cur.rowcount
    conn.commit()
    return new


def row_to_alert(row: sqlite3.Row) -> tuple[Alert, Triage | None]:
    alert = Alert(
        id=row["id"], rule_id=row["rule_id"], rule_title=row["rule_title"], sigma_level=row["sigma_level"],
        mitre=json.loads(row["mitre"]), ts=parse_ts(row["ts"]), event_ids=json.loads(row["event_ids"]),
    )
    triage = Triage.model_validate_json(row["triage"]) if row["triage"] else None
    return alert, triage


def list_alerts(conn: sqlite3.Connection, limit: int = 50) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM alerts ORDER BY ts DESC, id DESC LIMIT ?", (limit,)).fetchall()


def get_alert(conn: sqlite3.Connection, alert_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()


def pending_alerts(conn: sqlite3.Connection, limit: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM alerts WHERE triage IS NULL ORDER BY id LIMIT ?", (limit,)).fetchall()


def save_triage(conn: sqlite3.Connection, alert_id: int, triage: Triage, model: str,
                cost_usd: float | None, latency_ms: int) -> None:
    conn.execute(
        "UPDATE alerts SET triage = ?, model = ?, cost_usd = ?, latency_ms = ? WHERE id = ?",
        (triage.model_dump_json(), model, cost_usd, latency_ms, alert_id),
    )
    conn.commit()


def unnotified_alerts(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM alerts WHERE notified = 0 ORDER BY id").fetchall()


def mark_notified(conn: sqlite3.Connection, alert_id: int) -> None:
    conn.execute("UPDATE alerts SET notified = 1 WHERE id = ?", (alert_id,))
    conn.commit()


def get_state(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                 (key, value))
    conn.commit()
