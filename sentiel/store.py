import json
import re
import sqlite3
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path

from .models import SEVERITIES, Alert, Event, Triage, effective_severity, is_contested

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
STATUSES = ("open", "ack", "closed", "false_positive", "suppressed")
ACTIVE = ("open", "ack")
# Ordered schema migrations; item i holds the statements for version i+1. SCHEMA above is the v0.3 baseline (v0).
MIGRATIONS: tuple[tuple[str, ...], ...] = (
    (
        "ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'open'",
        "ALTER TABLE alerts ADD COLUMN note TEXT",
    ),
    (
        "ALTER TABLE alerts ADD COLUMN count INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE alerts ADD COLUMN last_ts TEXT",
        "ALTER TABLE alerts ADD COLUMN host TEXT",
        "ALTER TABLE alerts ADD COLUMN group_key TEXT",
        "UPDATE alerts SET count = json_array_length(event_ids), last_ts = ts, "
        "host = (SELECT host FROM logs WHERE logs.id = alerts.first_event_id)",
        "CREATE INDEX IF NOT EXISTS alerts_group ON alerts(rule_id, host, group_key, status, last_ts)",
    ),
)
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


class SchemaTooNew(RuntimeError):
    pass


def _version(conn: sqlite3.Connection) -> int:
    return conn.execute("PRAGMA user_version").fetchone()[0]


def _check_version(conn: sqlite3.Connection) -> int:
    v = _version(conn)
    if v > len(MIGRATIONS):
        raise SchemaTooNew(
            f"database schema v{v} is newer than this Sentiel (supports v{len(MIGRATIONS)}); upgrade Sentiel"
        )
    return v


def _migrate(conn: sqlite3.Connection) -> None:
    for n in range(_check_version(conn) + 1, len(MIGRATIONS) + 1):
        conn.execute("BEGIN IMMEDIATE")
        try:
            if _version(conn) >= n:  # another process migrated while we waited for the lock
                conn.rollback()
                continue
            for stmt in MIGRATIONS[n - 1]:  # never executescript: it commits
                conn.execute(stmt)
            conn.execute(f"PRAGMA user_version = {int(n)}")
            conn.commit()
        except BaseException:
            conn.rollback()
            raise


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30)
    try:
        conn.row_factory = sqlite3.Row
        conn.create_function("REGEXP", 2, _regexp, deterministic=True)
        _check_version(conn)  # refuse before touching a newer DB
        conn.executescript(SCHEMA)
        _migrate(conn)
    except BaseException:
        conn.close()
        raise
    return conn


def _columns(conn: sqlite3.Connection) -> set[str]:
    return {r[1].lower() for r in conn.execute("PRAGMA table_info(logs)")}


def ensure_column(conn: sqlite3.Connection, name: str) -> None:
    # NUMERIC: "4625" and 4625 compare equal; NOCASE: Sigma matching is case-insensitive
    try:
        conn.execute(f"ALTER TABLE logs ADD COLUMN {quote(name)} NUMERIC COLLATE NOCASE")
    except sqlite3.OperationalError as e:
        # A concurrent scan on another connection may have added it after our check.
        if "duplicate column name" not in str(e).lower():
            raise


def query_tolerant(conn: sqlite3.Connection, sql: str, params: list | tuple | dict = ()) -> list[sqlite3.Row]:
    """Run a rule query; a field no event has yet becomes an all-NULL column instead of failing the whole rule."""
    for _ in range(50):
        try:
            return conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError as e:
            m = re.match(r"no such column: (.+)$", str(e))  # Sigma fields may hold '-' or '.': cs-uri-query, user.name
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


def insert_alerts(conn: sqlite3.Connection, alerts: Iterable[Alert], group_window: timedelta = timedelta(0),
                  commit: bool = True) -> int:
    """Insert alerts; returns the number of NEW rows. With a window, alerts of the same rule/host/key/status merge.

    Any exception rolls back, so nothing partial is left; `commit=False` lets the caller commit with its own writes.
    """
    try:
        new = _insert_alerts(conn, alerts, group_window)
        if commit:
            conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return new


def _insert_alerts(conn: sqlite3.Connection, alerts: Iterable[Alert], group_window: timedelta) -> int:
    new = 0
    for a in alerts:
        first = a.event_ids[0]
        last_ts = fmt_ts(a.last_ts or a.ts)
        added = a.fresh if a.fresh is not None else a.count  # events this alert adds to an existing row
        h = conn.execute("SELECT host FROM logs WHERE id = ?", (first,)).fetchone()
        host = h["host"] if h else None
        target = conn.execute("SELECT id, count, last_ts, event_ids FROM alerts"
                              " WHERE rule_id = ? AND first_event_id = ?", (a.rule_id, first)).fetchone()
        if not target and group_window > timedelta(0):
            try:
                lo, hi = fmt_ts(a.ts - group_window), fmt_ts(a.ts + group_window)
            except OverflowError:
                lo = hi = None
            if lo is not None:
                target = conn.execute(
                    "SELECT id, count, last_ts, event_ids FROM alerts WHERE rule_id = ? AND host IS ?"
                    " AND group_key IS ? AND status = ? AND status IN ('open', 'suppressed')"
                    " AND last_ts >= ? AND ts <= ? ORDER BY last_ts DESC LIMIT 1",
                    (a.rule_id, host, a.group_key, a.status, lo, hi)).fetchone()
        if target:
            # ponytail: `count` of a correlation is approximate. This `same` path ignores status, so the continuation
            # of an already closed/false_positive correlation is added to that alert, without notifying, until the
            # lookback window passes.
            ids = json.loads(target["event_ids"])
            seen = set(ids)
            merged = (ids + [i for i in a.event_ids if i not in seen])[:50]
            conn.execute("UPDATE alerts SET count = ?, last_ts = ?, event_ids = ? WHERE id = ?",
                         (target["count"] + added, max(target["last_ts"] or "", last_ts), json.dumps(merged),
                          target["id"]))
            continue
        cur = conn.execute(
            "INSERT OR IGNORE INTO alerts (rule_id, rule_title, sigma_level, mitre, ts, event_ids, first_event_id,"
            " status, note, host, group_key, count, last_ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (a.rule_id, a.rule_title, a.sigma_level, json.dumps(a.mitre), fmt_ts(a.ts), json.dumps(a.event_ids),
             first, a.status, a.note, host, a.group_key, a.count, last_ts),
        )
        new += cur.rowcount
    return new


def row_to_alert(row: sqlite3.Row) -> tuple[Alert, Triage | None]:
    alert = Alert(
        id=row["id"], rule_id=row["rule_id"], rule_title=row["rule_title"], sigma_level=row["sigma_level"],
        mitre=json.loads(row["mitre"]), ts=parse_ts(row["ts"]), event_ids=json.loads(row["event_ids"]),
        status=row["status"], note=row["note"], count=row["count"],
        last_ts=parse_ts(row["last_ts"] or row["ts"]), host=row["host"], group_key=row["group_key"],
    )
    triage = Triage.model_validate_json(row["triage"]) if row["triage"] else None
    return alert, triage


_ACTIVE_SQL = "(" + ", ".join(f"'{s}'" for s in ACTIVE) + ")"  # constants only, never user input


def list_alerts(conn: sqlite3.Connection, limit: int = 50, include_all: bool = False) -> list[sqlite3.Row]:
    where = "" if include_all else f"WHERE status IN {_ACTIVE_SQL} "
    return conn.execute(
        f"SELECT * FROM alerts {where}ORDER BY coalesce(last_ts, ts) DESC, id DESC LIMIT ?", (limit,)
    ).fetchall()


def set_status(conn: sqlite3.Connection, alert_id: int, status: str, note: str | None) -> bool:
    if status not in STATUSES or status == "suppressed":  # suppressed is reserved to the config file
        raise ValueError(f"invalid status {status!r}")
    cur = conn.execute("UPDATE alerts SET status = ?, note = coalesce(?, note) WHERE id = ?",
                       (status, note, alert_id))
    conn.commit()
    return cur.rowcount > 0


def count_pending(conn: sqlite3.Connection) -> int:
    return conn.execute(f"SELECT count(*) FROM alerts WHERE triage IS NULL AND status IN {_ACTIVE_SQL}").fetchone()[0]


def digest_stats(conn: sqlite3.Connection, since: datetime) -> dict:
    """Summary of alerts touched since `since` (suppressed ones are only counted, not listed)."""
    rows = conn.execute(
        "SELECT rule_id, rule_title, sigma_level, triage, status, count FROM alerts "
        "WHERE coalesce(last_ts, ts) >= ?", (fmt_ts(since),)).fetchall()
    by_sev: Counter[str] = Counter()
    per_rule: Counter[str] = Counter()
    titles: dict[str, str] = {}
    contested = suppressed = 0
    for r in rows:
        if r["status"] == "suppressed":
            suppressed += r["count"]
            continue
        try:
            triage = Triage.model_validate_json(r["triage"]) if r["triage"] else None
        except ValueError:  # a corrupt triage row must not take the digest down
            triage = None
        by_sev[effective_severity(r["sigma_level"], triage)] += 1
        contested += is_contested(r["sigma_level"], triage)
        per_rule[r["rule_id"]] += r["count"]
        titles[r["rule_id"]] = r["rule_title"]
    return {"by_severity": {s: by_sev[s] for s in reversed(SEVERITIES) if by_sev[s]},
            "top_rules": [(titles[k], n) for k, n in per_rule.most_common(5)],
            "contested": contested, "pending": count_pending(conn), "suppressed": suppressed}


def get_alert(conn: sqlite3.Connection, alert_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()


def pending_alerts(conn: sqlite3.Connection, limit: int) -> list[sqlite3.Row]:
    return conn.execute(
        f"SELECT * FROM alerts WHERE triage IS NULL AND status IN {_ACTIVE_SQL} ORDER BY id LIMIT ?", (limit,)
    ).fetchall()


def save_triage(conn: sqlite3.Connection, alert_id: int, triage: Triage, model: str,
                cost_usd: float | None, latency_ms: int) -> None:
    conn.execute(
        "UPDATE alerts SET triage = ?, model = ?, cost_usd = ?, latency_ms = ? WHERE id = ?",
        (triage.model_dump_json(), model, cost_usd, latency_ms, alert_id),
    )
    conn.commit()


def unnotified_alerts(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(f"SELECT * FROM alerts WHERE notified = 0 AND status IN {_ACTIVE_SQL} ORDER BY id").fetchall()


def mark_notified(conn: sqlite3.Connection, alert_id: int) -> None:
    conn.execute("UPDATE alerts SET notified = 1 WHERE id = ?", (alert_id,))
    conn.commit()


def get_state(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_state(conn: sqlite3.Connection, key: str, value: str, commit: bool = True) -> None:
    conn.execute("INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                 (key, value))
    if commit:
        conn.commit()
