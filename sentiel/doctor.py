"""`sentiel doctor`: diagnostics for new setups and for running `watch` as a service."""
import os
import sqlite3
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime

from . import store
from .collectors import WINDOWS_CHANNELS, read_windows
from .config import Config
from .detect import load_rules
from .triage import LLMUnavailable, call_llm


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    critical: bool = False


DB_BUSY_TIMEOUT_MS = 5000  # how long the write probe waits for another writer (e.g. a running watch)


def _age(seconds: float) -> str:
    s = int(seconds)
    if s < 120:
        return f"{s}s"
    if s < 7200:
        return f"{s // 60}m"
    return f"{s // 3600}h"


def _check_sources(cfg: Config) -> list[Check]:
    checks: list[Check] = []
    if cfg.sources.windows and sys.platform == "win32":
        for ch in WINDOWS_CHANNELS:
            stats: Counter = Counter()
            next(read_windows({}, stats, channels=(ch,)), None)
            denied = stats[f"denied:{ch}"]
            checks.append(Check(f"source:windows:{ch}", not denied, "run as administrator" if denied else "readable"))
    paths = ([cfg.sources.linux_auth] if cfg.sources.linux_auth else []) + list(cfg.sources.json_files)
    for path in paths:
        readable = os.access(path, os.R_OK)
        checks.append(Check(f"source:{path}", readable, "readable" if readable else "not readable"))
    return checks


def _check_notify(cfg: Config) -> Check:
    n = cfg.notify
    if n.get("telegram_bot_token") and n.get("telegram_chat_id"):
        return Check("notify", True, "Telegram configured")
    if n.get("discord_webhook"):
        return Check("notify", True, "Discord configured")
    return Check("notify", False, "no channel configured")


def _check_heartbeat(conn: sqlite3.Connection | None, cfg: Config) -> Check:
    if conn is None:
        return Check("heartbeat", False, "database unavailable")
    try:
        value = store.get_state(conn, "heartbeat")
    except sqlite3.Error as e:
        return Check("heartbeat", False, f"database unavailable: {e}")
    if not value:
        return Check("heartbeat", False, "scan/watch never ran")
    try:
        age = (datetime.now(UTC) - store.parse_ts(value)).total_seconds()
    except (ValueError, TypeError):
        return Check("heartbeat", False, "invalid heartbeat value")
    if age > 3 * cfg.interval:
        # a running watch can still be stuck in a cycle, so report what we know, not "not running"
        return Check("heartbeat", False, f"no completed cycle in {_age(age)}")
    return Check("heartbeat", True, f"last cycle {_age(age)} ago")


def run_checks(cfg: Config, ai: bool = True) -> list[Check]:
    checks: list[Check] = []
    conn: sqlite3.Connection | None = None
    try:
        try:
            conn = store.connect(cfg.db_path)
            conn.execute(f"PRAGMA busy_timeout = {int(DB_BUSY_TIMEOUT_MS)}")
            conn.execute("BEGIN IMMEDIATE")
            # BEGIN IMMEDIATE alone succeeds on a read-only file; a rolled-back write proves it is writable.
            conn.execute("INSERT OR REPLACE INTO state (key, value) VALUES ('doctor:probe', '1')")
            conn.rollback()
            checks.append(Check("database", True, str(cfg.db_path), critical=True))
        except sqlite3.Error as e:
            if isinstance(e, sqlite3.OperationalError) and "database is locked" in str(e):
                # another writer holds the lock: not a broken setup; keep conn so the heartbeat can still be read
                checks.append(Check("database", False, "busy: another process is writing (watch running?)"))
            else:
                checks.append(Check("database", False, str(e), critical=True))
                if conn is not None:
                    conn.close()
                    conn = None
        rules, warnings = load_rules()
        checks.append(Check("rules", len(rules) > 0, f"{len(rules)} loaded, {len(warnings)} skipped", critical=True))
        checks.extend(_check_sources(cfg))
        if ai:
            try:
                call_llm(cfg.model, [{"role": "user", "content": "ping"}], False, None, min(cfg.llm_timeout, 30))
                checks.append(Check("model", True, cfg.model))
            except LLMUnavailable as e:
                checks.append(Check("model", False, str(e)))
        checks.append(_check_notify(cfg))
        checks.append(_check_heartbeat(conn, cfg))
    finally:
        if conn is not None:
            conn.close()
    return checks
