import json
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from . import store
from .collectors import read_json, read_linux_auth, read_windows
from .config import Config, Sources
from .detect import detect, load_rules
from .enrich import enrich_ips, public_ips
from .models import RANK, effective_severity, is_contested
from .notify import format_message, send
from .triage import LLMUnavailable, triage_alert

DEMO_DIR = Path(__file__).parent / "demo"
MAX_NOTIFY_PER_CYCLE = 20


@dataclass
class ScanSummary:
    new_events: int = 0
    skipped_lines: int = 0
    new_alerts: int = 0
    triaged: int = 0
    pending: int = 0
    notified: int = 0
    warnings: list[str] = field(default_factory=list)


def _load_state(conn: sqlite3.Connection, key: str) -> dict:
    return json.loads(store.get_state(conn, key, "{}"))


def ingest(conn: sqlite3.Connection, sources: Sources, summary: ScanSummary) -> None:
    stats: Counter = Counter()
    jobs = []
    if sources.windows:
        jobs.append(("windows", lambda st: read_windows(st, stats)))
    if sources.linux_auth:
        jobs.append((f"linux:{sources.linux_auth}", lambda st, p=sources.linux_auth: read_linux_auth(p, st, stats)))
    for path in sources.json_files:
        jobs.append((f"json:{path}", lambda st, p=path: read_json(p, stats)))
    for key, make in jobs:
        state = _load_state(conn, f"src:{key}")
        try:
            summary.new_events += store.insert_events(conn, make(state))
        except OSError as e:
            summary.warnings.append(f"{key}: {e.strerror or e}")
            continue
        store.set_state(conn, f"src:{key}", json.dumps(state))
    summary.skipped_lines += stats["skipped"]
    for k in stats:
        if k.startswith("denied:"):
            summary.warnings.append(f"No permission to read the {k[7:]} event log (run as administrator).")


def triage_pending(conn: sqlite3.Connection, cfg: Config, summary: ScanSummary, http: httpx.Client | None,
                    mock_response: str | list[str] | None) -> None:
    keys = cfg.keys
    for row in store.pending_alerts(conn, cfg.max_triage_per_cycle):
        alert, _ = store.row_to_alert(row)
        events = store.get_events(conn, alert.event_ids[:20])
        enrichment = None
        if cfg.enrich:
            enrichment = enrich_ips(conn, public_ips(events), keys, http) or None
        try:
            res = triage_alert(alert, events, enrichment, cfg.model, mock_response, cfg.llm_timeout)
        except LLMUnavailable as e:
            summary.warnings.append(f"AI model unavailable ({e}); alerts stay pending, retry with `sentiel triage`.")
            break
        store.save_triage(conn, alert.id, res.triage, cfg.model, res.cost_usd, res.latency_ms)
        summary.triaged += 1
    summary.pending = conn.execute("SELECT count(*) FROM alerts WHERE triage IS NULL").fetchone()[0]


def _notify(conn: sqlite3.Connection, cfg: Config, summary: ScanSummary, http: httpx.Client | None) -> None:
    sent = 0
    for row in store.unnotified_alerts(conn):
        alert, triage = store.row_to_alert(row)
        severity = effective_severity(alert.sigma_level, triage)
        if RANK[severity] < RANK[cfg.notify_min_severity]:
            store.mark_notified(conn, alert.id)  # below threshold: nothing to send, don't re-check forever
            continue
        if sent >= MAX_NOTIFY_PER_CYCLE:
            break
        events = store.get_events(conn, alert.event_ids[:1])
        host = events[0]["host"] if events else "unknown"
        text = format_message(alert, triage, severity, host, is_contested(alert.sigma_level, triage))
        delivered = send(cfg.notify, text, http)
        if delivered is None:
            return  # no channel configured: leave flags alone so alerts fire once a channel is set up
        if delivered:
            store.mark_notified(conn, alert.id)
            summary.notified += 1
        sent += 1


def scan(conn: sqlite3.Connection, cfg: Config, *, ai: bool = True, http: httpx.Client | None = None,
         mock_response: str | list[str] | None = None) -> ScanSummary:
    summary = ScanSummary()
    ingest(conn, cfg.sources, summary)

    rules, warnings = load_rules()
    summary.warnings += [f"rule skipped: {w}" for w in warnings]
    since = int(store.get_state(conn, "last_detected_log_id", "0"))
    summary.new_alerts = store.insert_alerts(conn, detect(conn, rules, since))
    last_id = conn.execute("SELECT coalesce(max(id), 0) FROM logs").fetchone()[0]
    store.set_state(conn, "last_detected_log_id", str(last_id))

    if ai:
        triage_pending(conn, cfg, summary, http, mock_response)
    else:
        summary.pending = conn.execute("SELECT count(*) FROM alerts WHERE triage IS NULL").fetchone()[0]
    _notify(conn, cfg, summary, http)
    return summary


def demo_config(cfg: Config) -> Config:
    sources = Sources(windows=False, linux_auth=str(DEMO_DIR / "auth_log.txt"), json=[str(DEMO_DIR / "events.jsonl")])
    return cfg.model_copy(update={"sources": sources, "enrich": False, "notify": {}})
