import json
import sqlite3
from collections import Counter
from concurrent.futures import CancelledError, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

import httpx

from . import store
from .collectors import read_json, read_linux_auth, read_regex, read_windows
from .config import Config, Sources
from .detect import detect, rules_for
from .enrich import enrich_ips, public_ips
from .models import RANK, Alert, effective_severity, is_contested
from .notify import format_digest, format_message, send
from .triage import LLMUnavailable, triage_alert

DEMO_DIR = Path(__file__).parent / "demo"
MAX_NOTIFY_PER_CYCLE = 20
BACKOFF_BASE = 30  # seconds; doubles per consecutive LLM failure
BACKOFF_MAX = 1800


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
    for src in sources.files:
        jobs.append((f"file:{src.path}", lambda st, s=src: read_regex(s, st, stats)))
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


def _failure_count(conn: sqlite3.Connection) -> int:
    return int(store.get_state(conn, "llm_failures", "0"))


def _record_llm_failure(conn: sqlite3.Connection) -> datetime:
    try:
        failures = _failure_count(conn) + 1
    except ValueError:  # corrupt counter (`sentiel triage` skips scan's check): restart the backoff
        failures = 1
    retry_at = datetime.now(UTC) + timedelta(seconds=min(BACKOFF_BASE * 2 ** (failures - 1), BACKOFF_MAX))
    store.set_state(conn, "llm_failures", str(failures))
    store.set_state(conn, "llm_retry_at", store.fmt_ts(retry_at))
    return retry_at


def _clear_llm_failures(conn: sqlite3.Connection) -> None:
    store.set_state(conn, "llm_failures", "0")
    store.set_state(conn, "llm_retry_at", "")


def _backoff_until(conn: sqlite3.Connection) -> datetime | None:
    """End of the LLM backoff, or None. Corrupt state must not stop detection, notify or the heartbeat."""
    raw = store.get_state(conn, "llm_retry_at")
    try:
        _failure_count(conn)
        retry_at = store.parse_ts(raw) if raw else None
        if retry_at is not None and retry_at.utcoffset() is None:
            raise TypeError("naive llm_retry_at")
    except (ValueError, TypeError):
        _clear_llm_failures(conn)  # treat as no backoff
        return None
    return retry_at


def triage_pending(conn: sqlite3.Connection, cfg: Config, summary: ScanSummary, http: httpx.Client | None,
                    mock_response: str | list[str] | None) -> None:
    keys = cfg.keys
    jobs = []
    for row in store.pending_alerts(conn, cfg.max_triage_per_cycle):  # DB + enrichment stay on the main thread
        alert, _ = store.row_to_alert(row)
        events = store.get_events(conn, alert.event_ids[:20])
        enrichment = None
        if cfg.enrich:
            enrichment = enrich_ips(conn, public_ips(events), keys, http) or None
        jobs.append((alert, events, enrichment))
    done, failed = 0, False
    stop = Event()

    def run(alert, events, enrichment):
        if stop.is_set():
            raise CancelledError  # batch aborted before this job started
        try:
            return triage_alert(alert, events, enrichment, cfg.model, mock_response, cfg.llm_timeout)
        except BaseException:
            stop.set()  # a worker that dies must not pick up the next queued job before the main thread cancels
            raise

    with ThreadPoolExecutor(max_workers=cfg.triage_concurrency) as ex:
        futures = [ex.submit(run, alert, events, enrichment)
                   for alert, events, enrichment in jobs]
        try:
            for (alert, _, _), fut in zip(jobs, futures, strict=True):
                try:
                    res = fut.result()
                except CancelledError:
                    continue
                except LLMUnavailable as e:
                    if not failed:
                        failed = True
                        for f in futures:
                            f.cancel()
                        _record_llm_failure(conn)
                        summary.warnings.append(
                            f"AI model unavailable ({e}); alerts stay pending, retry with `sentiel triage`.")
                    continue
                if failed:
                    continue  # after the first failure nothing more is saved; the rest stays pending
                store.save_triage(conn, alert.id, res.triage, cfg.model, res.cost_usd, res.latency_ms)
                summary.triaged += 1
                done += 1
        except BaseException:
            stop.set()
            ex.shutdown(wait=False, cancel_futures=True)  # Ctrl+C/other errors: don't run the queued batch
            raise
    if done and not failed:
        _clear_llm_failures(conn)
    summary.pending = store.count_pending(conn)


def _notify(conn: sqlite3.Connection, cfg: Config, summary: ScanSummary, http: httpx.Client | None) -> None:
    sent, failed_channels = 0, set()
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
        if not delivered:
            return  # no channel configured: leave flags alone so alerts fire once a channel is set up
        if not any(delivered.values()):
            return  # every channel is failing: one attempt per cycle, retry next scan
        for name, ok in delivered.items():
            if not ok and name not in failed_channels:  # names only: token/webhook URL never reach the warning
                failed_channels.add(name)
                summary.warnings.append(f"notification channel {name} failed")
        store.mark_notified(conn, alert.id)  # at least one channel has it; resending would starve the working one
        summary.notified += 1
        sent += 1


def send_digest(conn: sqlite3.Connection, cfg: Config, http: httpx.Client | None = None,
                now: datetime | None = None) -> dict[str, bool]:
    """Send the last-24h summary; `{}` means no channel is configured. Never touches `digest_last`."""
    now = now or datetime.now().astimezone()
    stats = store.digest_stats(conn, (now - timedelta(hours=24)).astimezone(UTC))
    return send(cfg.notify, format_digest(stats), http)


def maybe_send_digest(conn: sqlite3.Connection, cfg: Config, http: httpx.Client | None = None,
                      now: datetime | None = None) -> bool:
    """Once per local day, from `digest_hour` on. Only a delivered digest is marked, so failures retry next cycle."""
    now = now or datetime.now().astimezone()
    today = now.date().isoformat()
    if cfg.digest_hour is None or now.hour < cfg.digest_hour or store.get_state(conn, "digest_last") == today:
        return False
    if not any(send_digest(conn, cfg, http, now).values()):
        return False
    store.set_state(conn, "digest_last", today)
    return True


def apply_suppressions(conn: sqlite3.Connection, cfg: Config, alerts: list[Alert]) -> None:
    """Mark alerts matched by a `[[suppress]]` entry. Runs inside scan's transaction; commits nothing.

    ponytail: only the first event of the alert is checked (a grouped burst is judged by its trigger).
    """
    by_rule: dict[str, list] = {}
    for s in cfg.suppress:
        by_rule.setdefault(s.rule_id, []).append(s)
    for a in alerts:
        if a.rule_id not in by_rule:
            continue
        events = store.get_events(conn, a.event_ids[:1])
        fields = events[0].get("fields", {}) if events else {}
        for s in by_rule[a.rule_id]:
            value = fields.get(s.field)
            if value is not None and str(value) == str(s.equals):
                a.status, a.note = "suppressed", s.reason
                break


def scan(conn: sqlite3.Connection, cfg: Config, *, ai: bool = True, http: httpx.Client | None = None,
         mock_response: str | list[str] | None = None) -> ScanSummary:
    summary = ScanSummary()
    ingest(conn, cfg.sources, summary)

    rules, warnings = rules_for(cfg)
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")  # cursor read under the write lock: a concurrent scan waits, then sees it moved
    try:  # alerts and the detection cursor commit together: a crash never replays (and double counts) a burst
        since = int(store.get_state(conn, "last_detected_log_id", "0"))
        new_alerts = detect(conn, rules, since, warnings)
        apply_suppressions(conn, cfg, new_alerts)
        last_id = conn.execute("SELECT coalesce(max(id), 0) FROM logs").fetchone()[0]
        summary.new_alerts = store.insert_alerts(conn, new_alerts, timedelta(seconds=cfg.group_window), commit=False)
        store.set_state(conn, "last_detected_log_id", str(last_id), commit=False)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    if warnings:
        summary.warnings.append(f"{len(warnings)} rule warnings (see `sentiel rules list --skipped`)")

    retry_at = None
    if ai:
        retry_at = _backoff_until(conn)
    if ai and not (retry_at and datetime.now(UTC) < retry_at):
        try:  # outside the detection transaction; a triage bug must not skip notify and heartbeat
            triage_pending(conn, cfg, summary, http, mock_response)
        except Exception as e:
            summary.warnings.append(f"triage failed: {e}")
            summary.pending = store.count_pending(conn)
    else:
        if ai:
            summary.warnings.append(f"AI paused after failures; next attempt at {retry_at:%H:%M:%S} UTC. "
                                    "Run `sentiel triage` to retry now.")
        summary.pending = store.count_pending(conn)
    _notify(conn, cfg, summary, http)
    store.set_state(conn, "heartbeat", store.fmt_ts(datetime.now(UTC)))
    return summary


def demo_config(cfg: Config) -> Config:
    sources = Sources(windows=False, linux_auth=str(DEMO_DIR / "auth_log.txt"), json=[str(DEMO_DIR / "events.jsonl")])
    return cfg.model_copy(update={"sources": sources, "enrich": False, "notify": {},
                                     "group_window": 0, "suppress": [], "digest_hour": None})
