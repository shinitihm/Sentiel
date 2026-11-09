import json
import time
from collections import Counter
from datetime import UTC, date, datetime, timedelta

import pytest

from sentiel import collectors, store
from sentiel.collectors import parse_auth_line, parse_event_xml, read_json, read_linux_auth, read_regex
from sentiel.config import FileSource
from sentiel.models import Alert, Event, Triage, effective_severity, is_contested

T0 = datetime(2026, 1, 1, tzinfo=UTC)

XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>
<TimeCreated SystemTime="2026-10-09T08:00:01.1234567Z"/><EventRecordID>77</EventRecordID>
<Channel>Security</Channel><Computer>PC1</Computer></System>
<EventData><Data Name="TargetUserName">bob</Data><Data Name="IpAddress">9.9.9.9</Data>
<Data Name="LogonType">3</Data></EventData></Event>"""


def test_insert_dedupes_and_adds_columns(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    e = Event(ts=T0, source="json", host="h", fields={"A": 1})
    assert store.insert_events(conn, [e]) == 1
    assert store.insert_events(conn, [e]) == 0
    store.insert_events(conn, [Event(ts=T0, source="json", host="h", fields={"A": 1, "NewField": "x"})])
    assert "newfield" in store._columns(conn)


def test_hostile_field_names_are_quoted_not_injected(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    store.insert_events(conn, [Event(ts=T0, source="json", host="h", fields={'a" INTEGER); DROP TABLE logs;--': 1})])
    assert conn.execute("SELECT count(*) FROM logs").fetchone()[0] == 1


def test_field_names_clashing_with_columns_or_case_are_dropped(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    store.insert_events(conn, [Event(ts=T0, source="json", host="h", fields={"Host": "evil", "id": 5, "x": 1, "X": 2})])
    row = conn.execute("SELECT id, host FROM logs").fetchone()
    assert row["host"] == "h" and row["id"] == 1


def test_parse_windows_xml():
    e = parse_event_xml(XML)
    assert e.source == "windows" and e.host == "PC1"
    assert e.fields["EventID"] == 4625 and e.fields["IpAddress"] == "9.9.9.9" and e.fields["LogonType"] == 3


def test_parse_auth_lines():
    e = parse_auth_line(
        "2026-10-09T08:00:00+00:00 h sshd[1]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2")
    assert e.fields["event"] == "ssh_failed" and e.fields["IpAddress"] == "1.2.3.4" and e.fields["User"] == "bob"
    e = parse_auth_line("Oct  9 08:00:00 h sudo: bob : 3 incorrect password attempts ; TTY=pts/0 ; COMMAND=/bin/ls")
    assert e.fields["event"] == "sudo_failed" and e.fields["User"] == "bob"
    e = parse_auth_line("Oct  9 08:00:00 h useradd[5]: new user: name=evil, UID=1001, GID=1001")
    assert e.fields["event"] == "useradd" and e.fields["TargetUserName"] == "evil"
    assert parse_auth_line("garbage") is None


SSH = " h sshd[1]: Accepted password for bob from 1.2.3.4 port 22 ssh2"


def test_bsd_date_after_today_belongs_to_last_year():
    e = parse_auth_line("Dec 30 12:00:00" + SSH, now=datetime(2027, 1, 2, 10, 0))
    assert e.ts.astimezone().date() == date(2026, 12, 30)


def test_bsd_recent_date_keeps_current_year():
    e = parse_auth_line("Jan  1 12:00:00" + SSH, now=datetime(2027, 1, 2, 10, 0))
    assert (e.ts.astimezone().year, e.ts.astimezone().month) == (2027, 1)


def test_bsd_up_to_one_day_ahead_is_clock_skew_not_last_year():
    e = parse_auth_line("Oct 12 12:00:00" + SSH, now=datetime(2026, 10, 11, 23, 0))
    assert e.ts.astimezone().year == 2026


def test_bsd_feb_29_read_in_non_leap_year_uses_last_leap_year():
    e = parse_auth_line("Feb 29 12:00:00" + SSH, now=datetime(2025, 1, 15, 10, 0))
    assert e.ts.astimezone().date() == date(2024, 2, 29)


def test_linux_collector_offsets_and_partial_lines(tmp_path):
    p = tmp_path / "auth.log"
    line = "2026-10-09T08:00:00+00:00 h sshd[1]: Accepted password for bob from 1.2.3.4 port 22 ssh2\n"
    p.write_bytes((line + line[:30]).encode())
    state: dict = {}
    assert len(list(read_linux_auth(p, state))) == 1
    p.write_bytes((line + line).encode())
    assert len(list(read_linux_auth(p, state))) == 1  # only the newly completed line
    p.write_bytes(b"x\n")  # rotated: smaller than the offset
    stats = Counter()
    list(read_linux_auth(p, state, stats))
    assert state["offset"] == 2 and stats["skipped"] == 1


def test_iso_timestamp_with_invalid_date_is_unparseable():
    assert parse_auth_line("2026-13-45T00:00:00 h sshd[1]: x") is None


def test_linux_collector_survives_invalid_iso_timestamp(tmp_path):
    p = tmp_path / "auth.log"
    bad = "2026-13-45T00:00:00 h sshd[1]: x\n"
    good = "2026-10-09T08:00:00+00:00 h sshd[1]: Failed password for bob from 1.2.3.4 port 22 ssh2\n"
    p.write_bytes((bad + good).encode())
    state: dict = {}
    stats = Counter()
    assert len(list(read_linux_auth(p, state, stats))) == 1
    assert stats["skipped"] == 1 and state["offset"] == p.stat().st_size


def test_json_collector_skips_garbage_and_flattens(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text('{"ts": "2026-01-01T00:00:00Z", "host": "h", "a": {"b": 1}, "big": 99999999999999999999}\n'
                 'not json\n[1,2]\n{"ts": "not a date"}\n', encoding="utf-8")
    stats = Counter()
    events = list(read_json(p, stats))
    assert len(events) == 1 and stats["skipped"] == 3
    assert events[0].fields["a.b"] == 1 and events[0].fields["big"] == "99999999999999999999"


def test_alert_roundtrip_and_pending(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    a = Alert(rule_id="r", rule_title="t", sigma_level="high", mitre=["T1"], ts=T0, event_ids=[1, 2])
    assert store.insert_alerts(conn, [a, a]) == 1
    row = store.pending_alerts(conn, 10)[0]
    alert, triage = store.row_to_alert(row)
    assert alert.event_ids == [1, 2] and triage is None


def test_effective_severity_never_lowers_and_flags_contested():
    benign = Triage(severity="info", verdict="benign", mitre_techniques=[], summary="", next_steps=[])
    assert effective_severity("high", benign) == "high"
    assert is_contested("high", benign) and not is_contested("medium", benign)
    worse = Triage(severity="critical", verdict="true_positive", mitre_techniques=[], summary="", next_steps=[])
    assert effective_severity("low", worse) == "critical"
    assert effective_severity("informational", None) == "info"


NGINX = r'^(?P<IpAddress>\S+) \S+ \S+ \[[^\]]+\] "(?P<Method>\w+) (?P<Url>\S+)'


def test_regex_source_turns_named_groups_into_fields(tmp_path):
    p = tmp_path / "access.log"
    p.write_text('1.2.3.4 - - [11/Oct/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 403\ngarbage\n', encoding="utf-8")
    stats, state = Counter(), {}
    evs = list(read_regex(FileSource(path=str(p), regex=NGINX, product="linux"), state, stats))
    assert len(evs) == 1 and stats["skipped"] == 1
    e = evs[0]
    assert e.source == "linux" and e.fields["IpAddress"] == "1.2.3.4" and e.fields["Url"] == "/admin"
    assert e.fields["message"].startswith("1.2.3.4") and state["offset"] == p.stat().st_size


def test_regex_source_resumes_from_offset_and_resets_on_rotation(tmp_path):
    p = tmp_path / "a.log"
    src = FileSource(path=str(p), regex=r"(?P<User>\w+)")
    p.write_text("alice\n", encoding="utf-8")
    state = {}
    assert [e.fields["User"] for e in read_regex(src, state)] == ["alice"]
    with open(p, "a", encoding="utf-8") as f:
        f.write("bob\n")
    assert [e.fields["User"] for e in read_regex(src, state)] == ["bob"]
    p.write_text("eve\n", encoding="utf-8")  # rotated: smaller than the offset
    assert [e.fields["User"] for e in read_regex(src, state)] == ["eve"]


def test_regex_ts_and_host_groups_are_used(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("2026-10-11T10:00:00+00:00 web1 hi\n", encoding="utf-8")
    e = next(read_regex(FileSource(path=str(p), regex=r"^(?P<ts>\S+) (?P<host>\S+) (?P<Word>\w+)"), {}))
    assert (e.ts.year, e.host, e.fields["Word"]) == (2026, "web1", "hi") and "ts" not in e.fields


def test_regex_bad_ts_skips_line_and_naive_ts_gets_a_zone(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("nope x\n2026-10-11T10:00:00 y\n", encoding="utf-8")
    stats = Counter()
    evs = list(read_regex(FileSource(path=str(p), regex=r"^(?P<ts>\S+) (?P<W>\w+)"), {}, stats))
    assert stats["skipped"] == 1 and len(evs) == 1 and evs[0].ts.tzinfo is not None


@pytest.mark.parametrize("regex, msg", [("(", "invalid regex"), (r"\S+", "named group")])
def test_bad_regex_is_a_config_error(regex, msg):
    with pytest.raises(ValueError, match=msg):
        FileSource(path="x", regex=regex)


@pytest.mark.parametrize("bad", ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00", "0001-01-01T00:00:00"])
def test_regex_out_of_range_ts_is_skipped_not_fatal(tmp_path, bad):
    p = tmp_path / "a.log"
    p.write_text(f"{bad} x\n2026-10-11T10:00:00+00:00 y\n", encoding="utf-8")
    stats = Counter()
    evs = list(read_regex(FileSource(path=str(p), regex=r"^(?P<ts>\S+) (?P<W>\w+)"), {}, stats))
    assert stats["skipped"] == 1 and [e.fields["W"] for e in evs] == ["y"]


def test_auth_line_with_out_of_range_iso_ts_is_none():
    assert parse_auth_line("0001-01-01T00:00:00+05:00 host sshd[1]: hi") is None


def test_json_out_of_range_ts_is_skipped(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text('{"ts": "0001-01-01T00:00:00+05:00", "a": 1}\n', encoding="utf-8")
    stats = Counter()
    assert list(read_json(p, stats)) == [] and stats["skipped"] == 1


def test_file_bigger_than_the_read_cap_is_consumed_over_several_calls(tmp_path, monkeypatch):
    monkeypatch.setattr(collectors, "MAX_READ", 16)
    p = tmp_path / "a.log"
    words = [f"w{i:02d}" * (1 + i % 3) for i in range(20)]
    p.write_text("".join(w + "\n" for w in words), encoding="utf-8")
    src, state, got = FileSource(path=str(p), regex=r"(?P<W>\w+)"), {}, []
    for _ in range(100):
        batch = [e.fields["W"] for e in read_regex(src, state)]
        assert len(batch) <= 16
        got += batch
        if state["offset"] == p.stat().st_size:
            break
    assert got == words


def test_line_longer_than_the_read_cap_still_advances_and_counts_a_skip(tmp_path, monkeypatch):
    monkeypatch.setattr(collectors, "MAX_READ", 16)
    p = tmp_path / "auth.log"
    p.write_bytes(b"x" * 40)  # no newline at all
    state, stats = {}, Counter()
    assert list(read_linux_auth(p, state, stats)) == []
    assert state["offset"] == 16 and stats["skipped"] == 1


def test_only_newline_splits_lines_so_attacker_cannot_forge_events(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes("user=eve\x0buser=root\u2028user=admin\n".encode())
    evs = list(read_regex(FileSource(path=str(p), regex=r"^user=(?P<User>\w+)"), {}))
    assert [e.fields["User"] for e in evs] == ["eve"]


V03_SCHEMA = """
CREATE TABLE logs (
    id INTEGER PRIMARY KEY, ts TEXT NOT NULL, source TEXT NOT NULL, host TEXT,
    hash TEXT UNIQUE NOT NULL, raw TEXT NOT NULL);
CREATE INDEX logs_ts ON logs(ts);
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY, rule_id TEXT NOT NULL, rule_title TEXT NOT NULL, sigma_level TEXT NOT NULL,
    mitre TEXT NOT NULL, ts TEXT NOT NULL, event_ids TEXT NOT NULL, first_event_id INTEGER NOT NULL,
    triage TEXT, model TEXT, cost_usd REAL, latency_ms INTEGER, notified INTEGER NOT NULL DEFAULT 0,
    UNIQUE(rule_id, first_event_id));
CREATE TABLE ip_cache (ip TEXT PRIMARY KEY, data TEXT NOT NULL, fetched_at TEXT NOT NULL);
CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
NEW_ALERT_COLS = {"status", "note", "count", "last_ts", "host", "group_key"}


def v03_db(path):
    import sqlite3

    c = sqlite3.connect(path)
    c.executescript(V03_SCHEMA)
    c.execute(
        "INSERT INTO logs (id, ts, source, host, hash, raw) "
        "VALUES (1, '2026-01-01T00:00:00.000000Z', 'json', 'h1', 'x', '{}')"
    )
    c.execute(
        "INSERT INTO alerts (rule_id, rule_title, sigma_level, mitre, ts, event_ids, first_event_id) "
        "VALUES ('r', 't', 'high', '[]', '2026-01-01T00:00:00.000000Z', '[1,2,3]', 1)"
    )
    c.commit()
    c.close()


def _version(path) -> int:
    import sqlite3

    c = sqlite3.connect(path)
    try:
        return c.execute("PRAGMA user_version").fetchone()[0]
    finally:
        c.close()


def _alert_cols(path) -> set[str]:
    import sqlite3

    c = sqlite3.connect(path)
    try:
        return {r[1] for r in c.execute("PRAGMA table_info(alerts)")}
    finally:
        c.close()


def test_migrate_v03_db_keeps_data_and_backfills(tmp_path):
    p = tmp_path / "old.db"
    v03_db(p)
    conn = store.connect(p)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == len(store.MIGRATIONS)
    row = conn.execute("SELECT * FROM alerts").fetchone()
    assert (row["status"], row["count"], row["host"], row["last_ts"]) == ("open", 3, "h1", row["ts"])
    assert row["note"] is None and row["group_key"] is None
    assert conn.execute("SELECT count(*) FROM logs").fetchone()[0] == 1
    alert, _ = store.row_to_alert(row)
    assert (alert.status, alert.count, alert.host, alert.last_ts) == ("open", 3, "h1", alert.ts)


def test_migrate_is_idempotent(tmp_path):
    p = tmp_path / "old.db"
    v03_db(p)
    store.connect(p).close()
    store.connect(p).close()
    assert _version(p) == len(store.MIGRATIONS)


def test_fresh_db_has_current_version_and_columns(tmp_path):
    p = tmp_path / "new.db"
    store.connect(p).close()
    assert _version(p) == len(store.MIGRATIONS)
    assert NEW_ALERT_COLS <= _alert_cols(p)


def test_schema_newer_than_code_is_refused(tmp_path):
    import sqlite3

    p = tmp_path / "future.db"
    c = sqlite3.connect(p)
    c.execute("PRAGMA user_version = 99")
    c.close()
    with pytest.raises(store.SchemaTooNew, match="v99 is newer than this Sentiel"):
        store.connect(p)
    assert _version(p) == 99


def test_migration_failure_rolls_back(tmp_path, monkeypatch):
    import sqlite3

    bad = ("ALTER TABLE alerts ADD COLUMN zzz TEXT", "ALTER TABLE nope ADD COLUMN x")
    monkeypatch.setattr(store, "MIGRATIONS", (bad,))
    p = tmp_path / "bad.db"
    with pytest.raises(sqlite3.OperationalError):
        store.connect(p)
    assert _version(p) == 0
    assert "zzz" not in _alert_cols(p)


def _mk_alert(conn, n, status="open"):
    a = Alert(rule_id=f"r{n}", rule_title=f"t{n}", sigma_level="high", mitre=[], ts=T0, event_ids=[n])
    store.insert_alerts(conn, [a])
    row = conn.execute("SELECT id FROM alerts WHERE rule_id = ?", (f"r{n}",)).fetchone()
    conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, row["id"]))
    conn.commit()
    return row["id"]


def test_set_status_roundtrip_and_note_kept(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    aid = _mk_alert(conn, 1)
    assert store.set_status(conn, aid, "ack", "x") is True
    assert store.set_status(conn, aid, "closed", None) is True
    row = store.get_alert(conn, aid)
    assert row["status"] == "closed" and row["note"] == "x"


def test_set_status_rejects_invalid_and_suppressed(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    aid = _mk_alert(conn, 1)
    for bad in ("nope", "suppressed"):
        with pytest.raises(ValueError):
            store.set_status(conn, aid, bad, None)
    assert store.set_status(conn, 999, "ack", None) is False
    assert store.get_alert(conn, aid)["status"] == "open"


def test_inactive_alerts_are_never_pending_or_unnotified(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    for i, st in enumerate(("closed", "false_positive", "suppressed"), start=1):
        _mk_alert(conn, i, st)
    active = _mk_alert(conn, 4, "ack")
    assert [r["id"] for r in store.pending_alerts(conn, 10)] == [active]
    assert [r["id"] for r in store.unnotified_alerts(conn)] == [active]
    assert store.count_pending(conn) == 1


def test_list_alerts_default_hides_closed_all_shows(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    for i, st in enumerate(("open", "ack", "closed", "false_positive", "suppressed"), start=1):
        _mk_alert(conn, i, st)
    assert {r["status"] for r in store.list_alerts(conn)} == {"open", "ack"}
    assert len(store.list_alerts(conn, include_all=True)) == 5


# ---------- grouping (v0.4) ----------

HOUR = timedelta(hours=1)


def _ids(conn, n, host="h"):
    store.insert_events(conn, [Event(ts=T0 + timedelta(seconds=i), source="json", host=host, fields={"i": i})
                               for i in range(n)])
    return [r["id"] for r in conn.execute("SELECT id FROM logs WHERE host = ? ORDER BY id", (host,))]


def _ga(eid, ts=T0, rule="r", key=None, status="open", count=1, ids=None):
    return Alert(rule_id=rule, rule_title="t", sigma_level="high", mitre=[], ts=ts, event_ids=ids or [eid],
                 group_key=key, status=status, count=count)


def _rows(conn):
    return conn.execute("SELECT * FROM alerts ORDER BY id").fetchall()


def test_insert_alerts_merges_same_rule_host_within_window(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    e = _ids(conn, 3)
    alerts = [_ga(e[i], T0 + timedelta(minutes=i * 10)) for i in range(3)]
    assert store.insert_alerts(conn, alerts, HOUR) == 1
    (row,) = _rows(conn)
    assert row["count"] == 3 and json.loads(row["event_ids"]) == e and row["host"] == "h"
    assert row["last_ts"] == store.fmt_ts(T0 + timedelta(minutes=20))
    conn2 = store.connect(tmp_path / "u.db")
    e2 = _ids(conn2, 3)
    assert store.insert_alerts(conn2, [_ga(e2[i], T0 + timedelta(minutes=i * 10)) for i in range(3)]) == 3
    assert len(_rows(conn2)) == 3


def test_merge_respects_window_host_and_key(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    e, o = _ids(conn, 4), _ids(conn, 1, host="other")
    far = T0 + timedelta(hours=2)
    store.insert_alerts(conn, [_ga(e[0]), _ga(e[1], far), _ga(o[0]), _ga(e[2], key="k1"), _ga(e[3], key="k2")], HOUR)
    assert len(_rows(conn)) == 5


def test_merge_only_between_same_status(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    e = _ids(conn, 8)
    store.insert_alerts(conn, [_ga(e[0], status="suppressed")], HOUR)
    store.insert_alerts(conn, [_ga(e[1])], HOUR)
    assert [r["status"] for r in _rows(conn)] == ["suppressed", "open"]
    store.insert_alerts(conn, [_ga(e[2], status="suppressed")], HOUR)
    assert [(r["status"], r["count"]) for r in _rows(conn)] == [("suppressed", 2), ("open", 1)]
    for st in ("ack", "closed", "false_positive"):
        c = store.connect(tmp_path / f"{st}.db")
        ids = _ids(c, 2)
        store.insert_alerts(c, [_ga(ids[0])], HOUR)
        c.execute("UPDATE alerts SET status = ?", (st,))
        c.commit()
        store.insert_alerts(c, [_ga(ids[1])], HOUR)
        assert [(r["status"], r["count"]) for r in _rows(c)] == [(st, 1), ("open", 1)]


def test_merge_caps_event_ids_at_50(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    e = _ids(conn, 120)
    assert store.insert_alerts(conn, [_ga(i) for i in e], HOUR) == 1
    (row,) = _rows(conn)
    assert row["count"] == 120 and json.loads(row["event_ids"]) == e[:50]


def test_redetected_correlation_refreshes_count(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    e = _ids(conn, 12)
    store.insert_alerts(conn, [_ga(e[0], ids=e[:5], count=5)], HOUR)
    a = _ga(e[0], ids=e[:10], count=10)
    a.fresh = 5
    assert store.insert_alerts(conn, [a], HOUR) == 0
    (row,) = _rows(conn)
    assert row["count"] == 10 and json.loads(row["event_ids"]) == e[:10]


def test_merge_burst_of_5000_is_fast_and_single_row(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    e = _ids(conn, 5000)
    start = time.monotonic()
    assert store.insert_alerts(conn, [_ga(i, T0 + timedelta(milliseconds=i)) for i in e], HOUR) == 1
    assert time.monotonic() - start < 5
    (row,) = _rows(conn)
    assert row["count"] == 5000 and len(json.loads(row["event_ids"])) <= 50


def test_extreme_timestamp_does_not_overflow(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    e = _ids(conn, 1)
    store.insert_alerts(conn, [_ga(e[0], datetime(1, 1, 1, tzinfo=UTC))], HOUR)
    assert len(_rows(conn)) == 1


def test_old_event_does_not_merge_into_todays_alert(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    e = _ids(conn, 2)
    store.insert_alerts(conn, [_ga(e[0])], HOUR)
    store.insert_alerts(conn, [_ga(e[1], T0 - timedelta(days=365))], HOUR)
    assert len(_rows(conn)) == 2


def test_exception_mid_insert_rolls_back_everything(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    e = _ids(conn, 2)

    def gen():
        yield _ga(e[0], rule="a")
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        store.insert_alerts(conn, gen(), HOUR)
    assert _rows(conn) == []
    conn.rollback()
    assert store.connect(tmp_path / "t.db").execute("SELECT count(*) FROM alerts").fetchone()[0] == 0


def _triage(sev, verdict="true_positive"):
    return Triage(severity=sev, verdict=verdict, mitre_techniques=[], summary="s", next_steps=[])


def test_digest_stats_counts_and_excludes_suppressed(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    ids = {}
    for n, (level, count) in enumerate([("medium", 5), ("high", 2), ("high", 1), ("low", 1), ("low", 9)], start=1):
        a = Alert(rule_id=f"r{n}", rule_title=f"t{n}", sigma_level=level, mitre=[], ts=T0, event_ids=[n], count=count)
        store.insert_alerts(conn, [a])
        ids[n] = conn.execute("SELECT id FROM alerts WHERE rule_id = ?", (f"r{n}",)).fetchone()["id"]
    store.save_triage(conn, ids[1], _triage("critical"), "m", None, 1)  # medium raised by the AI -> critical
    store.save_triage(conn, ids[2], _triage("info", "benign"), "m", None, 1)  # high stays high, contested
    conn.execute("UPDATE alerts SET triage = '{broken' WHERE id = ?", (ids[3],))  # bad triage must not break it
    conn.execute("UPDATE alerts SET status = 'suppressed' WHERE id = ?", (ids[5],))
    conn.commit()
    s = store.digest_stats(conn, T0 - timedelta(hours=1))
    assert s["by_severity"] == {"critical": 1, "high": 2, "low": 1}
    assert s["contested"] == 1 and s["suppressed"] == 9
    assert s["pending"] == store.count_pending(conn)
    assert s["top_rules"][0] == ("t1", 5)
    assert store.digest_stats(conn, T0 + timedelta(hours=1))["by_severity"] == {}
    for n in range(6, 12):
        store.insert_alerts(conn, [Alert(rule_id=f"x{n}", rule_title=f"u{n}", sigma_level="low", mitre=[], ts=T0,
                                         event_ids=[n + 50])])
    assert len(store.digest_stats(conn, T0 - timedelta(hours=1))["top_rules"]) == 5


def test_ingest_ignores_missing_channel_stats(tmp_path, monkeypatch):
    from sentiel import pipeline
    from sentiel.config import Sources

    def fake(state, stats=None):
        stats["missing:Sysmon"] += 1
        return iter(())

    monkeypatch.setattr(pipeline, "read_windows", fake)
    conn = store.connect(tmp_path / "s.db")
    s = pipeline.ScanSummary()
    pipeline.ingest(conn, Sources(windows=True), s)
    assert s.warnings == []


@pytest.mark.parametrize(("winerror", "key"), [(15007, "missing:Sysmon"), (5, "denied:Sysmon"), (1722, None)])
def test_read_windows_classifies_only_known_evtquery_errors(monkeypatch, winerror, key):
    import sys
    import types
    from collections import Counter

    pywintypes = pytest.importorskip("pywintypes")

    def evt_query(*a):
        raise pywintypes.error(winerror, "EvtQuery", "boom")

    fake = types.SimpleNamespace(EvtQuery=evt_query, EvtQueryForwardDirection=1)
    monkeypatch.setitem(sys.modules, "win32evtlog", fake)
    monkeypatch.setattr(sys, "platform", "win32")
    stats = Counter()
    assert list(collectors.read_windows({}, stats, channels=("Sysmon",))) == []
    assert dict(stats) == ({key: 1} if key else {})


def test_ensure_column_is_idempotent(tmp_path):
    conn = store.connect(tmp_path / "s.db")
    store.ensure_column(conn, "program")
    store.ensure_column(conn, "program")
    names = [r[1].lower() for r in conn.execute("PRAGMA table_info(logs)")]
    assert names.count("program") == 1


def test_ensure_column_tolerates_column_added_by_other_connection(tmp_path):
    path = tmp_path / "s.db"
    a = store.connect(path)
    b = store.connect(path)
    store.ensure_column(a, "program")
    a.commit()
    store.ensure_column(b, "program")  # must not raise duplicate column name


def test_ensure_column_still_raises_other_errors(tmp_path):
    import sqlite3

    conn = store.connect(tmp_path / "s.db")
    conn.close()
    with pytest.raises(sqlite3.ProgrammingError):
        store.ensure_column(conn, "program")
