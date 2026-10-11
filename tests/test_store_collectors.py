from collections import Counter
from datetime import UTC, datetime

from sentiel import store
from sentiel.collectors import parse_auth_line, parse_event_xml, read_json, read_linux_auth
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
