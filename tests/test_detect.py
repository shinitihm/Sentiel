import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentiel import store
from sentiel.collectors import read_json, read_linux_auth
from sentiel.detect import detect, load_rules
from sentiel.models import Event

DEMO = Path(__file__).parent.parent / "sentiel" / "demo"
T0 = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def conn(tmp_path):
    return store.connect(tmp_path / "t.db")


@pytest.fixture(scope="module")
def rules():
    rules, warnings = load_rules()
    assert warnings == []
    return rules


def ev(minutes: float, source="windows", **fields) -> Event:
    return Event(ts=T0 + timedelta(minutes=minutes), source=source, host="h", fields=fields)


def test_golden_demo_detects_exactly_expected_rules(conn, rules):
    store.insert_events(conn, read_json(DEMO / "events.jsonl"))
    store.insert_events(conn, read_linux_auth(DEMO / "auth_log.txt", {}))
    expected = json.loads((DEMO / "expected.json").read_text())
    alerts = detect(conn, rules, since_id=0)
    assert sorted({a.rule_id for a in alerts}) == sorted(expected)


def test_detect_is_idempotent_across_rescans(conn, rules):
    store.insert_events(conn, read_json(DEMO / "events.jsonl"))
    first = store.insert_alerts(conn, detect(conn, rules, 0))
    again = store.insert_alerts(conn, detect(conn, rules, 0))
    assert first > 0 and again == 0


def test_incremental_scan_ignores_old_events(conn, rules):
    store.insert_events(conn, read_json(DEMO / "events.jsonl"))
    last = conn.execute("SELECT max(id) FROM logs").fetchone()[0]
    assert detect(conn, rules, since_id=last) == []


def test_bruteforce_threshold_9_vs_10(conn, rules):
    store.insert_events(conn, [ev(i * 0.1, EventID=4625, IpAddress="1.1.1.1") for i in range(9)])
    assert detect(conn, rules, 0) == []
    store.insert_events(conn, [ev(0.95, EventID=4625, IpAddress="1.1.1.1")])
    assert [a.rule_id for a in detect(conn, rules, 0)] == ["sentiel-bruteforce-windows"]


def test_bruteforce_spread_over_6_minutes_does_not_alert(conn, rules):
    store.insert_events(conn, [ev(i * 0.6, EventID=4625, IpAddress="1.1.1.1") for i in range(10)])
    assert detect(conn, rules, 0) == []


def test_bruteforce_split_between_ips_does_not_alert(conn, rules):
    store.insert_events(conn, [ev(i * 0.1, EventID=4625, IpAddress=f"1.1.1.{i % 2}") for i in range(10)])
    assert detect(conn, rules, 0) == []


def test_rule_with_field_no_event_has_is_skipped_without_error(conn, rules):
    store.insert_events(conn, [ev(0, EventID=1, Image="C:\\x.exe")])
    assert detect(conn, rules, 0) == []


def test_sigma_matching_is_case_insensitive(conn, rules):
    store.insert_events(
        conn, [ev(0, EventID=1, Image="C:\\WINDOWS\\POWERSHELL.EXE", CommandLine="powershell -ENC AAAA")])
    assert [a.rule_id for a in detect(conn, rules, 0)] == ["c1d3a684-f103-4ed2-bfa5-4ec0186d6b30"]


def test_windows_rule_does_not_fire_on_linux_source(conn, rules):
    store.insert_events(conn, [ev(0, source="linux", EventID=1102, Provider_Name="Microsoft-Windows-Eventlog")])
    assert detect(conn, rules, 0) == []
