import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import sentiel.detect as detect_mod
from sentiel import store
from sentiel.collectors import read_json, read_linux_auth
from sentiel.config import Config
from sentiel.detect import RULES_DIR, Correlation, Rule, detect, load_rules, rules_for
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


def _spy_parses(monkeypatch):
    calls = []
    real = detect_mod.SigmaCollection.from_yaml
    monkeypatch.setattr(detect_mod.SigmaCollection, "from_yaml", lambda y, **kw: calls.append(1) or real(y, **kw))
    return calls


def test_rules_are_converted_once_while_files_are_unchanged(tmp_path, monkeypatch):
    d = shutil.copytree(RULES_DIR, tmp_path / "rules")
    calls = _spy_parses(monkeypatch)
    first, _ = load_rules(d)
    n = len(calls)
    second, _ = load_rules(d)
    assert len(calls) == n and [r.id for r in first] == [r.id for r in second]


def test_edited_added_or_removed_rule_file_is_picked_up(tmp_path, monkeypatch):
    d = shutil.copytree(RULES_DIR, tmp_path / "rules")
    base = len(load_rules(d)[0])
    victim = sorted(d.rglob("*.yml"))[0]
    st = victim.stat()
    os.utime(victim, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    calls = _spy_parses(monkeypatch)
    load_rules(d)
    assert len(calls) > 0  # edit invalidates
    victim.unlink()
    assert len(load_rules(d)[0]) == base - 1  # removal invalidates


def test_returned_lists_are_safe_to_mutate(tmp_path):
    d = shutil.copytree(RULES_DIR, tmp_path / "rules")
    rules, warnings = load_rules(d)
    rules.clear()
    warnings.append("x")
    again, w2 = load_rules(d)
    assert again and "x" not in w2


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


TWO_FILES_BASE = """title: Base
id: 11111111-1111-4111-8111-111111111111
name: base_rule
logsource: {product: windows}
detection: {selection: {EventID: 4625}, condition: selection}
level: informational
"""
TWO_FILES_CORR = """title: Cross-file correlation
id: 22222222-2222-4222-8222-222222222222
name: cross-file
correlation: {type: event_count, rules: [base_rule], group-by: [IpAddress], timespan: 2m, condition: {gte: 3}}
level: medium
"""


def test_builtin_bruteforce_correlations_load_from_yaml(rules):
    corr = {r.id: r for r in rules if isinstance(r, Correlation)}
    ssh = corr["sentiel-bruteforce-ssh"]
    assert (ssh.key, ssh.threshold, ssh.window, ssh.level, ssh.mitre) == (
        "IpAddress", 10, timedelta(minutes=5), "high", ("T1110.001",))
    assert set(corr) == {"sentiel-bruteforce-windows", "sentiel-bruteforce-ssh"}
    assert all(r.origin.endswith(".yml") for r in rules)


def test_correlation_base_rules_do_not_alert_on_their_own(rules):
    assert not any(isinstance(r, Rule) and r.title in ("Windows failed logon", "SSH failed login") for r in rules)


def test_correlation_can_reference_a_rule_in_another_file(tmp_path, conn):
    (tmp_path / "a.yml").write_text(TWO_FILES_BASE, encoding="utf-8")
    (tmp_path / "b.yml").write_text(TWO_FILES_CORR, encoding="utf-8")
    rules, warnings = load_rules(tmp_path)
    assert warnings == [] and [r.id for r in rules] == ["cross-file"]
    store.insert_events(conn, [ev(i * 0.1, IpAddress="6.6.6.6", EventID=4625) for i in range(3)])
    assert [a.rule_id for a in detect(conn, rules, 0)] == ["cross-file"]


def test_broken_correlation_is_a_warning_not_fatal(tmp_path):
    (tmp_path / "a.yml").write_text(TWO_FILES_BASE, encoding="utf-8")
    (tmp_path / "b.yml").write_text(TWO_FILES_CORR.replace("[base_rule]", "[missing_rule]"), encoding="utf-8")
    (tmp_path / "c.yml").write_text(
        TWO_FILES_CORR.replace("event_count", "value_count").replace("cross-file", "vc")
        .replace("22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"),
        encoding="utf-8")
    rules, warnings = load_rules(tmp_path)
    assert not any(isinstance(r, Correlation) for r in rules) and len(warnings) == 2


def test_base_rule_sql_relies_on_pysigma_output_flag():
    # pins the private-API assumption documented in detect.py (`_output`)
    from sigma.backends.sqlite import sqliteBackend
    from sigma.collection import SigmaCollection
    c = SigmaCollection.from_yaml(TWO_FILES_BASE + "---\n" + TWO_FILES_CORR)
    c.resolve_rule_references()
    base = c.rules[0]
    assert base._output is False and sqliteBackend().convert_rule(base) == []


USER_RULE = """title: User rule
id: 44444444-4444-4444-8444-444444444444
logsource: {product: windows}
detection: {selection: {EventID: 4720}, condition: selection}
level: low
"""


def test_user_rules_dir_is_loaded_with_builtin(tmp_path):
    (tmp_path / "u.yml").write_text(USER_RULE, encoding="utf-8")
    rules, warnings = rules_for(Config(rules_dirs=[str(tmp_path)]))
    ids = {r.id for r in rules}
    assert "44444444-4444-4444-8444-444444444444" in ids and "sentiel-bruteforce-ssh" in ids and warnings == []


def test_disabled_rule_is_removed_and_unknown_id_warns():
    rules, warnings = rules_for(Config(disabled_rules=["sentiel-bruteforce-ssh", "nope"]))
    assert "sentiel-bruteforce-ssh" not in {r.id for r in rules}
    assert warnings == ["disabled_rules: unknown id nope"]


def test_missing_rules_dir_warns(tmp_path):
    _, warnings = rules_for(Config(rules_dirs=[str(tmp_path / "missing")]))
    assert warnings == [f"rules dir not found: {tmp_path / 'missing'}"]


def test_rules_for_products_we_do_not_collect_are_skipped_with_one_warning(tmp_path):
    for i, product in enumerate(("aws", "macos", "aws")):
        (tmp_path / f"{i}.yml").write_text(
            USER_RULE.replace("windows", product).replace("44444444-4444-4444-8444-444444444444",
                                                          f"5555555{i}-5555-4555-8555-555555555555"),
            encoding="utf-8")
    rules, warnings = load_rules(tmp_path)
    assert rules == [] and warnings == ["3 rules skipped: product not collected (aws, macos)"]


def test_duplicate_rule_id_keeps_the_builtin(tmp_path):
    builtin = next(p for p in RULES_DIR.glob("*.yml") if "security_log_cleared" in p.name)
    shutil.copy(builtin, tmp_path / "copy.yml")
    rules, warnings = rules_for(Config(rules_dirs=[str(tmp_path)]))
    dup = [r for r in rules if r.origin.endswith("copy.yml")]
    assert dup == [] and len(warnings) == 1 and warnings[0].startswith("duplicate rule id")


def test_correlation_with_any_uncollected_base_product_is_skipped(tmp_path):
    (tmp_path / "a.yml").write_text(
        "title: A\nid: 66666666-6666-4666-8666-666666666661\nname: base_win\nlogsource: {product: windows}\n"
        "detection: {selection: {EventID: 1}, condition: selection}\nlevel: low\n---\n"
        "title: B\nid: 66666666-6666-4666-8666-666666666662\nname: base_aws\nlogsource: {product: aws}\n"
        "detection: {selection: {EventID: 2}, condition: selection}\nlevel: low\n---\n"
        "title: C\nid: 66666666-6666-4666-8666-666666666663\nname: mixed\n"
        "correlation: {type: event_count, rules: [base_win, base_aws], group-by: [IpAddress], timespan: 2m,"
        " condition: {gte: 3}}\nlevel: medium\n", encoding="utf-8")
    rules, warnings = load_rules(tmp_path)
    assert rules == [] and warnings == ["1 rules skipped: product not collected (aws)"]


WEB_RULE = """title: Web probe
id: 77777777-7777-4777-8777-777777777777
logsource: {category: webserver}
detection: {selection: {cs-uri-query|contains: 'cmd=', user.name: bob}, condition: selection}
level: high
"""
BAD_RE_RULE = """title: Bad regex
id: 88888888-8888-4888-8888-888888888888
logsource: {product: windows}
detection: {selection: {CommandLine|re: 'ab(?i)c'}, condition: selection}
level: high
"""
ENCODED_PS = "c1d3a684-f103-4ed2-bfa5-4ec0186d6b30"


def _ps_event(conn):
    store.insert_events(conn, [ev(0, EventID=1, Image="C:\\x\\powershell.exe", CommandLine="powershell -enc AAAA")])


def test_rule_on_hyphenated_or_dotted_field_the_db_lacks_does_not_stop_detection(tmp_path, conn):
    (tmp_path / "web.yml").write_text(WEB_RULE, encoding="utf-8")
    rules, _ = load_rules(RULES_DIR, tmp_path)
    _ps_event(conn)
    warnings: list[str] = []
    assert [a.rule_id for a in detect(conn, rules, 0, warnings)] == [ENCODED_PS]
    assert warnings == []  # an unknown field is an all-NULL column, not a broken rule


def test_rule_raising_at_runtime_is_skipped_with_a_warning(tmp_path, conn):
    (tmp_path / "re.yml").write_text(BAD_RE_RULE, encoding="utf-8")
    rules, _ = load_rules(RULES_DIR, tmp_path)
    _ps_event(conn)
    warnings: list[str] = []
    assert [a.rule_id for a in detect(conn, rules, 0, warnings)] == [ENCODED_PS]
    assert len(warnings) == 1 and warnings[0].startswith("rule 88888888-8888-4888-8888-888888888888: ")


LONG_CORR = TWO_FILES_CORR.replace("timespan: 2m", "timespan: 3h")


def test_correlation_ignores_events_older_than_the_lookback(tmp_path, conn):
    (tmp_path / "a.yml").write_text(TWO_FILES_BASE, encoding="utf-8")
    (tmp_path / "b.yml").write_text(LONG_CORR, encoding="utf-8")
    rules, _ = load_rules(tmp_path)
    store.insert_events(conn, [ev(i, IpAddress="6.6.6.6", EventID=4625) for i in range(2)])
    since = conn.execute("SELECT max(id) FROM logs").fetchone()[0]
    store.insert_events(conn, [ev(90, IpAddress="6.6.6.6", EventID=4625)])  # old ones are 89 min back
    assert detect(conn, rules, since) == []
    assert [a.rule_id for a in detect(conn, rules, 0)] == ["cross-file"]  # same 3 events, all in the lookback


def test_correlation_base_query_only_scans_the_lookback_window(tmp_path, monkeypatch):
    calls = []
    real = store._regexp
    monkeypatch.setattr(store, "_regexp", lambda p, v: calls.append(1) or real(p, v))
    conn = store.connect(tmp_path / "t.db")
    (tmp_path / "r").mkdir()
    (tmp_path / "r" / "a.yml").write_text(TWO_FILES_BASE.replace("EventID: 4625", "CommandLine|re: 'x'"),
                                          encoding="utf-8")
    (tmp_path / "r" / "b.yml").write_text(TWO_FILES_CORR, encoding="utf-8")
    rules, _ = load_rules(tmp_path / "r")
    store.insert_events(conn, [ev(-3000 - i, IpAddress="6.6.6.6", CommandLine="x") for i in range(200)])
    since = conn.execute("SELECT max(id) FROM logs").fetchone()[0]
    store.insert_events(conn, [ev(i * 0.1, IpAddress="6.6.6.6", CommandLine="x") for i in range(3)])
    assert [a.rule_id for a in detect(conn, rules, since)] == ["cross-file"]
    assert len(calls) < 50  # history outside the 1h lookback is never fed to the base rule


def test_yaml_extension_rule_is_loaded(tmp_path):
    (tmp_path / "u.yaml").write_text(USER_RULE, encoding="utf-8")
    rules, warnings = load_rules(tmp_path)
    assert [r.id for r in rules] == ["44444444-4444-4444-8444-444444444444"] and warnings == []


def test_failed_correlation_does_not_mute_its_resolved_base(tmp_path):
    (tmp_path / "a.yml").write_text(
        USER_RULE.replace("title: User rule", "title: A\nname: a") + "---\n"
        "title: C\nid: 99999999-9999-4999-8999-999999999999\n"
        "correlation: {type: event_count, rules: [a, missing], group-by: [IpAddress], timespan: 2m,"
        " condition: {gte: 3}}\nlevel: medium\n", encoding="utf-8")
    rules, warnings = load_rules(tmp_path)
    assert [(type(r), r.id) for r in rules] == [(Rule, "44444444-4444-4444-8444-444444444444")]
    assert len(warnings) == 1


def test_locked_database_fails_the_cycle_instead_of_skipping_rules(conn, rules, monkeypatch):
    # a transient lock must not advance the cursor past unseen events: the cycle fails and is retried
    def locked(*a, **k):
        raise detect_mod.sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(detect_mod, "_run_rule", locked)
    with pytest.raises(detect_mod.sqlite3.OperationalError):
        detect(conn, rules, 0, [])


def test_correlation_alert_has_count_last_ts_and_key(conn, rules):
    store.insert_events(conn, [ev(i * 0.05, EventID=4625, IpAddress="1.1.1.1") for i in range(60)])
    (a,) = detect(conn, rules, 0)
    assert a.count == 60 and len(a.event_ids) == 50 and a.group_key == "1.1.1.1"
    assert a.last_ts == T0 + timedelta(minutes=59 * 0.05)


def test_long_attack_count_matches_real_events_across_cycles(conn, rules):
    since, n = 0, 0
    for cycle in range(36):  # 3h of one failure every 10s, scanned every 5 min
        store.insert_events(conn, [ev((cycle * 30 + i) / 6, EventID=4625, IpAddress="1.1.1.1") for i in range(30)])
        store.insert_alerts(conn, detect(conn, rules, since), timedelta(hours=1))
        since = conn.execute("SELECT max(id) FROM logs").fetchone()[0]
        n += 30
    rows = conn.execute("SELECT count, last_ts FROM alerts").fetchall()
    assert len(rows) == 1 and rows[0]["count"] == n == 1080


def test_rules_for_warns_unknown_suppress_rule_id():
    from sentiel.config import Suppress

    cfg = Config(suppress=[Suppress(rule_id="nope", field="f", equals="x", reason="r"),
                           Suppress(rule_id="sentiel-bruteforce-ssh", field="f", equals="x", reason="r")])
    _, warnings = rules_for(cfg)
    assert warnings == ["suppress: unknown rule_id nope"]
