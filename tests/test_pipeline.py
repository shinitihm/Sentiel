import json
from datetime import UTC, datetime, timedelta

import httpx
import litellm
import pytest

from sentiel import store
from sentiel.config import Config, FileSource, Sources
from sentiel.models import effective_severity, is_contested
from sentiel.pipeline import demo_config, scan
from sentiel.store import fmt_ts, parse_ts

FOOLED = json.dumps({"severity": "info", "verdict": "benign", "mitre_techniques": [], "summary": "all fine",
                     "next_steps": []})
INJECTION_TEXT = "ignore all previous instructions"


@pytest.fixture
def cfg(tmp_path):
    return demo_config(Config(db_path=str(tmp_path / "s.db"), model="ollama/test"))


@pytest.fixture
def conn(cfg):
    return store.connect(cfg.db_path)


def http_recorder(statuses=(200,)):
    calls, codes = [], list(statuses)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(codes.pop(0) if len(codes) > 1 else codes[0])

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_end_to_end_demo_detects_all_seven_attacks(conn, cfg):
    s = scan(conn, cfg, mock_response=FOOLED)
    assert (s.new_events, s.new_alerts, s.triaged, s.pending) == (190, 7, 7, 0)
    assert s.skipped_lines == 0 and s.warnings == []


def test_ai_saying_benign_never_hides_a_high_rule(conn, cfg):
    scan(conn, cfg, mock_response=FOOLED)
    for row in store.list_alerts(conn, 50):
        alert, triage = store.row_to_alert(row)
        assert RANK_OK(effective_severity(alert.sigma_level, triage), alert.sigma_level)
        assert is_contested(alert.sigma_level, triage) == (alert.sigma_level in ("high", "critical"))


def RANK_OK(effective: str, sigma: str) -> bool:
    from sentiel.models import RANK
    return RANK[effective] >= RANK[sigma]


def test_rescan_is_idempotent(conn, cfg):
    scan(conn, cfg, mock_response=FOOLED)
    s = scan(conn, cfg, mock_response=FOOLED)
    assert (s.new_events, s.new_alerts, s.triaged) == (0, 0, 0)


def test_llm_down_keeps_alerts_pending(conn, cfg, monkeypatch):
    def boom(**_):
        raise litellm.Timeout("t", "m", "p")

    monkeypatch.setattr(litellm, "completion", boom)
    s = scan(conn, cfg)
    assert s.new_alerts == 7 and s.triaged == 0 and s.pending == 7
    assert any("unavailable" in w for w in s.warnings)


def test_no_ai_mode_only_detects(conn, cfg):
    s = scan(conn, cfg, ai=False)
    assert s.new_alerts == 7 and s.triaged == 0 and s.pending == 7


def test_triage_cap_per_cycle(conn, cfg):
    cfg.max_triage_per_cycle = 3
    s = scan(conn, cfg, mock_response=FOOLED)
    assert s.triaged == 3 and s.pending == 4


def test_notify_sends_high_and_above_without_raw_log_content(conn, cfg):
    cfg.notify = {"discord_webhook": "https://discord.example/hook"}
    client, calls = http_recorder()
    s = scan(conn, cfg, http=client, mock_response=FOOLED)
    assert s.notified == 5  # 5 high rules; the 2 medium ones stay below the threshold
    body = [json.loads(c.content) for c in calls]
    assert all(b["allowed_mentions"] == {"parse": []} for b in body)
    assert not any(INJECTION_TEXT in b["content"] for b in body)
    assert any("WARNING" in b["content"] for b in body)  # contested alerts say so


def test_notify_without_channel_leaves_alerts_unsent(conn, cfg):
    s = scan(conn, cfg, mock_response=FOOLED)
    assert s.notified == 0
    assert conn.execute("SELECT count(*) FROM alerts WHERE notified = 0 AND sigma_level = 'high'").fetchone()[0] > 0


def test_failed_notification_is_retried_next_cycle(conn, cfg):
    cfg.notify = {"discord_webhook": "https://discord.example/hook"}
    down, _ = http_recorder((500,))
    assert scan(conn, cfg, http=down, mock_response=FOOLED).notified == 0
    up, _ = http_recorder((200,))
    assert scan(conn, cfg, http=up, mock_response=FOOLED).notified == 5


def test_telegram_error_never_leaks_token(conn):
    from sentiel.notify import send

    def handler(request):
        raise httpx.ConnectError("failed for " + str(request.url))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert send({"telegram_bot_token": "SECRET", "telegram_chat_id": "1"}, "hi", client) == {"telegram": False}


def test_malformed_webhook_and_token_fail_the_channel_without_raising():
    from sentiel.notify import send

    def handler(request):
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert send({"discord_webhook": "http://[::1"}, "hi", client) == {"discord": False}
    assert send({"discord_webhook": "https://"}, "hi", client) == {"discord": False}
    assert send({"telegram_bot_token": "bad token/\x00 [x", "telegram_chat_id": "1"}, "hi", client) == {
        "telegram": False}


def test_one_failing_channel_does_not_starve_the_working_one(conn, cfg):
    cfg.notify = {"telegram_bot_token": "SECRET", "telegram_chat_id": "1",
                  "discord_webhook": "https://discord.example/hook"}
    telegram = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.telegram.org":
            telegram.append(json.loads(request.content)["text"])
            return httpx.Response(200)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    s = scan(conn, cfg, http=client, mock_response=FOOLED)
    assert s.notified == 5
    assert [w for w in s.warnings if "discord" in w] == ["notification channel discord failed"]
    assert not any("SECRET" in w or "discord.example" in w for w in s.warnings)
    s2 = scan(conn, cfg, http=client, mock_response=FOOLED)
    assert s2.notified == 0
    assert len(telegram) == 5 and len(set(telegram)) == 5  # every high alert reached Telegram exactly once


def _failing_llm(monkeypatch):
    calls = []

    def boom(**kw):
        calls.append(kw)
        raise litellm.Timeout("t", "m", "p")
    monkeypatch.setattr(litellm, "completion", boom)
    return calls


def test_llm_down_starts_backoff_and_next_scan_skips_triage(conn, cfg, monkeypatch):
    calls = _failing_llm(monkeypatch)
    scan(conn, cfg)
    assert store.get_state(conn, "llm_failures") == "1"
    wait = parse_ts(store.get_state(conn, "llm_retry_at")) - datetime.now(UTC)
    assert timedelta(seconds=25) < wait <= timedelta(seconds=30)
    n = len(calls)
    s = scan(conn, cfg)
    assert len(calls) == n and s.triaged == 0 and s.pending == 7
    assert any("AI paused" in w for w in s.warnings)


def test_backoff_doubles_and_caps_at_30_minutes(conn, cfg, monkeypatch):
    _failing_llm(monkeypatch)
    store.set_state(conn, "llm_failures", "10")
    scan(conn, cfg)
    wait = parse_ts(store.get_state(conn, "llm_retry_at")) - datetime.now(UTC)
    assert timedelta(minutes=29) < wait <= timedelta(minutes=30)


def test_expired_backoff_retries_and_success_clears_it(conn, cfg):
    store.set_state(conn, "llm_failures", "3")
    store.set_state(conn, "llm_retry_at", fmt_ts(datetime.now(UTC) - timedelta(seconds=1)))
    s = scan(conn, cfg, mock_response=FOOLED)
    assert s.triaged == 7
    assert store.get_state(conn, "llm_failures", "0") == "0"


def test_manual_triage_ignores_backoff(conn, cfg):
    from sentiel.pipeline import ScanSummary, triage_pending

    scan(conn, cfg, ai=False)
    store.set_state(conn, "llm_failures", "1")
    store.set_state(conn, "llm_retry_at", fmt_ts(datetime.now(UTC) + timedelta(minutes=10)))
    s = ScanSummary()
    triage_pending(conn, cfg, s, None, FOOLED)
    assert s.triaged == 7


def test_failing_webhook_gets_one_post_per_cycle(conn, cfg):
    cfg.notify = {"discord_webhook": "https://discord.example/hook"}
    down, calls = http_recorder((500,))
    assert scan(conn, cfg, http=down, mock_response=FOOLED).notified == 0
    assert len(calls) == 1
    # alert 1 (high) fails first, so the cycle stops before reaching anything else
    assert conn.execute("SELECT count(*) FROM alerts WHERE notified = 1").fetchone()[0] == 0


def test_scan_writes_heartbeat(conn, cfg):
    scan(conn, cfg, ai=False)
    beat = parse_ts(store.get_state(conn, "heartbeat"))
    assert datetime.now(UTC) - beat < timedelta(seconds=10)


@pytest.mark.parametrize("value", ["garbage", "2099-01-01T00:00:00"])  # unparseable, naive (no tz)
def test_corrupt_retry_at_does_not_break_the_cycle(conn, cfg, value):
    store.set_state(conn, "llm_retry_at", value)
    s = scan(conn, cfg, mock_response=FOOLED)
    assert s.triaged == 7
    assert datetime.now(UTC) - parse_ts(store.get_state(conn, "heartbeat")) < timedelta(seconds=10)


def test_corrupt_failure_count_restarts_backoff(conn, cfg, monkeypatch):
    _failing_llm(monkeypatch)
    store.set_state(conn, "llm_failures", "x")
    s = scan(conn, cfg)
    assert s.pending == 7
    assert store.get_state(conn, "llm_failures") == "1"
    assert store.get_state(conn, "heartbeat")


def test_ai_paused_warning_says_how_to_retry_now(conn, cfg):
    store.set_state(conn, "llm_failures", "1")
    store.set_state(conn, "llm_retry_at", fmt_ts(datetime.now(UTC) + timedelta(minutes=10)))
    w = [w for w in scan(conn, cfg, mock_response=FOOLED).warnings if w.startswith("AI paused")]
    assert len(w) == 1 and w[0].endswith(" Run `sentiel triage` to retry now.")


def test_concurrent_triage_matches_sequential(tmp_path):
    results = []
    for workers in (1, 4):
        c = demo_config(Config(db_path=str(tmp_path / f"{workers}.db"), model="ollama/test",
                               triage_concurrency=workers))
        conn = store.connect(c.db_path)
        s = scan(conn, c, mock_response=FOOLED)
        results.append((s.triaged, s.pending,
                        [(r["id"], r["triage"]) for r in conn.execute("SELECT id, triage FROM alerts ORDER BY id")]))
    assert results[0] == results[1] and results[0][0] == 7


def test_concurrent_triage_with_llm_down_keeps_everything_pending(conn, cfg, monkeypatch):
    def boom(**_):
        raise litellm.Timeout("t", "m", "p")
    monkeypatch.setattr(litellm, "completion", boom)
    cfg.triage_concurrency = 4
    s = scan(conn, cfg)
    assert s.triaged == 0 and s.pending == 7
    assert store.get_state(conn, "llm_failures") == "1"


def test_triage_concurrency_must_be_positive():
    with pytest.raises(ValueError):
        Config(triage_concurrency=0)


def test_success_clears_retry_at_too(conn, cfg):
    from sentiel.pipeline import ScanSummary, triage_pending
    scan(conn, cfg, ai=False)
    store.set_state(conn, "llm_failures", "2")
    store.set_state(conn, "llm_retry_at", fmt_ts(datetime.now(UTC) + timedelta(minutes=10)))
    triage_pending(conn, cfg, ScanSummary(), None, FOOLED)
    assert store.get_state(conn, "llm_retry_at") in (None, "")
    assert not any("AI paused" in w for w in scan(conn, cfg, mock_response=FOOLED).warnings)


def test_partial_success_then_failure_still_escalates(conn, cfg, monkeypatch):
    # first call succeeds, every later call fails
    real, n = litellm.completion, []

    def flaky(**kw):
        n.append(1)
        if len(n) > 1:
            raise litellm.Timeout("t", "m", "p")
        return real(**{**kw, "mock_response": FOOLED})
    monkeypatch.setattr(litellm, "completion", flaky)
    store.set_state(conn, "llm_failures", "3")
    s = scan(conn, cfg)
    assert s.triaged == 1
    assert store.get_state(conn, "llm_failures") == "4"


def test_interrupt_during_triage_does_not_run_the_queued_batch(conn, cfg, monkeypatch):
    calls = []

    def interrupt(**_):
        calls.append(1)
        raise KeyboardInterrupt
    monkeypatch.setattr(litellm, "completion", interrupt)
    with pytest.raises(KeyboardInterrupt):
        scan(conn, cfg)
    assert len(calls) == 1
    assert conn.execute("SELECT count(*) FROM alerts WHERE triage IS NULL").fetchone()[0] == 7


def test_rule_warnings_are_summarised_in_one_line(conn, cfg, tmp_path):
    bad = tmp_path / "rules"
    bad.mkdir()
    for i in range(5):
        (bad / f"{i}.yml").write_text("title: broken\ndetection: [", encoding="utf-8")
    cfg.rules_dirs = [str(bad)]
    s = scan(conn, cfg, ai=False)
    rule_lines = [w for w in s.warnings if "rule warnings" in w]
    assert rule_lines == ["5 rule warnings (see `sentiel rules list --skipped`)"]


def test_user_rule_fires_on_a_regex_source(tmp_path):
    log = tmp_path / "access.log"
    log.write_text('6.6.6.6 - - [11/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404\n', encoding="utf-8")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "env.yml").write_text(
        "title: Dotenv probe\nid: 66666666-6666-4666-8666-666666666666\nlogsource: {product: linux}\n"
        "detection: {selection: {Url|endswith: '/.env'}, condition: selection}\nlevel: medium\n", encoding="utf-8")
    regex = r'^(?P<IpAddress>\S+) .*"\w+ (?P<Url>\S+)'
    c = Config(db_path=str(tmp_path / "s.db"), rules_dirs=[str(rules)], sources=Sources(
        windows=False, linux_auth=None, files=[FileSource(path=str(log), regex=regex, product="linux")]))
    s = scan(store.connect(c.db_path), c, ai=False)
    assert s.new_events == 1 and s.new_alerts == 1


def test_duplicate_file_source_paths_are_rejected():
    f = FileSource(path="a.log", regex=r"(?P<W>\w+)")
    with pytest.raises(ValueError, match="duplicate path in sources.files: a.log"):
        Sources(files=[f, f])


def test_rule_failing_at_runtime_is_a_rule_warning_and_detection_moves_on(conn, cfg, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "re.yml").write_text(
        "title: Bad regex\nid: 88888888-8888-4888-8888-888888888888\nlogsource: {product: windows}\n"
        "detection: {selection: {CommandLine|re: 'ab(?i)c'}, condition: selection}\nlevel: high\n", encoding="utf-8")
    cfg.rules_dirs = [str(rules)]
    s = scan(conn, cfg, ai=False)
    assert s.new_alerts == 7 and [w for w in s.warnings if "rule warnings" in w] == [
        "1 rule warnings (see `sentiel rules list --skipped`)"]
    assert store.get_state(conn, "last_detected_log_id") == str(conn.execute("SELECT max(id) FROM logs").fetchone()[0])


def test_triage_skips_non_active_alerts(conn, cfg, monkeypatch):
    from sentiel import pipeline

    scan(conn, cfg, ai=False)
    conn.execute("UPDATE alerts SET status = 'false_positive'")
    conn.commit()

    def boom(*a, **k):
        raise AssertionError("LLM must not be called for inactive alerts")

    monkeypatch.setattr(pipeline, "triage_alert", boom)
    s = scan(conn, cfg, mock_response=FOOLED)
    assert s.triaged == 0 and s.pending == 0


def test_scan_groups_burst_into_one_alert_and_one_llm_call(conn, cfg, tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "probe.yml").write_text(
        "title: Probe\nid: 99999999-9999-4999-8999-999999999999\nlogsource: {category: test}\n"
        "detection: {selection: {msg|startswith: probe}, condition: selection}\nlevel: high\n", encoding="utf-8")
    log = tmp_path / "e.jsonl"

    def write(lo, hi):
        with log.open("a", encoding="utf-8") as f:
            for i in range(lo, hi):
                f.write(json.dumps({"ts": f"2026-10-09T08:{i // 60:02d}:{i % 60:02d}+00:00", "host": "h1",
                                    "msg": f"probe {i}"}) + "\n")

    cfg.rules_dirs = [str(rules)]
    cfg.group_window = 3600
    cfg.notify = {"discord_webhook": "https://discord.example/hook"}
    cfg.sources = Sources(windows=False, linux_auth=None, json=[str(log)])
    client, calls = http_recorder()
    n = []
    real = litellm.completion
    monkeypatch.setattr(litellm, "completion", lambda **k: n.append(1) or real(**k))
    write(0, 50)
    s = scan(conn, cfg, http=client, mock_response=FOOLED)
    assert s.new_alerts == 1 and s.triaged == 1 and len(n) == 1 and len(calls) == 1
    write(50, 80)
    s = scan(conn, cfg, http=client, mock_response=FOOLED)
    assert s.new_alerts == 0 and s.triaged == 0 and len(n) == 1 and len(calls) == 1
    (row,) = conn.execute("SELECT * FROM alerts").fetchall()
    assert row["count"] == 80



def test_crash_between_alerts_and_cursor_leaves_db_untouched_and_replay_is_exact(conn, cfg, tmp_path):
    real = store.set_state

    def crash(c, key, value, commit=True):
        if key == "last_detected_log_id":
            raise RuntimeError("crash")
        real(c, key, value, commit)

    store.set_state = crash
    try:
        with pytest.raises(RuntimeError):
            scan(conn, cfg, ai=False)
    finally:
        store.set_state = real
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0
    assert store.get_state(conn, "last_detected_log_id", "0") == "0"
    scan(conn, cfg, ai=False)
    other = demo_config(Config(db_path=str(tmp_path / "o.db"), model="ollama/test"))
    c2 = store.connect(other.db_path)
    scan(c2, other, ai=False)
    q = "SELECT rule_id, count FROM alerts ORDER BY rule_id"
    assert [tuple(r) for r in conn.execute(q)] == [tuple(r) for r in c2.execute(q)]


def test_concurrent_scans_do_not_double_count(cfg, tmp_path, monkeypatch):
    import threading
    import time

    from sentiel import pipeline

    real, first = pipeline.detect, []

    def slow(*a, **k):
        out = real(*a, **k)
        if not first:  # the first scan lingers between reading the cursor and writing
            first.append(1)
            time.sleep(1)
        return out

    monkeypatch.setattr(pipeline, "detect", slow)
    errors = []

    def run():
        try:
            scan(store.connect(cfg.db_path), cfg, ai=False)
        except Exception as e:  # pragma: no cover
            errors.append(e)

    a = threading.Thread(target=run)
    a.start()
    time.sleep(0.5)
    b = threading.Thread(target=run)
    b.start()
    a.join()
    b.join()
    assert errors == []
    other = demo_config(Config(db_path=str(tmp_path / "o.db"), model="ollama/test"))
    c2 = store.connect(other.db_path)
    scan(c2, other, ai=False)
    q = "SELECT rule_id, count FROM alerts ORDER BY rule_id"
    assert [tuple(r) for r in store.connect(cfg.db_path).execute(q)] == [tuple(r) for r in c2.execute(q)]


PROBE_ID = "99999999-9999-4999-8999-999999999999"


def _probe_setup(cfg, tmp_path, events):
    """One-rule setup: every {"msg": "probe ..."} event raises a 'Probe' alert; `events` is a list of dicts."""
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    (rules / "probe.yml").write_text(
        f"title: Probe\nid: {PROBE_ID}\nlogsource: {{category: test}}\n"
        "detection: {selection: {msg|startswith: probe}, condition: selection}\nlevel: high\n", encoding="utf-8")
    log = tmp_path / "e.jsonl"
    with log.open("a", encoding="utf-8") as f:
        for i, extra in enumerate(events):
            f.write(json.dumps({"ts": f"2026-10-09T08:00:{i:02d}+00:00", "host": "h1", "msg": f"probe {i}", **extra})
                    + "\n")
    cfg.rules_dirs = [str(rules)]
    cfg.sources = Sources(windows=False, linux_auth=None, json=[str(log)])


def test_suppressed_alert_is_stored_but_not_triaged_or_notified(conn, cfg, tmp_path, monkeypatch):
    from sentiel import pipeline
    from sentiel.config import Suppress

    _probe_setup(cfg, tmp_path, [{"user": "svc"}])
    cfg.notify = {"discord_webhook": "https://discord.example/hook"}
    cfg.suppress = [Suppress(rule_id=PROBE_ID, field="user", equals="svc", reason="backup service")]
    client, calls = http_recorder()
    llm = []
    monkeypatch.setattr(pipeline, "triage_alert", lambda *a, **k: llm.append(1) or pytest.fail("no LLM"))
    s = scan(conn, cfg, http=client, mock_response=FOOLED)
    (row,) = conn.execute("SELECT * FROM alerts WHERE rule_id = ?", (PROBE_ID,)).fetchall()
    assert row["status"] == "suppressed" and row["note"] == "backup service" and row["triage"] is None
    assert not llm and not calls and s.triaged == 0 and s.notified == 0 and s.new_alerts == 1


def test_non_suppressed_alert_of_the_same_run_is_triaged_and_notified(conn, cfg, tmp_path):
    from sentiel.config import Suppress

    cfg.notify = {"discord_webhook": "https://discord.example/hook"}
    cfg.suppress = [Suppress(rule_id="sentiel-bruteforce-ssh", field="IpAddress", equals="nope", reason="r")]
    client, calls = http_recorder()
    s = scan(conn, cfg, http=client, mock_response=FOOLED)
    assert s.triaged == 7 and s.notified == 5


def test_suppression_matches_int_and_string_field(conn, cfg, tmp_path):
    from sentiel.config import Suppress

    _probe_setup(cfg, tmp_path, [{"EventID": 4625}, {"other": 1}])
    cfg.group_window = 0
    for eq in ("4625", 4625):
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM state WHERE key = 'last_detected_log_id'")
        conn.commit()
        cfg.suppress = [Suppress(rule_id=PROBE_ID, field="EventID", equals=eq, reason="r")]
        scan(conn, cfg, ai=False)
        rows = {r["first_event_id"]: r["status"] for r in conn.execute("SELECT * FROM alerts")}
        assert sorted(rows.values()) == ["open", "suppressed"], eq  # the event without the field never matches


def test_suppression_does_not_leak_to_other_rules_or_values(conn, cfg, tmp_path):
    from sentiel.config import Suppress

    _probe_setup(cfg, tmp_path, [{"user": "bob"}])
    cfg.suppress = [Suppress(rule_id="other-rule", field="user", equals="bob", reason="r"),
                    Suppress(rule_id=PROBE_ID, field="user", equals="alice", reason="r")]
    scan(conn, cfg, ai=False)
    statuses = {r["rule_id"]: r["status"] for r in conn.execute("SELECT rule_id, status FROM alerts")}
    assert statuses[PROBE_ID] == "open" and set(statuses.values()) == {"open"}


def test_suppressed_events_do_not_absorb_open_alert(conn, cfg, tmp_path):
    from sentiel.config import Suppress

    _probe_setup(cfg, tmp_path, [{"user": "svc"}, {"user": "eve"}])
    cfg.group_window = 3600
    cfg.suppress = [Suppress(rule_id=PROBE_ID, field="user", equals="svc", reason="r")]
    scan(conn, cfg, ai=False)
    rows = conn.execute("SELECT status FROM alerts WHERE rule_id = ? ORDER BY id", (PROBE_ID,)).fetchall()
    assert [r["status"] for r in rows] == ["suppressed", "open"]


def test_llm_never_changes_status(conn, cfg):
    scan(conn, cfg, ai=False)
    conn.execute("UPDATE alerts SET status = 'ack' WHERE id = 1")
    conn.commit()
    before = [(r["id"], r["status"]) for r in conn.execute("SELECT id, status FROM alerts ORDER BY id")]
    benign = json.dumps({"severity": "info", "verdict": "benign", "mitre_techniques": [], "summary": "ok",
                         "next_steps": []})
    scan(conn, cfg, mock_response=benign)
    assert [(r["id"], r["status"]) for r in conn.execute("SELECT id, status FROM alerts ORDER BY id")] == before


def test_demo_config_ignores_user_suppressions(cfg):
    from sentiel.config import Suppress

    user = Config(suppress=[Suppress(rule_id="x", field="f", equals=1, reason="r")])
    assert demo_config(user).suppress == []


def _digest_stats():
    return {"by_severity": {"high": 3, "low": 1}, "top_rules": [("Brute force", 40), ("x" * 500, 2)],
            "contested": 1, "pending": 4, "suppressed": 7}


def test_format_digest_has_counts_and_no_raw_log_and_is_capped():
    from sentiel.notify import format_digest
    text = format_digest(_digest_stats())
    assert "high: 3" in text and "Brute force" in text and "Pending triage: 4" in text
    assert "x" * 200 not in text  # long rule titles are cut
    big = {**_digest_stats(), "top_rules": [(f"{i}" * 300, 1) for i in range(50)]}
    assert len(format_digest(big)) <= 1900
    assert "- a b c (1)" in format_digest({**_digest_stats(), "top_rules": [("a\nb\r\nc", 1)]})


DAY = datetime(2026, 10, 11, 8, 0).astimezone()


def _digest_cfg(cfg, hour=9):
    cfg.notify = {"discord_webhook": "https://discord.example/hook"}
    cfg.digest_hour = hour
    return cfg


def test_digest_sent_once_per_day(conn, cfg):
    from sentiel.pipeline import maybe_send_digest
    _digest_cfg(cfg)
    client, calls = http_recorder()
    assert maybe_send_digest(conn, cfg, client, DAY) is False and not calls  # before the hour
    assert maybe_send_digest(conn, cfg, client, DAY.replace(hour=9)) is True and len(calls) == 1
    assert maybe_send_digest(conn, cfg, client, DAY.replace(hour=15)) is False and len(calls) == 1
    assert maybe_send_digest(conn, cfg, client, DAY.replace(day=12, hour=9)) is True and len(calls) == 2


def test_digest_off_when_hour_unset(conn, cfg):
    from sentiel.pipeline import maybe_send_digest
    _digest_cfg(cfg).digest_hour = None
    client, calls = http_recorder()
    assert maybe_send_digest(conn, cfg, client, DAY.replace(hour=23)) is False and not calls


def test_digest_not_marked_when_delivery_fails(conn, cfg):
    from sentiel.pipeline import maybe_send_digest
    _digest_cfg(cfg)
    down, _ = http_recorder((500,))
    now = DAY.replace(hour=10)
    assert maybe_send_digest(conn, cfg, down, now) is False
    assert store.get_state(conn, "digest_last") is None
    up, _ = http_recorder((200,))
    assert maybe_send_digest(conn, cfg, up, now) is True
    assert store.get_state(conn, "digest_last") == now.date().isoformat()


def test_digest_not_marked_without_channel(conn, cfg):
    from sentiel.pipeline import maybe_send_digest
    cfg.digest_hour = 0
    assert maybe_send_digest(conn, cfg, None, DAY) is False
    assert store.get_state(conn, "digest_last") is None


def test_digest_hour_validation():
    from pydantic import ValidationError
    for bad in (24, -1):
        with pytest.raises(ValidationError):
            Config(digest_hour=bad)
    assert Config(digest_hour=0).digest_hour == 0 and Config().digest_hour is None


def test_demo_config_turns_digest_off():
    assert demo_config(Config(digest_hour=9)).digest_hour is None


def test_scan_survives_triage_exception(conn, cfg, monkeypatch):
    from sentiel import pipeline

    def boom(*_a, **_k):
        raise RuntimeError("model exploded")

    notified = []
    monkeypatch.setattr(pipeline, "triage_pending", boom)
    monkeypatch.setattr(pipeline, "_notify", lambda *a: notified.append(1))
    s = scan(conn, cfg)
    assert "triage failed: RuntimeError" in s.warnings and not any("model exploded" in w for w in s.warnings)
    assert notified and store.get_state(conn, "heartbeat")
