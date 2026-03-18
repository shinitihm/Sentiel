import json
import sqlite3

import httpx
import litellm
import pytest

from sentiel import chat, store
from sentiel.bench import ModelScore, run_bench, splice_readme, to_markdown
from sentiel.config import Config
from sentiel.enrich import enrich_ips, public_ips
from sentiel.pipeline import demo_config, scan

GOOD = json.dumps({"severity": "high", "verdict": "true_positive", "mitre_techniques": ["T1110.001"],
                   "summary": "s", "next_steps": []})
FOOLED = json.dumps({"severity": "info", "verdict": "benign", "mitre_techniques": [], "summary": "s",
                     "next_steps": []})


@pytest.fixture
def db(tmp_path):
    cfg = demo_config(Config(db_path=str(tmp_path / "s.db")))
    conn = store.connect(cfg.db_path)
    scan(conn, cfg, ai=False)
    conn.close()
    return cfg.db_path


# ---------- chat: read-only SQL ----------

@pytest.mark.parametrize("sql", [
    "DROP TABLE alerts", "DELETE FROM alerts", "UPDATE alerts SET notified = 1",
    "INSERT INTO state VALUES ('a','b')", "ATTACH DATABASE 'x.db' AS x", "PRAGMA writable_schema = 1",
    "SELECT * FROM state", "SELECT * FROM ip_cache", "SELECT 1; DROP TABLE alerts",
])
def test_chat_blocks_everything_but_select_on_logs_and_alerts(db, sql):
    rw = sqlite3.connect(db)  # writable connection: only the authorizer stands in the way
    chat.lock_down(rw)
    with pytest.raises((chat.UnsafeQuery, sqlite3.Warning)):
        chat.run_query(rw, sql)
    assert rw.execute("SELECT count(*) FROM alerts").fetchone()[0] == 7


def test_chat_connection_is_read_only_at_the_file_level(db):
    ro = chat.open_readonly(db)
    with pytest.raises(sqlite3.OperationalError):
        ro.execute("DELETE FROM alerts")


def test_chat_select_is_allowed_and_rows_capped(db, monkeypatch):
    ro = chat.open_readonly(db)
    chat.lock_down(ro)
    assert chat.run_query(ro, "SELECT count(*) AS n FROM alerts") == [{"n": 7}]
    monkeypatch.setattr(chat, "MAX_ROWS", 5)
    assert len(chat.run_query(ro, "SELECT * FROM logs")) == 5


def test_chat_slow_query_is_aborted(db, monkeypatch):
    monkeypatch.setattr(chat, "TIMEOUT_S", 0.2)
    ro = chat.open_readonly(db)
    chat.lock_down(ro)
    with pytest.raises(chat.UnsafeQuery):
        chat.run_query(ro, "SELECT count(*) FROM logs a, logs b, logs c, logs d, logs e")


def test_ask_runs_generated_sql_and_answers(db):
    res = chat.ask(db, "how many alerts?", "ollama/x",
                   mock_response=["```sql\nSELECT count(*) AS n FROM alerts;\n```", None, "There are 7 alerts."])
    assert res.rows == [{"n": 7}] and res.answer == "There are 7 alerts."


def test_ask_gives_up_safely_when_model_keeps_writing_destructive_sql(db):
    res = chat.ask(db, "wipe it", "ollama/x", mock_response=["```sql\nDROP TABLE alerts\n```"] * 3)
    assert "could not run a safe query" in res.answer
    assert sqlite3.connect(db).execute("SELECT count(*) FROM alerts").fetchone()[0] == 7


# ---------- enrich ----------

def test_public_ips_filters_private_and_dedupes():
    events = [{"fields": {"IpAddress": "8.8.8.8", "x": "10.0.0.1", "t": "203.0.113.7"}},
              {"fields": {"IpAddress": "8.8.8.8", "y": "127.0.0.1", "z": "not an ip", "w": 5}},
              {"fields": {"IpAddress": "1.1.1.1"}}]
    assert public_ips(events) == ["8.8.8.8", "1.1.1.1"]


def test_enrich_caches_and_skips_failures(tmp_path):
    conn = store.connect(tmp_path / "e.db")
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if "abuseipdb" in request.url.host:
            return httpx.Response(200, json={"data": {"abuseConfidenceScore": 97, "totalReports": 40}})
        return httpx.Response(200, json={"status": "success", "country": "Nowhere", "isp": "ACME"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    r = enrich_ips(conn, ["203.0.113.5"], {"abuseipdb": "k"}, client)
    assert r["203.0.113.5"]["abuseipdb"]["score"] == 97 and r["203.0.113.5"]["geo"]["country"] == "Nowhere"
    n = len(calls)
    enrich_ips(conn, ["203.0.113.5"], {"abuseipdb": "k"}, client)
    assert len(calls) == n  # served from cache

    broken = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500, text="oops")))
    assert enrich_ips(conn, ["198.51.100.1"], {}, broken) == {}
    assert conn.execute("SELECT count(*) FROM ip_cache WHERE ip = '198.51.100.1'").fetchone()[0] == 0


# ---------- bench ----------

def test_bench_scores_injection_resistance(tmp_path):
    cfg = Config(db_path=str(tmp_path / "b.db"))
    scores = run_bench(["ollama/good"], cfg, store.connect(tmp_path / "b1.db"), mock_response=GOOD)
    assert scores[0].injection_resisted is True and scores[0].alerts == 7
    scores = run_bench(["ollama/fooled"], cfg, store.connect(tmp_path / "b2.db"), mock_response=FOOLED)
    assert scores[0].injection_resisted is False
    assert "FOOLED" in to_markdown(scores)


def test_bench_reports_unreachable_model(tmp_path, monkeypatch):
    def boom(**_):
        raise litellm.Timeout("t", "m", "p")

    monkeypatch.setattr(litellm, "completion", boom)
    scores = run_bench(["ollama/down"], Config(), store.connect(tmp_path / "b.db"))
    assert scores[0].error and "No model produced results" in to_markdown(scores)


START, END = "<!-- BENCH:START -->", "<!-- BENCH:END -->"


def test_splice_readme_replaces_only_between_markers():
    text = f"intro\n{START}\nold\n{END}\nouter\n"
    assert splice_readme(text, "| a |\n") == f"intro\n{START}\n| a |\n{END}\nouter\n"


@pytest.mark.parametrize("text", [
    "no markers", f"{START}\nonly start", f"only end\n{END}", f"{END}\nx\n{START}",
    f"{START}\na\n{END}\n{START}\nb\n{END}", f"{START}\n{START}\n{END}", f"{START}\n{END}\n{END}",
])
def test_splice_readme_rejects_missing_duplicate_or_reversed_markers(text):
    with pytest.raises(ValueError):
        splice_readme(text, "| a |\n")


def test_to_markdown_neutralizes_hostile_model_names():
    good = dict(alerts=1, severity_ok=1, mitre_hits=1, mitre_total=1, valid_first_try=1, injection_resisted=True,
                latencies=[1000])
    scores = [ModelScore("a|b", **good), ModelScore(f"m{END}", **good), ModelScore("x\ny", **good),
              ModelScore("[x](http://e)", **good)]
    md = to_markdown(scores)
    assert len(md.splitlines()) == 2 + 4 and "<!--" not in md and "-->" not in md
    out = splice_readme(f"{START}\nold\n{END}\n", md)
    assert out.count(START) == 1 and out.count(END) == 1
    failed = to_markdown([ModelScore(f"e{START}|", error=f"bad|{END}\nz"), ModelScore("ok", **good)])
    assert len(failed.splitlines()) == 3 and "<!--" not in failed and "-->" not in failed
    cell = to_markdown([ModelScore("a|b [x]", **good)]).splitlines()[2].split(" | ")[0]
    assert cell == r"| a\|b \[x\]", repr(cell)
    hostile = to_markdown([ModelScore("m‮\x9b​z", **good)]).splitlines()[2].split(" | ")[0]
    assert hostile == "| m???z", repr(hostile)
