import json

import httpx
import litellm
import pytest

from sentiel import store
from sentiel.config import Config
from sentiel.models import effective_severity, is_contested
from sentiel.pipeline import demo_config, scan

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
    assert send({"telegram_bot_token": "SECRET", "telegram_chat_id": "1"}, "hi", client) is False
