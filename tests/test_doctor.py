import os
import sqlite3
import stat
import time
from datetime import UTC, datetime, timedelta

import litellm
import pytest
from typer.testing import CliRunner

from sentiel import store
from sentiel.cli import app
from sentiel.config import Config, Sources
from sentiel.doctor import run_checks
from sentiel.pipeline import DEMO_DIR

runner = CliRunner(env={"COLUMNS": "250"})


def _cfg(tmp_path, **kw) -> Config:
    src = Sources(windows=False, linux_auth=str(DEMO_DIR / "auth_log.txt"), json=[str(DEMO_DIR / "events.jsonl")])
    return Config(db_path=str(tmp_path / "s.db"), model="ollama/x", sources=src, **kw)


def _by_name(checks):
    return {c.name: c for c in checks}


def test_healthy_setup_has_no_critical_failure(tmp_path):
    checks = _by_name(run_checks(_cfg(tmp_path), ai=False))
    assert checks["database"].ok and checks["rules"].ok
    assert checks["rules"].detail.endswith(" loaded, 0 warnings")  # one warning may stand for many skipped rules
    assert "model" not in checks
    assert not checks["notify"].ok and not checks["notify"].critical
    assert not checks["heartbeat"].ok  # never ran


def test_recent_heartbeat_is_ok(tmp_path):
    from sentiel.pipeline import scan
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg.db_path)
    try:
        scan(conn, cfg, ai=False)
    finally:
        conn.close()
    assert _by_name(run_checks(cfg, ai=False))["heartbeat"].ok


@pytest.mark.parametrize("value", ["not-a-date", "2026-10-11T10:00:00"])
def test_corrupt_heartbeat_is_a_warning_not_a_crash(tmp_path, value):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg.db_path)
    store.set_state(conn, "heartbeat", value)
    conn.commit()
    conn.close()
    c = _by_name(run_checks(cfg, ai=False))["heartbeat"]
    assert not c.ok and not c.critical and c.detail == "invalid heartbeat value"


def test_stale_heartbeat_says_no_completed_cycle(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg.db_path)
    store.set_state(conn, "heartbeat", store.fmt_ts(datetime.now(UTC) - timedelta(hours=3)))
    conn.commit()
    conn.close()
    c = _by_name(run_checks(cfg, ai=False))["heartbeat"]
    assert not c.ok and not c.critical and c.detail == "no completed cycle in 3h"


def test_locked_database_is_a_warning_not_a_failure(tmp_path, monkeypatch):
    import sentiel.doctor as doctor_mod
    monkeypatch.setattr(doctor_mod, "DB_BUSY_TIMEOUT_MS", 100, raising=False)  # keep the test fast
    cfg = _cfg(tmp_path)
    store.connect(cfg.db_path).close()
    writer = sqlite3.connect(cfg.db_path, isolation_level=None)
    writer.execute("BEGIN IMMEDIATE")  # what a running `watch` holds while it writes
    try:
        t0 = time.monotonic()
        checks = _by_name(run_checks(cfg, ai=False))
        elapsed = time.monotonic() - t0
    finally:
        writer.rollback()
        writer.close()
    db = checks["database"]
    assert not db.ok and not db.critical
    assert db.detail == "busy: another process is writing (watch running?)"
    assert checks["heartbeat"].detail == "scan/watch never ran"  # still readable while another process writes
    assert elapsed < 3


def test_unreadable_source_is_a_warning(tmp_path):
    cfg = _cfg(tmp_path)
    cfg.sources.json_files = [str(tmp_path / "missing.jsonl")]
    c = _by_name(run_checks(cfg, ai=False))[f"source:{tmp_path / 'missing.jsonl'}"]
    assert not c.ok and not c.critical


def test_model_down_is_a_warning(tmp_path, monkeypatch):
    def boom(**_):
        raise litellm.Timeout("t", "m", "p")
    monkeypatch.setattr(litellm, "completion", boom)
    c = _by_name(run_checks(_cfg(tmp_path), ai=True))["model"]
    assert not c.ok and not c.critical


def test_doctor_cli_exits_1_on_read_only_database(tmp_path):
    db = tmp_path / "s.db"
    store.connect(db).close()
    os.chmod(db, stat.S_IREAD)
    try:
        f = tmp_path / "sentiel.toml"
        f.write_text(f'db_path = "{db.as_posix()}"\n[sources]\nwindows = false\n', encoding="utf-8")
        r = runner.invoke(app, ["doctor", "--no-ai", "-c", str(f)])
        assert r.exit_code == 1 and "database" in r.output and "FAIL" in r.output
    finally:
        os.chmod(db, stat.S_IREAD | stat.S_IWRITE)


def test_doctor_cli_reports_invalid_config_without_traceback(tmp_path):
    f = tmp_path / "sentiel.toml"
    f.write_text('notify_min_severity = "urgent"\n', encoding="utf-8")
    r = runner.invoke(app, ["doctor", "--no-ai", "-c", str(f)])
    assert r.exit_code == 1 and "config" in r.output and isinstance(r.exception, SystemExit)


def test_doctor_cli_reports_unreadable_config_without_traceback(tmp_path):
    r = runner.invoke(app, ["doctor", "--no-ai", "-c", str(tmp_path)])  # a directory: reading it raises OSError
    assert r.exit_code == 1 and "config" in r.output and isinstance(r.exception, SystemExit)


def test_doctor_config_error_does_not_echo_input(tmp_path):
    f = tmp_path / "sentiel.toml"
    f.write_text("[keys]\nabuseipdb = 999\n", encoding="utf-8")
    r = runner.invoke(app, ["doctor", "--no-ai", "-c", str(f)])
    assert r.exit_code == 1 and "config" in r.output and "999" not in r.output


def test_doctor_missing_sysmon_channel_is_warn(tmp_path, monkeypatch):
    import sys

    from sentiel import doctor

    def fake(state, stats, channels=()):
        stats[f"missing:{channels[0]}"] += 1
        return iter(())

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(doctor, "read_windows", fake)
    checks = doctor._check_sources(Config(sources=Sources(windows=True)))
    missing = [c for c in checks if c.detail == "channel not installed"]
    assert missing and all(not c.ok and not c.critical for c in missing)
