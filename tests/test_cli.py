import re

import pytest
from typer.testing import CliRunner

from sentiel import store
from sentiel.cli import app
from sentiel.config import Config, load_config

runner = CliRunner(env={"COLUMNS": "250"})


def plain(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def test_demo_without_ai_lists_all_seven_attacks():
    r = runner.invoke(app, ["demo", "--no-ai"])
    assert r.exit_code == 0, r.output
    out = plain(r.output)
    assert "7 new alerts" in out
    for title in ("SSH brute force", "Security Event Log Cleared", "PowerShell With Encoded Command"):
        assert title in out


def test_alerts_report_and_show_on_a_populated_db(tmp_path):
    from sentiel.pipeline import demo_config, scan

    db = tmp_path / "s.db"
    cfg_file = tmp_path / "sentiel.toml"
    cfg_file.write_text(f'db_path = "{db.as_posix()}"\nmodel = "ollama/x"\n', encoding="utf-8")
    scan(store.connect(db), demo_config(Config(db_path=str(db))), ai=False)

    assert "Windows logon brute force" in plain(runner.invoke(app, ["alerts", "-c", str(cfg_file)]).output)
    assert "Alerts by severity" in runner.invoke(app, ["report", "-c", str(cfg_file)]).output
    shown = runner.invoke(app, ["show", "1", "-c", str(cfg_file)])
    assert shown.exit_code == 0 and "Not triaged yet" in plain(shown.output)
    assert runner.invoke(app, ["show", "999", "-c", str(cfg_file)]).exit_code != 0


def test_config_defaults_and_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTIEL_MODEL", "anthropic/claude-sonnet-5-5")
    monkeypatch.setenv("DISCORD_WEBHOOK", "https://example/hook")
    cfg = load_config(tmp_path / "missing.toml")
    assert cfg.model == "anthropic/claude-sonnet-5-5" and cfg.notify["discord_webhook"] == "https://example/hook"


def test_invalid_config_value_is_rejected(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text('notify_min_severity = "urgent"\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(f)
