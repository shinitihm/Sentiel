import json
import re

import litellm
import pytest
from typer.testing import CliRunner

from sentiel import __version__, store
from sentiel.cli import app
from sentiel.config import Config, load_config
from sentiel.detect import RULES_DIR
from sentiel.pipeline import DEMO_DIR

runner = CliRunner(env={"COLUMNS": "250"})


def plain(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def _model_down(monkeypatch):
    def boom(**_):
        raise litellm.Timeout("t", "m", "p")
    monkeypatch.setattr(litellm, "completion", boom)


def test_version_prints_package_version():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0 and __version__ in r.output


def test_chat_with_model_down_exits_1_without_traceback(tmp_path, monkeypatch):
    _model_down(monkeypatch)
    cfg_file = tmp_path / "sentiel.toml"
    cfg_file.write_text(f'db_path = "{(tmp_path / "s.db").as_posix()}"\nmodel = "ollama/x"\n', encoding="utf-8")
    r = runner.invoke(app, ["chat", "how many alerts?", "-c", str(cfg_file)])
    assert r.exit_code == 1 and "Model unavailable" in plain(r.output)
    assert isinstance(r.exception, SystemExit) and "Traceback" not in r.output


def test_bench_with_all_models_down_still_writes_markdown(tmp_path, monkeypatch):
    _model_down(monkeypatch)
    out = tmp_path / "bench.md"
    r = runner.invoke(app, ["bench", "ollama/x", "--out", str(out), "-c", str(tmp_path / "missing.toml")])
    assert r.exit_code == 0, r.output
    assert out.read_text(encoding="utf-8") == "_No model produced results._\n"


def test_bench_with_empty_model_list_is_a_usage_error():
    r = runner.invoke(app, ["bench", ","])
    assert r.exit_code != 0 and not isinstance(r.exception, IndexError)


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


def test_rules_list_shows_builtin_rules_and_correlations(tmp_path):
    r = runner.invoke(app, ["rules", "list", "-c", str(tmp_path / "missing.toml")])
    out = plain(r.output)
    assert r.exit_code == 0 and "sentiel-bruteforce-ssh" in out and "correlation" in out and "builtin" in out
    assert "8 rules loaded, 0 warnings" in out


def test_rules_test_reports_matches_on_demo_events():
    rule = next(RULES_DIR.glob("*security_log_cleared*.yml"))
    r = runner.invoke(app, ["rules", "test", str(rule), str(DEMO_DIR / "events.jsonl")])
    assert r.exit_code == 0, r.output
    assert "Security Event Log Cleared" in plain(r.output)


def test_rules_test_correlation_file_is_self_contained():
    rule = RULES_DIR / "lnx_ssh_bruteforce.yml"
    events = runner.invoke(app, ["rules", "test", str(rule), str(DEMO_DIR / "events.jsonl")])
    assert events.exit_code == 1 and "No match" in plain(events.output)  # ssh failures live in auth_log.txt


def test_rules_test_broken_rule_file_exits_1(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: broken\ndetection: [", encoding="utf-8")
    r = runner.invoke(app, ["rules", "test", str(bad), str(DEMO_DIR / "events.jsonl")])
    assert r.exit_code == 1 and "bad.yml" in plain(r.output)


def test_rules_test_prints_runtime_rule_warning(tmp_path):
    bad = tmp_path / "re.yml"
    bad.write_text("title: Bad regex\nid: 88888888-8888-4888-8888-888888888888\nlogsource: {product: windows}\n"
                   "detection: {selection: {CommandLine|re: 'ab(?i)c'}, condition: selection}\nlevel: high\n",
                   encoding="utf-8")
    r = runner.invoke(app, ["rules", "test", str(bad), str(DEMO_DIR / "events.jsonl")])
    assert r.exit_code == 1 and "rule 88888888-8888-4888-8888-888888888888:" in plain(r.output)


def _populated(tmp_path):
    from sentiel.pipeline import demo_config, scan

    db = tmp_path / "s.db"
    cfg_file = tmp_path / "sentiel.toml"
    cfg_file.write_text(f'db_path = "{db.as_posix()}"\nmodel = "ollama/x"\n', encoding="utf-8")
    conn = store.connect(db)
    scan(conn, demo_config(Config(db_path=str(db))), ai=False)
    return cfg_file, conn


def test_set_command_and_invalid_status(tmp_path):
    cfg_file, conn = _populated(tmp_path)
    ok = runner.invoke(app, ["set", "1", "ack", "--note", "foo", "-c", str(cfg_file)])
    assert ok.exit_code == 0
    row = store.get_alert(conn, 1)
    assert row["status"] == "ack" and row["note"] == "foo"
    bad = runner.invoke(app, ["set", "1", "bogus", "-c", str(cfg_file)])
    assert bad.exit_code != 0 and "closed" in plain(bad.output)
    missing = runner.invoke(app, ["set", "999", "ack", "-c", str(cfg_file)])
    assert missing.exit_code != 0 and "no alert with id" in plain(missing.output)
    assert runner.invoke(app, ["set", "1", "suppressed", "-c", str(cfg_file)]).exit_code != 0


def test_alerts_all_flag(tmp_path):
    cfg_file, conn = _populated(tmp_path)
    store.set_status(conn, 1, "closed", None)
    default = plain(runner.invoke(app, ["alerts", "-c", str(cfg_file)]).output)
    full = plain(runner.invoke(app, ["alerts", "--all", "-c", str(cfg_file)]).output)
    assert "closed" not in default and "closed" in full


def test_report_shows_false_positive_rate(tmp_path):
    cfg_file, conn = _populated(tmp_path)
    conn.execute("DELETE FROM alerts WHERE id > 2")
    conn.execute("UPDATE alerts SET rule_id = 'same', rule_title = 'Same rule', first_event_id = id")
    conn.commit()
    store.set_status(conn, 1, "false_positive", None)
    out = plain(runner.invoke(app, ["report", "-c", str(cfg_file)]).output)
    assert "False-positive rate by rule" in out and "50%" in out


def test_suppress_config_validation():
    from pydantic import ValidationError

    from sentiel.config import Suppress

    assert Suppress(rule_id="r", field="f", equals=4625, reason="why").equals == 4625
    for bad in ({"rule_id": ""}, {"field": ""}, {"reason": ""}):
        with pytest.raises(ValidationError):
            Suppress(**{"rule_id": "r", "field": "f", "equals": "x", "reason": "why", **bad})


def test_set_suppress_prints_toml_that_roundtrips(tmp_path):
    import tomllib

    cfg_file, conn = _populated(tmp_path)
    row = store.get_alert(conn, 1)
    first = store.get_events(conn, [json.loads(row["event_ids"])[0]])[0]
    nasty = 'a"b\c [red]x[/] \né\x7f'
    conn.execute("UPDATE logs SET raw = ? WHERE id = ?",
                 (json.dumps({"ts": first["ts"], "host": first["host"], "fields": {**first["fields"], "Nasty": nasty}}),
                  first["id"]))
    conn.commit()
    out = runner.invoke(app, ["set", "1", "false_positive", "--suppress", "Nasty", "--note", nasty,
                              "-c", str(cfg_file)])
    assert out.exit_code == 0, out.output
    text = out.output[out.output.index("[[suppress]]"):]
    (block,) = tomllib.loads(text)["suppress"]
    assert block == {"rule_id": row["rule_id"], "field": "Nasty", "equals": nasty, "reason": nasty}
    assert "[red]x[/]" in out.output  # markup shows up literally
    assert store.get_alert(conn, 1)["status"] == "false_positive"


def test_set_suppress_keeps_int_values_as_numbers(tmp_path):
    import tomllib

    cfg_file, conn = _populated(tmp_path)
    fields = store.get_events(conn, [json.loads(store.get_alert(conn, 1)["event_ids"])[0]])[0]["fields"]
    name, value = next((k, v) for k, v in fields.items() if isinstance(v, int))
    out = runner.invoke(app, ["set", "1", "false_positive", "--suppress", name, "-c", str(cfg_file)])
    assert out.exit_code == 0, out.output
    (block,) = tomllib.loads(out.output[out.output.index("[[suppress]]"):])["suppress"]
    assert block["equals"] == value and block["reason"]


def test_set_suppress_rejects_wrong_status_and_missing_field(tmp_path):
    cfg_file, conn = _populated(tmp_path)
    bad_status = runner.invoke(app, ["set", "1", "closed", "--suppress", "EventID", "-c", str(cfg_file)])
    assert bad_status.exit_code != 0 and "false_positive" in plain(bad_status.output)
    missing = runner.invoke(app, ["set", "1", "false_positive", "--suppress", "NoSuchField", "-c", str(cfg_file)])
    assert missing.exit_code != 0 and "NoSuchField" in plain(missing.output)
    assert store.get_alert(conn, 1)["status"] == "open"  # a rejected command changes nothing


def test_set_note_is_limited_to_1000_chars(tmp_path):
    cfg_file, conn = _populated(tmp_path)
    r = runner.invoke(app, ["set", "1", "ack", "--note", "x" * 1001, "-c", str(cfg_file)])
    assert r.exit_code != 0 and store.get_alert(conn, 1)["status"] == "open"
    assert runner.invoke(app, ["set", "1", "ack", "--note", "x" * 1000, "-c", str(cfg_file)]).exit_code == 0


def test_set_note_with_markup_is_printed_literally(tmp_path):
    cfg_file, _ = _populated(tmp_path)
    assert runner.invoke(app, ["set", "1", "ack", "--note", "[bold]x[/]", "-c", str(cfg_file)]).exit_code == 0
    assert "Note: [bold]x[/]" in plain(runner.invoke(app, ["show", "1", "-c", str(cfg_file)]).output)


import httpx  # noqa: E402

_REAL_CLIENT = httpx.Client


def _digest_file(tmp_path, extra=""):
    f = tmp_path / "sentiel.toml"
    f.write_text(f'db_path = "{(tmp_path / "s.db").as_posix()}"\n{extra}', encoding="utf-8")
    return f


def _mock_http(monkeypatch, status):
    import httpx
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status)

    monkeypatch.setattr(httpx, "Client", lambda **kw: _REAL_CLIENT(transport=httpx.MockTransport(handler)))
    return calls


def test_digest_command_sends_or_prints(tmp_path, monkeypatch):
    f = _digest_file(tmp_path)
    r = runner.invoke(app, ["digest", "-c", str(f)])  # no channel: prints the text
    assert r.exit_code == 0 and "Sentiel digest" in plain(r.output)
    f = _digest_file(tmp_path, 'notify = {discord_webhook = "https://discord.example/hook"}\n')
    calls = _mock_http(monkeypatch, 200)
    r = runner.invoke(app, ["digest", "-c", str(f)])
    assert r.exit_code == 0 and len(calls) == 1
    assert store.get_state(store.connect(tmp_path / "s.db"), "digest_last") is None  # the command never marks it
    _mock_http(monkeypatch, 500)
    r = runner.invoke(app, ["digest", "-c", str(f)])
    assert r.exit_code == 1 and "Traceback" not in r.output


CONFIG_COMMANDS = [["scan"], ["watch"], ["alerts"], ["show", "1"], ["triage"], ["report"], ["set", "1", "ack"],
                   ["digest"], ["demo"], ["bench", "x"], ["rules", "list"], ["chat", "q"]]


def test_config_commands_cover_every_registered_command():
    names = {c.name or c.callback.__name__ for c in app.registered_commands}
    assert names - {"version", "doctor"} == {c[0] for c in CONFIG_COMMANDS} - {"rules"}  # rules test reads no config


@pytest.mark.parametrize("args", CONFIG_COMMANDS, ids=lambda a: " ".join(a))
def test_invalid_config_exits_2_without_traceback(tmp_path, args):
    f = tmp_path / "sentiel.toml"
    f.write_text('interval = "abc"\n', encoding="utf-8")
    r = runner.invoke(app, [*args, "-c", str(f)])
    assert r.exit_code == 2 and "Invalid config" in plain(r.output)
    assert isinstance(r.exception, SystemExit) and "Traceback" not in r.output


def test_invalid_config_does_not_echo_input_value(tmp_path):
    f = tmp_path / "sentiel.toml"
    f.write_text('[notify]\ntelegram_bot_token = 123456789\n[keys]\nabuseipdb = 999\n', encoding="utf-8")
    r = runner.invoke(app, ["alerts", "-c", str(f)])
    out = plain(r.output)
    assert r.exit_code == 2 and "Invalid config" in out and "123456789" not in out and "999" not in out
    f.write_text("interval = = 1\n", encoding="utf-8")
    assert runner.invoke(app, ["alerts", "-c", str(f)]).exit_code == 2
    f.write_bytes(b"\xff\xfe\x00bad")
    r = runner.invoke(app, ["alerts", "-c", str(f)])
    assert r.exit_code == 2 and isinstance(r.exception, SystemExit)


def test_cli_reports_newer_schema(tmp_path):
    import sqlite3

    db = tmp_path / "s.db"
    c = sqlite3.connect(db)
    c.execute("PRAGMA user_version = 99")
    c.close()
    f = tmp_path / "sentiel.toml"
    f.write_text(f'db_path = "{db.as_posix()}"\n', encoding="utf-8")
    r = runner.invoke(app, ["alerts", "-c", str(f)])
    assert r.exit_code == 1 and "v99 is newer than this Sentiel" in plain(r.output)
    assert isinstance(r.exception, SystemExit)


def _set_field(conn, tmp_path, name, value):
    row = store.get_alert(conn, 1)
    first = store.get_events(conn, [json.loads(row["event_ids"])[0]])[0]
    conn.execute("UPDATE logs SET raw = ? WHERE id = ?",
                 (json.dumps({"ts": first["ts"], "host": first["host"], "fields": {**first["fields"], name: value}}),
                  first["id"]))
    conn.commit()
    return row


@pytest.mark.parametrize("cols", ["80", "120"])
def test_set_suppress_long_values_do_not_wrap_the_toml(tmp_path, cols):
    import tomllib

    cfg_file, conn = _populated(tmp_path)
    long_value = "x" * 150
    note = "long note " * 30
    row = _set_field(conn, tmp_path, "Long", long_value)
    out = CliRunner(env={"COLUMNS": cols}).invoke(
        app, ["set", "1", "false_positive", "--suppress", "Long", "--note", note, "-c", str(cfg_file)])
    assert out.exit_code == 0, out.output
    (block,) = tomllib.loads(out.output[out.output.index("[[suppress]]"):])["suppress"]
    assert block == {"rule_id": row["rule_id"], "field": "Long", "equals": long_value, "reason": note}


def test_toml_str_escapes_control_and_format_characters(tmp_path):
    import tomllib

    cfg_file, conn = _populated(tmp_path)
    nasty = "a‮b\x9bc d​e"
    _set_field(conn, tmp_path, "Nasty", nasty)
    out = runner.invoke(app, ["set", "1", "false_positive", "--suppress", "Nasty", "--note", nasty,
                              "-c", str(cfg_file)])
    assert out.exit_code == 0, out.output
    text = out.output[out.output.index("[[suppress]]"):]
    (block,) = tomllib.loads(text)["suppress"]
    assert block["equals"] == nasty and block["reason"] == nasty
    assert not any(c in out.output for c in "‮\x9b ​")


def test_show_and_alerts_survive_markup_in_mitre(tmp_path):
    cfg_file, conn = _populated(tmp_path)
    tri = {"verdict": "true_positive", "severity": "high", "summary": "s", "next_steps": ["n"],
           "mitre_techniques": ["T1[/bold]"], "confidence": 0.5}
    conn.execute("UPDATE alerts SET triage = ?, model = 'm', mitre = ? WHERE id = 1",
                 (json.dumps(tri), json.dumps(["T9[/bold]"])))
    conn.commit()
    for args in (["show", "1"], ["alerts"], ["alerts", "--all"]):
        r = runner.invoke(app, [*args, "-c", str(cfg_file)])
        assert r.exit_code == 0, (args, r.output, r.exception)
    assert "T1[/bold]" in runner.invoke(app, ["show", "1", "-c", str(cfg_file)]).output


def test_set_on_locked_database_exits_1_without_traceback(tmp_path, monkeypatch):
    import sqlite3

    cfg_file, conn = _populated(tmp_path)
    conn.close()
    locker = sqlite3.connect(tmp_path / "s.db")
    locker.execute("BEGIN IMMEDIATE")
    real = sqlite3.connect
    monkeypatch.setattr(store.sqlite3, "connect", lambda p, **kw: real(p, **{**kw, "timeout": 0.1}))
    r = runner.invoke(app, ["set", "1", "ack", "-c", str(cfg_file)])
    locker.rollback()
    locker.close()
    assert r.exit_code == 1 and "locked" in plain(r.output) and isinstance(r.exception, SystemExit)


def test_store_connect_waits_up_to_30s_for_locks(tmp_path, monkeypatch):
    import sqlite3

    seen = {}
    real = sqlite3.connect

    def spy(p, **kw):
        seen.update(kw)
        return real(p, **kw)

    monkeypatch.setattr(store.sqlite3, "connect", spy)
    store.connect(tmp_path / "t.db").close()
    assert seen.get("timeout") == 30


def test_report_fp_rate_groups_by_rule_id_not_title(tmp_path):
    cfg_file, conn = _populated(tmp_path)
    conn.execute("DELETE FROM alerts WHERE id > 2")
    conn.execute("UPDATE alerts SET rule_title = 'Same title'")
    conn.commit()
    out = plain(runner.invoke(app, ["report", "-c", str(cfg_file)]).output)
    fp = out[out.index("False-positive rate by rule"):]
    assert fp.count("Same title") == 2


def test_group_window_has_a_30_day_ceiling():
    from pydantic import ValidationError

    assert Config(group_window=2592000).group_window == 2592000
    with pytest.raises(ValidationError):
        Config(group_window=2592001)


def test_group_window_too_large_exits_2(tmp_path):
    f = tmp_path / "sentiel.toml"
    f.write_text("group_window = 99999999\n", encoding="utf-8")
    assert runner.invoke(app, ["alerts", "-c", str(f)]).exit_code == 2


def test_suppress_config_is_strict():
    from pydantic import ValidationError

    from sentiel.config import Suppress

    base = {"rule_id": "r", "field": "f", "equals": "x", "reason": "why"}
    assert Suppress(**base).equals == "x"
    for bad in ({"equals": True}, {"equals": False}, {"equals": 1.5}, {"equals": None}, {"reason": "   "},
                {"extra_key": 1}):
        with pytest.raises(ValidationError):
            Suppress(**{**base, **bad})
