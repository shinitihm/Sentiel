import json
import re
import tomllib
from pathlib import Path

import litellm
import pytest
from typer.testing import CliRunner

from sentiel import __version__, store
from sentiel.bench import ModelScore
from sentiel.cli import app
from sentiel.config import Config, describe_error, load_config
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
    nasty = 'a"b\\c [red]x[/] \né\x7f'
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
    nasty = "a\u202eb\x9bc\u2028d\u200be"
    _set_field(conn, tmp_path, "Nasty", nasty)
    out = runner.invoke(app, ["set", "1", "false_positive", "--suppress", "Nasty", "--note", nasty,
                              "-c", str(cfg_file)])
    assert out.exit_code == 0, out.output
    text = out.output[out.output.index("[[suppress]]"):]
    (block,) = tomllib.loads(text)["suppress"]
    assert block["equals"] == nasty and block["reason"] == nasty
    assert not any(c in out.output for c in "\u202e\x9b\u2028\u200b")


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


def test_unknown_top_level_key_is_a_config_error(tmp_path):
    f = tmp_path / "sentiel.toml"
    f.write_text("intervall = 30\n", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        load_config(f)
    msg = describe_error(exc.value)
    assert "intervall" in msg and "Extra inputs are not permitted" in msg
    r = runner.invoke(app, ["scan", "--no-ai", "-c", str(f)])
    assert r.exit_code == 2 and "Invalid config" in plain(r.output) and "intervall" in plain(r.output)


@pytest.mark.parametrize("toml, name, secret", [
    ("[sources]\nwindos = true\n", "windos", None),
    ('[[sources.files]]\npath = "a.log"\nregx = "SECRET"\n', "regx", "SECRET"),
    ('[notify]\ntelegram_bot_tokn = "123:SECRET"\n', "telegram_bot_tokn", "SECRET"),
    ('[keys]\nabuseipdb_key = "SECRET"\n', "abuseipdb_key", "SECRET"),
])
def test_unknown_nested_key_names_the_key_never_the_value(tmp_path, toml, name, secret):
    f = tmp_path / "sentiel.toml"
    f.write_text(toml, encoding="utf-8")
    r = runner.invoke(app, ["scan", "--no-ai", "-c", str(f)])
    out = plain(r.output)
    assert r.exit_code == 2 and "Invalid config" in out and name in out
    if secret:
        assert secret not in out and "123:" not in out


def test_unknown_keys_message_lists_valid_names(tmp_path):
    f = tmp_path / "sentiel.toml"
    f.write_text('[keys]\nabuseipdb_key = "SECRET"\n', encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        load_config(f)
    assert "unknown key 'abuseipdb_key' in [keys] (valid: abuseipdb, virustotal)" in describe_error(exc.value)
    assert "SECRET" not in describe_error(exc.value)


def test_shipped_examples_still_load():
    text = (Path(__file__).resolve().parent.parent / "sentiel.example.toml").read_text(encoding="utf-8")
    cfg_line = re.compile(r"^(\[\[?[\w.]+\]\]?|[A-Za-z_]+ *= *.+)$")
    lines = []
    for ln in text.splitlines():
        m = re.match(r"^# ?(.*)$", ln)
        body = m.group(1) if m else ln
        if m and not cfg_line.match(re.sub(r"\s+#.*$", "", body).rstrip()):
            continue  # prose
        lines.append(body if m else ln)
    uncommented = "\n".join(lines)
    for src in (text, uncommented):
        data = tomllib.loads(src)
        cfg = Config.model_validate(data)
        assert cfg.interval == 30
    full = Config.model_validate(tomllib.loads(uncommented))
    assert full.digest_hour == 9 and full.group_window == 3600 and full.triage_concurrency == 1
    assert full.sources.json_files == ["C:/logs/app.jsonl"] and len(full.sources.files) == 1
    assert len(full.suppress) == 1 and full.rules_dirs == [] and full.disabled_rules == []


def test_bench_readme_flag_writes_atomically_and_keeps_file_on_error(tmp_path, monkeypatch):
    row = ModelScore("ollama/x", alerts=7, severity_ok=7, mitre_hits=7, mitre_total=7, valid_first_try=7,
                     injection_resisted=True, latencies=[1000])
    monkeypatch.setattr("sentiel.bench.run_bench", lambda *a, **k: [row])
    readme = tmp_path / "README.md"
    readme.write_bytes("# T\r\n<!-- BENCH:START -->\r\nold\r\n<!-- BENCH:END -->\r\ntail ç\r\n".encode())
    base = ["bench", "ollama/x", "--out", str(tmp_path / "b.md"), "-c", str(tmp_path / "missing.toml"), "--readme"]
    r = runner.invoke(app, base + ["--readme-file", str(readme)])
    assert r.exit_code == 0, r.output
    data = readme.read_bytes()
    assert b"\n" not in data.replace(b"\r\n", b"") and b"| ollama/x |" in data and b"old" not in data
    assert data.startswith(b"# T\r\n<!-- BENCH:START -->\r\n") and data.endswith(b"tail \xc3\xa7\r\n")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["README.md", "b.md"]
    bad = tmp_path / "bad.md"
    bad.write_bytes(b"no markers\r\n")
    r = runner.invoke(app, base + ["--readme-file", str(bad)])
    assert r.exit_code == 1 and "Traceback" not in r.output and bad.read_bytes() == b"no markers\r\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["README.md", "b.md", "bad.md"]
    r = runner.invoke(app, base + ["--readme-file", str(tmp_path / "nope.md")])
    assert r.exit_code == 1 and "Traceback" not in r.output


def _fake_bench(monkeypatch):
    calls = []
    row = ModelScore("ollama/x", alerts=7, severity_ok=7, mitre_hits=7, mitre_total=7, valid_first_try=7,
                     injection_resisted=True, latencies=[1000])

    def fake(*a, **k):
        calls.append(1)
        return [row]

    monkeypatch.setattr("sentiel.bench.run_bench", fake)
    return calls


def test_bench_readme_is_validated_before_running_the_models(tmp_path, monkeypatch):
    calls = _fake_bench(monkeypatch)
    bad = tmp_path / "bad.md"
    bad.write_bytes(b"no markers\r\n")
    out = tmp_path / "b.md"
    base = ["bench", "ollama/x", "--out", str(out), "-c", str(tmp_path / "missing.toml"), "--readme"]
    for target in (bad, tmp_path / "nope.md"):
        r = runner.invoke(app, base + ["--readme-file", str(target)])
        assert r.exit_code == 1 and "Traceback" not in r.output, r.output
    assert calls == [] and not out.exists() and bad.read_bytes() == b"no markers\r\n"


def test_bench_refuses_out_equal_to_readme_file(tmp_path, monkeypatch):
    calls = _fake_bench(monkeypatch)
    readme = tmp_path / "README.md"
    original = b"# T\n<!-- BENCH:START -->\nold\n<!-- BENCH:END -->\n"
    readme.write_bytes(original)
    r = runner.invoke(app, ["bench", "ollama/x", "--out", str(readme), "-c", str(tmp_path / "missing.toml"),
                            "--readme", "--readme-file", str(tmp_path / "." / "README.md")])
    assert r.exit_code == 1 and "Traceback" not in r.output
    assert calls == [] and readme.read_bytes() == original


def test_bench_readonly_readme_leaves_no_temp_file(tmp_path, monkeypatch):
    import os
    import stat

    _fake_bench(monkeypatch)
    readme = tmp_path / "README.md"
    original = b"# T\n<!-- BENCH:START -->\nold\n<!-- BENCH:END -->\n"
    readme.write_bytes(original)
    os.chmod(readme, stat.S_IREAD)
    try:
        r = runner.invoke(app, ["bench", "ollama/x", "--out", str(tmp_path / "b.md"), "-c",
                                str(tmp_path / "missing.toml"), "--readme", "--readme-file", str(readme)])
        if os.name == "nt":  # POSIX can replace a read-only file inside a writable folder
            assert r.exit_code == 1 and "Traceback" not in r.output, r.output
            assert readme.read_bytes() == original
        assert not list(tmp_path.glob(".sentiel-*.tmp"))
    finally:
        os.chmod(readme, stat.S_IWRITE | stat.S_IREAD)


def test_rules_test_reports_skipped_lines(tmp_path):
    events = tmp_path / "ev.jsonl"
    events.write_text("garbage\nmore garbage\n[1]\n", encoding="utf-8")
    rule = next(RULES_DIR.glob("*security_log_cleared*.yml"))
    r = runner.invoke(app, ["rules", "test", str(rule), str(events)])
    assert r.exit_code == 1 and "Traceback" not in r.output
    assert "3 lines skipped" in plain(r.output)


def test_set_help_shows_literal_suppress_block():
    r = runner.invoke(app, ["set", "--help"])
    assert r.exit_code == 0 and "[[suppress]]" in plain(r.output)


def test_safe_strips_terminal_controls():
    from sentiel.cli import safe

    nasty = "a\x1b[31mb\x1b]8;;http://x\x07c\x9bd\u202ee [red]x[/red]\u2028\u2029f g\nh"
    out = safe(nasty)
    assert not any(c in out for c in "\x1b\x07\x9b\u202e\u2028\u2029\n")
    assert out == "a?[31mb?]8;;http://x?c?d?e \\[red]x\\[/red]??f g?h"
    assert safe("plain text, 100% ok") == "plain text, 100% ok"
    assert safe("l1\nl2", keep_newlines=True) == "l1\nl2"


HOSTILE = "Evil \x1b[31mred\x1b]8;;http://x\x07 \u202erev \x9b [red]x[/red]"
HOSTILE_ID = "99999999-9999-4999-8999-999999999999"


def _hostile_rule_dir(tmp_path):
    src = next(RULES_DIR.glob("*security_log_cleared*.yml")).read_text(encoding="utf-8")
    src = re.sub(r"^title:.*$", lambda _: "title: " + json.dumps(HOSTILE), src, count=1, flags=re.M)
    src = re.sub(r"^id:.*$", "id: " + HOSTILE_ID, src, count=1, flags=re.M)
    d = tmp_path / "myrules"
    d.mkdir()
    (d / "evil.yml").write_text(src, encoding="utf-8")
    return d


def test_alerts_show_report_rules_list_hide_control_chars_in_third_party_titles(tmp_path):
    from sentiel.pipeline import demo_config, scan

    d = _hostile_rule_dir(tmp_path)
    db = tmp_path / "s.db"
    cfg_file = tmp_path / "sentiel.toml"
    cfg_file.write_text(f'db_path = "{db.as_posix()}"\nmodel = "ollama/x"\nrules_dirs = ["{d.as_posix()}"]\n',
                        encoding="utf-8")
    conn = store.connect(db)
    scan(conn, demo_config(Config(db_path=str(db), rules_dirs=[str(d)])), ai=False)
    (aid,) = [r["id"] for r in conn.execute("SELECT id FROM alerts WHERE rule_id = ?", (HOSTILE_ID,))]
    tri = {"verdict": "true_positive", "severity": "high", "summary": HOSTILE, "next_steps": [HOSTILE],
           "mitre_techniques": [HOSTILE], "confidence": 0.5}
    conn.execute("UPDATE alerts SET triage = ?, model = ?, mitre = ?, note = ? WHERE id = ?",
                 (json.dumps(tri), HOSTILE, json.dumps([HOSTILE]), HOSTILE, aid))
    conn.commit()
    conn.close()
    bad = "\x1b\x07\x9b\u202e"
    c = ["-c", str(cfg_file)]
    for args in (["alerts", "--all", *c], ["show", str(aid), *c], ["report", *c], ["rules", "list", *c],
                 ["rules", "list", "--skipped", *c],
                 ["rules", "test", str(d / "evil.yml"), str(DEMO_DIR / "events.jsonl")]):
        r = runner.invoke(app, args)
        assert r.exit_code == 0, (args, r.output, r.exception)
        assert not any(ch in r.output for ch in bad), args
        assert "Evil" in r.output, args


def test_rules_test_non_utf8_file_is_short_error(tmp_path):
    bad = tmp_path / "bin.yml"
    bad.write_bytes(b"title: \xff\xfe\x80 caf\xe9\n\xc3\x28\n")
    r = runner.invoke(app, ["rules", "test", str(bad), str(DEMO_DIR / "events.jsonl")])
    assert isinstance(r.exception, SystemExit) and r.exit_code == 1 and "Traceback" not in r.output
    events = tmp_path / "ev.jsonl"
    events.write_bytes(b"\xff\xfe\x00 not json\n")
    rule = next(RULES_DIR.glob("*security_log_cleared*.yml"))
    r = runner.invoke(app, ["rules", "test", str(rule), str(events)])
    assert isinstance(r.exception, SystemExit) and "Traceback" not in r.output


def _track_connect(monkeypatch):
    conns = []
    real = store.connect

    def connect(*a, **k):
        conns.append(real(*a, **k))
        return conns[-1]

    monkeypatch.setattr(store, "connect", connect)
    return conns


def _is_closed(conn):
    import sqlite3

    try:
        conn.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        return True
    return False


def test_demo_and_bench_close_connection_on_error(tmp_path, monkeypatch):
    conns = _track_connect(monkeypatch)

    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr("sentiel.cli.run_scan", boom)
    r = runner.invoke(app, ["demo", "--no-ai", "-c", str(tmp_path / "missing.toml")])
    assert isinstance(r.exception, RuntimeError) and len(conns) == 1 and _is_closed(conns[0])
    monkeypatch.setattr("sentiel.bench.run_bench", boom)
    r = runner.invoke(app, ["bench", "ollama/x", "--out", str(tmp_path / "b.md"), "-c", str(tmp_path / "missing.toml")])
    assert isinstance(r.exception, RuntimeError) and len(conns) == 2 and _is_closed(conns[1])


def test_bench_out_written_even_if_a_later_model_fails(tmp_path, monkeypatch):
    from types import SimpleNamespace

    def fake_triage(alert, events, http, model, mock, timeout):
        if model == "bad/model":
            raise RuntimeError("kaboom")
        t = SimpleNamespace(severity="high", mitre_techniques=[], verdict="true_positive")
        return SimpleNamespace(triage=t, valid_first_try=True, latency_ms=10, cost_usd=0.0)

    monkeypatch.setattr("sentiel.bench.triage_alert", fake_triage)
    out = tmp_path / "b.md"
    r = runner.invoke(app, ["bench", "good/model,bad/model", "--out", str(out), "-c", str(tmp_path / "missing.toml")])
    assert isinstance(r.exception, RuntimeError)
    assert "good/model" in out.read_text(encoding="utf-8")


def test_write_atomic_keeps_file_mode(tmp_path):
    import os
    import sys

    from sentiel.cli import _write_atomic

    if sys.platform == "win32":
        pytest.skip("POSIX modes only")
    f = tmp_path / "R.md"
    f.write_text("old", encoding="utf-8")
    os.chmod(f, 0o640)
    _write_atomic(f, "new")
    assert f.read_text(encoding="utf-8") == "new" and (f.stat().st_mode & 0o777) == 0o640


def test_config_errors_sanitize_and_cap_key_names(tmp_path):
    f = tmp_path / "sentiel.toml"
    for toml in ('[keys]\n"\\u001b[31mX" = "SECRET"\n', '"\\u001b[31mX" = 1\n'):
        f.write_text(toml, encoding="utf-8")
        with pytest.raises(ValueError) as exc:
            load_config(f)
        msg = describe_error(exc.value)
        assert "\x1b" not in msg and "?[31mX" in msg and "SECRET" not in msg
        for cmd in ("scan", "doctor"):
            r = runner.invoke(app, [cmd, "--no-ai", "-c", str(f)])
            assert "\x1b" not in r.output and "SECRET" not in r.output
    huge = "k" * 10_000
    for toml in (f'[keys]\n{huge} = "SECRET"\n', f"{huge} = 1\n"):
        f.write_text(toml, encoding="utf-8")
        with pytest.raises(ValueError) as exc:
            load_config(f)
        msg = describe_error(exc.value)
        assert huge not in msg and "..." in msg and len(msg) < 600 and "SECRET" not in msg
        for cmd in ("scan", "doctor"):
            r = runner.invoke(app, [cmd, "--no-ai", "-c", str(f)])
            assert huge not in r.output and "SECRET" not in r.output and "Traceback" not in r.output


def test_env_vars_fill_model_keys_notify_after_validation(tmp_path, monkeypatch):
    env = {"SENTIEL_MODEL": "ollama/envmodel", "ABUSEIPDB_API_KEY": "a-key", "VT_API_KEY": "v-key",
           "TELEGRAM_BOT_TOKEN": "123:tok", "TELEGRAM_CHAT_ID": "42", "DISCORD_WEBHOOK": "https://d.example/w"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    f = tmp_path / "empty.toml"
    f.write_text("", encoding="utf-8")
    cfg = load_config(f)
    assert cfg.model == "ollama/envmodel"
    assert cfg.keys == {"abuseipdb": "a-key", "virustotal": "v-key"}
    assert cfg.notify == {"telegram_bot_token": "123:tok", "telegram_chat_id": "42",
                          "discord_webhook": "https://d.example/w"}


def test_show_hides_c1_bidi_and_zero_width_in_event_json(tmp_path):
    cfg_file, conn = _populated(tmp_path)
    (eid,) = json.loads(conn.execute("SELECT event_ids FROM alerts WHERE id = 1").fetchone()[0])[:1]
    raw = json.loads(conn.execute("SELECT raw FROM logs WHERE id = ?", (eid,)).fetchone()[0])
    raw["fields"]["Hostile"] = "a\x1b[31mb\x9bc\u202ed\u200be"
    conn.execute("UPDATE logs SET raw = ? WHERE id = ?", (json.dumps(raw), eid))
    conn.commit()
    r = runner.invoke(app, ["show", "1", "-c", str(cfg_file)])
    assert r.exit_code == 0, (r.output, r.exception)
    assert "Hostile" in r.output
    assert not any(c in r.output for c in "\x1b\x9b\u202e\u200b")


def test_multiline_ai_text_keeps_line_breaks_but_no_controls(tmp_path, monkeypatch):
    from types import SimpleNamespace

    cfg_file, conn = _populated(tmp_path)
    tri = {"verdict": "true_positive", "severity": "high", "summary": "sum1\nsum2\x1b", "next_steps": ["step1\nstep2"],
           "mitre_techniques": [], "confidence": 0.5}
    conn.execute("UPDATE alerts SET triage = ?, model = 'm' WHERE id = 1", (json.dumps(tri),))
    conn.commit()
    out = runner.invoke(app, ["show", "1", "-c", str(cfg_file)]).output
    lines = out.splitlines()
    for a, b in (("sum1", "sum2"), ("step1", "step2")):
        assert [i for i, ln in enumerate(lines) if a in ln] != [i for i, ln in enumerate(lines) if b in ln]
    assert "\x1b" not in out
    fake = SimpleNamespace(sql="SELECT 1\nFROM x", answer="ans1\nans2\x1b")
    monkeypatch.setattr("sentiel.chat.ask", lambda *a, **k: fake)
    out = runner.invoke(app, ["chat", "q", "-c", str(cfg_file)]).output
    assert "ans1\nans2" in out and "\x1b" not in out
    sql_lines = out.splitlines()
    at = [[i for i, ln in enumerate(sql_lines) if s in ln] for s in ("SELECT 1", "FROM x")]
    assert at[0] and at[1] and at[0] != at[1]


def test_describe_error_caps_number_of_errors_and_length(tmp_path):
    f = tmp_path / "sentiel.toml"
    f.write_text("".join(f"k{i} = 1\n" for i in range(30)), encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        load_config(f)
    msg = describe_error(exc.value)
    assert "k0" in msg and "k29" not in msg and "and 20 more" in msg and len(msg) <= 1500
