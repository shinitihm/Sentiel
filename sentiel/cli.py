import json
import shutil
import sqlite3
import tempfile
import time
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from . import __version__, store
from .collectors import read_json
from .config import Config, describe_error, load_config
from .detect import RULES_DIR, Correlation, detect, load_rules, rules_for
from .models import RANK, effective_severity, is_contested
from .notify import format_digest
from .pipeline import ScanSummary, demo_config, maybe_send_digest, send_digest, triage_pending
from .pipeline import scan as run_scan
from .triage import is_local

app = typer.Typer(help="Sentiel: a personal SOC with AI triage that works with any model.", no_args_is_help=True)
rules_app = typer.Typer(help="Inspect and test detection rules.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")
console = Console()

ConfigOpt = Annotated[Path, typer.Option("--config", "-c", help="Path to sentiel.toml")]
ModelOpt = Annotated[str | None, typer.Option("--model", "-m", help="LiteLLM model, e.g. ollama/llama3.1:8b")]
NoAiOpt = Annotated[bool, typer.Option("--no-ai", help="Skip LLM triage (detection only)")]

COLORS = {"info": "dim", "low": "cyan", "medium": "yellow", "high": "red", "critical": "bold white on red"}


def _load_config(path: Path) -> Config:
    try:
        return load_config(path)
    except (ValueError, OSError) as e:  # ValidationError, TOMLDecodeError, UnicodeDecodeError are ValueErrors
        console.print(f"[red]Invalid config:[/] {escape(describe_error(e))}")
        raise typer.Exit(2) from e


def _setup(config: Path, model: str | None) -> tuple[Config, sqlite3.Connection]:
    cfg = _load_config(config)
    if model:
        cfg.model = model
    try:
        return cfg, store.connect(cfg.db_path)
    except (store.SchemaTooNew, sqlite3.Error) as e:
        console.print(f"[red]Database error:[/] {escape(str(e))}")
        raise typer.Exit(1) from e


def _privacy_notice(conn: sqlite3.Connection, model: str) -> None:
    provider = model.split("/")[0]
    if is_local(model) or store.get_state(conn, f"cloud_ack:{provider}"):
        return
    console.print(Panel(f"Model [bold]{escape(model)}[/] is not local: alert details (and chat results) are sent to "
                        f"[bold]{escape(provider)}[/]. Use an [bold]ollama/...[/] model to keep logs on this machine.",
                        title="Privacy", border_style="yellow"))
    store.set_state(conn, f"cloud_ack:{provider}", "1")


def alerts_table(rows: list[sqlite3.Row], title: str = "Alerts") -> Table:
    t = Table(title=title, show_lines=False, expand=True)
    for col, kw in (("ID", {"justify": "right"}), ("When (UTC)", {}), ("Severity", {}), ("Status", {}),
                    ("Rule", {"ratio": 3}), ("Count", {"justify": "right"}), ("MITRE", {}), ("AI verdict", {})):
        t.add_column(col, **kw)
    for row in rows:
        alert, triage = store.row_to_alert(row)
        sev = effective_severity(alert.sigma_level, triage)
        if triage is None:
            verdict = "[dim]pending[/]"
        elif is_contested(alert.sigma_level, triage):
            verdict = "[bold red]CONTESTED[/] (AI said benign)"
        else:
            verdict = triage.verdict.replace("_", " ")
        t.add_row(str(alert.id), alert.ts.strftime("%m-%d %H:%M"), f"[{COLORS[sev]}] {sev.upper()} [/]",
                  escape(alert.status), escape(alert.rule_title), f"×{alert.count}" if alert.count > 1 else "",
                  escape(", ".join(alert.mitre)), verdict)
    return t


def _print_summary(s: ScanSummary) -> None:
    console.print(f"[bold]{s.new_events}[/] new events, [bold]{s.new_alerts}[/] new alerts, "
                  f"[bold]{s.triaged}[/] triaged, [bold]{s.pending}[/] pending, [bold]{s.notified}[/] notified"
                  + (f", {s.skipped_lines} unreadable lines skipped" if s.skipped_lines else ""))
    for w in s.warnings:
        console.print(f"[yellow]![/] {escape(w)}")


@app.command("scan")
def scan_cmd(config: ConfigOpt = Path("sentiel.toml"), model: ModelOpt = None, no_ai: NoAiOpt = False) -> None:
    """Read new logs, detect, triage with the LLM and notify."""
    cfg, conn = _setup(config, model)
    if not no_ai:
        _privacy_notice(conn, cfg.model)
    _print_summary(run_scan(conn, cfg, ai=not no_ai))
    console.print(alerts_table(store.list_alerts(conn, 15), "Latest alerts"))


@app.command()
def watch(config: ConfigOpt = Path("sentiel.toml"), model: ModelOpt = None, no_ai: NoAiOpt = False) -> None:
    """Keep scanning every `interval` seconds. Ctrl+C to stop."""
    cfg, conn = _setup(config, model)
    if not no_ai:
        _privacy_notice(conn, cfg.model)
    console.print(f"Watching every {cfg.interval}s with [bold]{escape(cfg.model)}[/]. Ctrl+C to stop.")
    try:
        while True:
            last = conn.execute("SELECT coalesce(max(id), 0) FROM alerts").fetchone()[0]
            try:
                _print_summary(run_scan(conn, cfg, ai=not no_ai))
                maybe_send_digest(conn, cfg)
                new = conn.execute("SELECT * FROM alerts WHERE id > ? ORDER BY id", (last,)).fetchall()
                if new:
                    console.print(alerts_table(new, "New alerts"))
            except Exception as e:  # keep the loop alive: one bad cycle must not stop monitoring
                console.print(f"[red]Cycle failed:[/] {escape(str(e))}")
            time.sleep(cfg.interval)
    except KeyboardInterrupt:
        console.print("\nStopped.")


@app.command()
def digest(config: ConfigOpt = Path("sentiel.toml")) -> None:
    """Send (or print, with no channel set) the last-24h summary now. Does not affect the daily schedule."""
    cfg, conn = _setup(config, None)
    delivered = send_digest(conn, cfg)
    if not delivered:
        console.print(escape(format_digest(store.digest_stats(conn, datetime.now(UTC) - timedelta(hours=24)))))
    elif not any(delivered.values()):
        console.print("[red]Digest delivery failed on every channel.[/]")
        raise typer.Exit(1)
    else:
        console.print("Digest sent.")


@app.command()
def alerts(config: ConfigOpt = Path("sentiel.toml"), limit: int = 30,
           all_: Annotated[bool, typer.Option("--all", help="Include closed, false-positive and suppressed")] = False,
           ) -> None:
    """List stored alerts (open and ack by default)."""
    _, conn = _setup(config, None)
    console.print(alerts_table(store.list_alerts(conn, limit, include_all=all_)))


@app.command("set")
def set_cmd(alert_id: int, status: str, note: Annotated[str | None, typer.Option("--note", help="Free text")] = None,
            suppress: Annotated[str | None, typer.Option(
                "--suppress", help="With false_positive: print a [[suppress]] block for this event field")] = None,
            config: ConfigOpt = Path("sentiel.toml")) -> None:
    """Set an alert's status: open, ack, closed or false_positive."""
    valid = tuple(s for s in store.STATUSES if s != "suppressed")  # suppressed only comes from the config file
    if status not in valid:
        raise typer.BadParameter(f"status must be one of: {', '.join(valid)}", param_hint="STATUS")
    if note is not None and len(note) > 1000:
        raise typer.BadParameter("note is limited to 1000 characters", param_hint="--note")
    if suppress is not None and status != "false_positive":
        raise typer.BadParameter("--suppress only works with the false_positive status", param_hint="--suppress")
    _, conn = _setup(config, None)
    row = store.get_alert(conn, alert_id)
    if row is None:
        raise typer.BadParameter(f"no alert with id {alert_id}")
    snippet = None
    if suppress is not None:
        first = store.get_events(conn, json.loads(row["event_ids"])[:1])
        value = first[0].get("fields", {}).get(suppress) if first else None
        if value is None:
            raise typer.BadParameter(f"the first event has no field {suppress!r}", param_hint="--suppress")
        snippet = _suppress_block(row["rule_id"], suppress, value, note or "marked false_positive with `sentiel set`")
    try:
        store.set_status(conn, alert_id, status, note)
    except sqlite3.OperationalError as e:  # e.g. "database is locked" by another process
        console.print(f"[red]Database error:[/] {escape(str(e))}")
        raise typer.Exit(1) from e
    console.print(f"Alert {alert_id} -> [bold]{escape(status)}[/]")
    if snippet:
        console.print("Paste this into your config to suppress it from now on (nothing was edited):")
        console.print(snippet, markup=False, highlight=False, soft_wrap=True)


def _toml_str(s: str) -> str:
    # JSON escapes are valid TOML; also escape control/format/separator chars (Cc, Cf, Zl, Zp: all in the BMP)
    return "".join(f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") else c
                   for c in json.dumps(s, ensure_ascii=False))


def _suppress_block(rule_id: str, field: str, value: object, reason: str) -> str:
    equals = str(value) if type(value) is int else _toml_str(str(value))
    return (f"[[suppress]]\nrule_id = {_toml_str(rule_id)}\nfield = {_toml_str(field)}\nequals = {equals}\n"
            f"reason = {_toml_str(reason)}")


@app.command()
def show(alert_id: int, config: ConfigOpt = Path("sentiel.toml")) -> None:
    """Show one alert with the AI triage and its first events."""
    _, conn = _setup(config, None)
    row = store.get_alert(conn, alert_id)
    if row is None:
        raise typer.BadParameter(f"no alert with id {alert_id}")
    alert, triage = store.row_to_alert(row)
    sev = effective_severity(alert.sigma_level, triage)
    lines = [f"[bold]{escape(alert.rule_title)}[/]  [{COLORS[sev]}] {sev.upper()} [/]  rule level: {alert.sigma_level}",
             f"MITRE (rule): {escape(', '.join(alert.mitre)) or '-'}   matching events: {len(alert.event_ids)}",
             f"Status: {escape(alert.status)}   count: {alert.count}   last seen: {alert.last_ts:%Y-%m-%d %H:%M} UTC"]
    if alert.note:
        lines.append(f"Note: {escape(alert.note)}")
    if triage:
        if is_contested(alert.sigma_level, triage):
            lines.append("[bold red]CONTESTED:[/] the AI called this benign, but the detection rule rates it "
                         f"{alert.sigma_level}. Severity stays {sev}. Verify manually.")
        lines += ["", f"[bold]AI ({escape(row['model'] or '?')}):[/] {triage.verdict}, severity {triage.severity}",
                  escape(triage.summary), "", "[bold]Next steps[/]", *[f" - {escape(s)}" for s in triage.next_steps],
                  f"MITRE (AI): {escape(', '.join(triage.mitre_techniques)) or '-'}"]
    else:
        lines.append("\n[dim]Not triaged yet. Run `sentiel triage`.[/]")
    console.print(Panel("\n".join(lines), title=f"Alert {alert.id}"))
    for e in store.get_events(conn, alert.event_ids[:3]):
        console.print_json(json.dumps(e["fields"], default=str))


@app.command()
def triage(config: ConfigOpt = Path("sentiel.toml"), model: ModelOpt = None) -> None:
    """Triage alerts that are still pending (e.g. the model was offline)."""
    cfg, conn = _setup(config, model)
    _privacy_notice(conn, cfg.model)
    s = ScanSummary()
    triage_pending(conn, cfg, s, None, None)
    _print_summary(s)


@app.command()
def report(config: ConfigOpt = Path("sentiel.toml")) -> None:
    """Summary of everything stored: severities, top rules, AI cost."""
    _, conn = _setup(config, None)
    rows = conn.execute("SELECT * FROM alerts").fetchall()
    if not rows:
        console.print("No alerts stored yet. Try `sentiel demo`.")
        return
    by_sev, by_rule, contested = {}, {}, 0
    for row in rows:
        alert, tri = store.row_to_alert(row)
        sev = effective_severity(alert.sigma_level, tri)
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_rule[alert.rule_title] = by_rule.get(alert.rule_title, 0) + 1
        contested += is_contested(alert.sigma_level, tri)
    t = Table(title="Alerts by severity")
    t.add_column("Severity")
    t.add_column("Count", justify="right")
    for sev in sorted(by_sev, key=RANK.get, reverse=True):
        t.add_row(f"[{COLORS[sev]}] {sev.upper()} [/]", str(by_sev[sev]))
    console.print(t)
    top = Table(title="Top rules")
    top.add_column("Rule")
    top.add_column("Alerts", justify="right")
    for title, n in sorted(by_rule.items(), key=lambda kv: -kv[1])[:5]:
        top.add_row(escape(title), str(n))
    console.print(top)
    fp = Table(title="False-positive rate by rule")
    fp.add_column("Rule")
    fp.add_column("Alerts", justify="right")
    fp.add_column("False positives", justify="right")
    fp.add_column("Rate", justify="right")
    stats: dict[str, list[int]] = {}
    titles: dict[str, str] = {}
    for row in rows:
        st = stats.setdefault(row["rule_id"], [0, 0])
        titles[row["rule_id"]] = row["rule_title"]
        st[0] += 1
        st[1] += row["status"] == "false_positive"
    for rid, (n, bad) in sorted(stats.items(), key=lambda kv: -kv[1][0])[:10]:  # ponytail: top 10 rules only
        fp.add_row(escape(titles[rid]), str(n), str(bad), f"{round(100 * bad / n)}%")
    console.print(fp)
    console.print(f"Suppressed: {sum(1 for r in rows if r['status'] == 'suppressed')}")
    cost = conn.execute("SELECT coalesce(sum(cost_usd), 0) FROM alerts").fetchone()[0]
    console.print(f"Contested by AI: {contested}   Triaged: {sum(1 for r in rows if r['triage'])}/{len(rows)}   "
                  f"AI cost so far: ${cost:.4f}")


@app.command()
def demo(model: ModelOpt = None, no_ai: NoAiOpt = False, config: ConfigOpt = Path("sentiel.toml")) -> None:
    """Run the full pipeline on built-in simulated attacks (7 attacks, one with prompt injection)."""
    cfg = demo_config(_load_config(config))
    if model:
        cfg.model = model
    with tempfile.TemporaryDirectory() as tmp:
        conn = store.connect(Path(tmp) / "demo.db")
        console.print(f"Simulated attacks on a Windows desktop and a Linux server. "
                      f"AI: {'off' if no_ai else '[bold]' + escape(cfg.model) + '[/]'}")
        _print_summary(run_scan(conn, cfg, ai=not no_ai))
        console.print(alerts_table(store.list_alerts(conn, 50), "Detected attacks"))
        if no_ai:
            console.print("\nRe-run without --no-ai (e.g. `ollama pull llama3.1:8b`) to see AI triage.")
        conn.close()


@app.command()
def bench(models: Annotated[str, typer.Argument(help="Comma-separated LiteLLM models")],
          out: Path = Path("bench.md"), config: ConfigOpt = Path("sentiel.toml")) -> None:
    """Compare models on the demo attacks: severity, MITRE recall, JSON validity, injection resistance, cost."""
    from .bench import run_bench, to_markdown

    model_list = [m.strip() for m in models.split(",") if m.strip()]
    if not model_list:
        raise typer.BadParameter("no models given")
    cfg = _load_config(config)
    with tempfile.TemporaryDirectory() as tmp:
        conn = store.connect(Path(tmp) / "bench.db")
        scores = run_bench(model_list, cfg, conn)
        conn.close()
    t = Table(title="Model benchmark (demo attacks)")
    rows = [s.row for s in scores]
    cols = list(next((r for r in rows if len(r) > 2), rows[0]))
    for c in cols:
        t.add_column(c)
    for r in rows:
        t.add_row(*[escape(r.get(c, "")) for c in cols])
    console.print(t)
    out.write_text(to_markdown(scores), encoding="utf-8")
    console.print(f"Markdown table written to {out}")


@app.command()
def chat(question: Annotated[str, typer.Argument(help="Question about your logs")], model: ModelOpt = None,
         config: ConfigOpt = Path("sentiel.toml")) -> None:
    """Ask a question in natural language; the model writes a read-only SQL query."""
    from .chat import ask
    from .triage import LLMUnavailable

    cfg, conn = _setup(config, model)
    _privacy_notice(conn, cfg.model)
    conn.close()
    try:
        res = ask(cfg.db_path, question, cfg.model, timeout=cfg.llm_timeout)
    except LLMUnavailable as e:
        console.print(f"[red]Model unavailable:[/] {escape(str(e))}")
        raise typer.Exit(1) from e
    console.print(Panel(escape(res.sql), title="SQL (read-only)", border_style="dim"))
    console.print(escape(res.answer))


@app.command()
def doctor(config: ConfigOpt = Path("sentiel.toml"), model: ModelOpt = None, no_ai: NoAiOpt = False) -> None:
    """Diagnose config, database, rules, log sources, model and notifications."""
    from .doctor import Check, run_checks

    try:
        cfg = load_config(config)
    except (ValueError, OSError) as e:  # invalid toml/values, or unreadable file (e.g. /etc/sentiel as non-root)
        checks = [Check("config", False, describe_error(e), critical=True)]
    else:
        if model:
            cfg.model = model
        checks = run_checks(cfg, ai=not no_ai)
    table = Table(title="Sentiel doctor")
    for col in ("Check", "Status", "Detail"):
        table.add_column(col)
    for c in checks:
        status = "[green]OK[/]" if c.ok else ("[red]FAIL[/]" if c.critical else "[yellow]WARN[/]")
        table.add_row(escape(c.name), status, escape(c.detail))
    console.print(table)
    if any(c.critical and not c.ok for c in checks):
        raise typer.Exit(1)


@rules_app.command("list")
def rules_list(config: ConfigOpt = Path("sentiel.toml"),
               skipped: Annotated[bool, typer.Option("--skipped", help="List load warnings")] = False) -> None:
    """List loaded detection rules and where they come from."""
    rules, warnings = rules_for(_load_config(config))
    builtin = RULES_DIR.resolve()
    t = Table(title="Detection rules")
    t.add_column("ID", overflow="fold")  # never ellipsized: ids are copied into disabled_rules
    for col in ("Title", "Level", "Kind", "Origin"):
        t.add_column(col)
    for r in rules:
        origin = Path(r.origin).resolve()
        where = "builtin" if origin.is_relative_to(builtin) else str(r.origin)
        t.add_row(escape(r.id), escape(r.title), r.level, "correlation" if isinstance(r, Correlation) else "sigma",
                  escape(where))
    console.print(t)
    console.print(f"{len(rules)} rules loaded, {len(warnings)} warnings")
    if skipped:
        for w in warnings:
            console.print(f"[yellow]![/] {escape(w)}")


@rules_app.command("test")
def rules_test(rule_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Self-contained rule file")],
               events_jsonl: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="JSON Lines events")],
               ) -> None:
    """Run one rule file against a JSONL events file and show what it would alert on."""
    with tempfile.TemporaryDirectory() as tmp:
        rules_dir = Path(tmp) / "rules"
        rules_dir.mkdir()
        shutil.copy(rule_file, rules_dir / rule_file.name)
        rules, warnings = load_rules(rules_dir)
        if not rules:
            console.print(f"[red]No rules loaded from[/] {escape(str(rule_file))}")
            for w in warnings:
                console.print(f"[yellow]![/] {escape(w)}")
            raise typer.Exit(1)
        conn = store.connect(Path(tmp) / "test.db")
        try:
            store.insert_events(conn, read_json(events_jsonl))
            found = detect(conn, rules, 0, warnings)
        finally:
            conn.close()  # an open DB file blocks temp dir cleanup on Windows
    for w in warnings:
        console.print(f"[yellow]![/] {escape(w)}")
    if not found:
        console.print("No match. Events must use the source the rule expects (logsource.product); "
                      "generic JSON lines are source=json.")
        raise typer.Exit(1)
    t = Table(title="Rule matches")
    for col in ("Rule", "First event (UTC)", "Events"):
        t.add_column(col)
    for a in found:
        t.add_row(escape(a.rule_title), a.ts.strftime("%Y-%m-%d %H:%M:%S"), str(len(a.event_ids)))
    console.print(t)


@app.command()
def version() -> None:
    """Print the version."""
    console.print(__version__)


if __name__ == "__main__":
    app()
