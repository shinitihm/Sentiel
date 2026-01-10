import json
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from . import __version__, store
from .config import Config, load_config
from .models import RANK, effective_severity, is_contested
from .pipeline import ScanSummary, demo_config, triage_pending
from .pipeline import scan as run_scan
from .triage import is_local

app = typer.Typer(help="Sentiel: a personal SOC with AI triage that works with any model.", no_args_is_help=True)
console = Console()

ConfigOpt = Annotated[Path, typer.Option("--config", "-c", help="Path to sentiel.toml")]
ModelOpt = Annotated[str | None, typer.Option("--model", "-m", help="LiteLLM model, e.g. ollama/llama3.1:8b")]
NoAiOpt = Annotated[bool, typer.Option("--no-ai", help="Skip LLM triage (detection only)")]

COLORS = {"info": "dim", "low": "cyan", "medium": "yellow", "high": "red", "critical": "bold white on red"}


def _setup(config: Path, model: str | None) -> tuple[Config, sqlite3.Connection]:
    cfg = load_config(config)
    if model:
        cfg.model = model
    return cfg, store.connect(cfg.db_path)


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
    for col, kw in (("ID", {"justify": "right"}), ("When (UTC)", {}), ("Severity", {}), ("Rule", {"ratio": 3}),
                    ("MITRE", {}), ("AI verdict", {})):
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
                  escape(alert.rule_title), ", ".join(alert.mitre), verdict)
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
                new = conn.execute("SELECT * FROM alerts WHERE id > ? ORDER BY id", (last,)).fetchall()
                if new:
                    console.print(alerts_table(new, "New alerts"))
            except Exception as e:  # keep the loop alive: one bad cycle must not stop monitoring
                console.print(f"[red]Cycle failed:[/] {escape(str(e))}")
            time.sleep(cfg.interval)
    except KeyboardInterrupt:
        console.print("\nStopped.")


@app.command()
def alerts(config: ConfigOpt = Path("sentiel.toml"), limit: int = 30) -> None:
    """List stored alerts."""
    _, conn = _setup(config, None)
    console.print(alerts_table(store.list_alerts(conn, limit)))


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
             f"MITRE (rule): {', '.join(alert.mitre) or '-'}   matching events: {len(alert.event_ids)}"]
    if triage:
        if is_contested(alert.sigma_level, triage):
            lines.append("[bold red]CONTESTED:[/] the AI called this benign, but the detection rule rates it "
                         f"{alert.sigma_level}. Severity stays {sev}. Verify manually.")
        lines += ["", f"[bold]AI ({escape(row['model'] or '?')}):[/] {triage.verdict}, severity {triage.severity}",
                  escape(triage.summary), "", "[bold]Next steps[/]", *[f" - {escape(s)}" for s in triage.next_steps],
                  f"MITRE (AI): {', '.join(triage.mitre_techniques) or '-'}"]
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
    cost = conn.execute("SELECT coalesce(sum(cost_usd), 0) FROM alerts").fetchone()[0]
    console.print(f"Contested by AI: {contested}   Triaged: {sum(1 for r in rows if r['triage'])}/{len(rows)}   "
                  f"AI cost so far: ${cost:.4f}")

