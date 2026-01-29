import re
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from itertools import groupby
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

from .models import Alert
from .store import fmt_ts, parse_ts, query_tolerant, quote

RULES_DIR = Path(__file__).parent / "rules"
_TECHNIQUE = re.compile(r"^t\d{4}(\.\d{3})?$")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    level: str
    mitre: tuple[str, ...]
    product: str | None
    queries: tuple[str, ...]


@dataclass(frozen=True)
class Correlation:
    """Threshold rule: >= `threshold` events with the same `key` within `window`."""
    id: str
    title: str
    level: str
    mitre: tuple[str, ...]
    where: str
    key: str
    threshold: int = 10
    window: timedelta = timedelta(minutes=5)


CORRELATIONS = (
    Correlation("sentiel-bruteforce-windows", "Windows logon brute force (>=10 failures in 5 min)", "high",
                ("T1110.001",), "source = 'windows' AND EventID = 4625", "IpAddress"),
    Correlation("sentiel-bruteforce-ssh", "SSH brute force (>=10 failures in 5 min)", "high",
                ("T1110.001",), "source = 'linux' AND event = 'ssh_failed'", "IpAddress"),
)
LOOKBACK = timedelta(hours=1)


def load_rules(rules_dir: Path = RULES_DIR) -> tuple[list[Rule], list[str]]:
    """Returns (rules, warnings). A rule that fails to parse or convert is skipped, not fatal."""
    backend = sqliteBackend()
    rules, warnings = [], []
    for path in sorted(Path(rules_dir).rglob("*.yml")):
        try:
            for r in SigmaCollection.from_yaml(path.read_text(encoding="utf-8")).rules:
                mitre = tuple(t.name.upper() for t in r.tags if t.namespace == "attack" and _TECHNIQUE.match(t.name))
                level = r.level.name.lower() if r.level else "medium"
                rules.append(Rule(str(r.id), r.title, level, mitre, r.logsource.product,
                                  tuple(backend.convert_rule(r))))
        except Exception as e:  # pySigma raises many unrelated exception types
            warnings.append(f"{path.name}: {e}")
    return rules, warnings


def _run_rule(conn: sqlite3.Connection, rule: Rule, since_id: int) -> list[Alert]:
    alerts = []
    for q in rule.queries:
        sql, params = f"SELECT id, ts FROM ({q}) WHERE id > ?", [since_id]
        if rule.product in ("windows", "linux"):
            sql += " AND source = ?"
            params.append(rule.product)
        rows = query_tolerant(conn, sql, params)
        alerts += [Alert(rule_id=rule.id, rule_title=rule.title, sigma_level=rule.level, mitre=list(rule.mitre),
                         ts=parse_ts(r["ts"]), event_ids=[r["id"]]) for r in rows]
    return alerts


def _bursts(rows: list, window: timedelta) -> list[list]:
    """Split time-ordered rows wherever the gap between neighbours exceeds `window`."""
    out: list[list] = []
    for r in rows:
        if out and parse_ts(r["ts"]) - parse_ts(out[-1][-1]["ts"]) <= window:
            out[-1].append(r)
        else:
            out.append([r])
    return out


def _dense(times: list, threshold: int, window: timedelta) -> bool:
    return any(times[i + threshold - 1] - times[i] <= window for i in range(len(times) - threshold + 1))


def _run_correlation(conn: sqlite3.Connection, c: Correlation, since_id: int) -> list[Alert]:
    first_new = conn.execute("SELECT min(ts) FROM logs WHERE id > ?", (since_id,)).fetchone()[0]
    if first_new is None:
        return []
    # ponytail: 1h lookback; an attack that keeps going for longer than that becomes a second alert
    start = fmt_ts(parse_ts(first_new) - LOOKBACK)
    rows = query_tolerant(
        conn, f"SELECT id, ts, {quote(c.key)} AS k FROM logs WHERE ({c.where}) AND ts >= ? "
        f"AND {quote(c.key)} IS NOT NULL ORDER BY k, ts", (start,))
    alerts = []
    for _, group in groupby(rows, key=lambda r: r["k"]):
        for burst in _bursts(list(group), c.window):
            if max(r["id"] for r in burst) <= since_id:
                continue
            if _dense([parse_ts(r["ts"]) for r in burst], c.threshold, c.window):
                alerts.append(Alert(rule_id=c.id, rule_title=c.title, sigma_level=c.level, mitre=list(c.mitre),
                                    ts=parse_ts(burst[0]["ts"]), event_ids=[r["id"] for r in burst[:50]]))
    return alerts


def detect(conn: sqlite3.Connection, rules: list[Rule], since_id: int) -> list[Alert]:
    alerts = [a for rule in rules for a in _run_rule(conn, rule, since_id)]
    alerts += [a for c in CORRELATIONS for a in _run_correlation(conn, c, since_id)]
    return sorted(alerts, key=lambda a: a.ts)
