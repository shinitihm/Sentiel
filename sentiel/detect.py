import functools
import re
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from itertools import groupby
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import (
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.rule import SigmaRule

from .config import Config
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
    origin: str = ""


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
    origin: str = ""


LOOKBACK = timedelta(hours=1)


def _meta(r) -> tuple[tuple[str, ...], str]:
    mitre = tuple(t.name.upper() for t in r.tags if t.namespace == "attack" and _TECHNIQUE.match(t.name))
    return mitre, r.level.name.lower() if r.level else "medium"


def _correlation_where(backend, corr: SigmaCorrelationRule) -> str:
    parts = []
    for ref in corr.rules:
        base = ref.rule
        if not isinstance(base, SigmaRule):
            raise ValueError("correlating another correlation")
        # ponytail: `_output` is private pySigma API (False on correlation bases, so convert_rule yields []);
        # pinned by test_base_rule_sql_relies_on_pysigma_output_flag
        was, base._output = base._output, True
        try:
            sqls = backend.convert_rule(base)
        finally:
            base._output = was
        # bounded by :start, or the subquery materializes the whole logs table before the outer ts filter
        clause = " OR ".join(f"id IN (SELECT id FROM ({q}) WHERE ts >= :start)" for q in sqls)
        if base.logsource.product in ("windows", "linux"):
            clause = f"source = '{base.logsource.product}' AND ({clause})"
        parts.append(f"({clause})")
    return " OR ".join(parts)


def _to_correlation(backend, corr: SigmaCorrelationRule, path: Path) -> Correlation:
    def bad(why):
        return ValueError(f"correlation {corr.title!r}: unsupported ({why})")
    if corr.type != SigmaCorrelationType.EVENT_COUNT:
        raise bad(f"type {corr.type.name.lower()}")
    if corr.condition.op != SigmaCorrelationConditionOperator.GTE:
        raise bad(f"condition {corr.condition.op.name.lower()}")
    if len(corr.group_by or []) != 1:
        raise bad("group-by needs exactly 1 field")
    mitre, level = _meta(corr)
    return Correlation(corr.name or str(corr.id), corr.title, level, mitre, _correlation_where(backend, corr),
                       corr.group_by[0], corr.condition.count, timedelta(seconds=corr.timespan.seconds), str(path))


@functools.lru_cache(maxsize=8)
def _load(
    signature: tuple[tuple[str, tuple[tuple[str, int], ...]], ...],
) -> tuple[tuple[Rule | Correlation, ...], tuple[str, ...]]:
    # `signature` is the cache key and the input: per rules dir, every .yml/.yaml path and mtime. Any change = new key.
    backend = sqliteBackend()
    warnings, parsed = [], []
    for _, files in signature:
        for fname, _ in files:
            path = Path(fname)
            try:
                parsed.append((path, SigmaCollection.from_yaml(path.read_text(encoding="utf-8"),
                                                               resolve_references=False)))
            except Exception as e:  # pySigma raises many unrelated exception types
                warnings.append(f"{path.name}: {e}")
    merged = SigmaCollection.merge([c for _, c in parsed], resolve_references=False)
    origin = {id(r): p for p, c in parsed for r in c.rules}
    # resolve every correlation first: that is what flips its bases to `_output=False`
    ok = []
    for r in merged.rules:
        if isinstance(r, SigmaCorrelationRule):
            outputs = [(b, b._output) for b in merged.rules if isinstance(b, SigmaRule)]
            try:
                r.resolve_rule_references(merged)
                ok.append(r)
            except Exception as e:
                for b, was in outputs:  # a reference that failed midway must not mute the bases it already resolved
                    b._output = was
                warnings.append(f"{origin[id(r)].name}: correlation {r.title!r}: {e}")
    rules: list[Rule | Correlation] = []
    seen: dict[str, str] = {}
    skipped: dict[str, int] = {}
    skipped_rules: set[str] = set()

    def keep(rule: Rule | Correlation, products: set[str | None], path: Path) -> None:
        bad = sorted(p for p in products if p not in (None, "windows", "linux"))  # logs we do not collect
        if bad:
            for p in bad:
                skipped[p] = skipped.get(p, 0) + 1
            skipped_rules.add(rule.id)
        elif rule.id in seen:
            warnings.append(f"duplicate rule id {rule.id} in {path.name} (kept {seen[rule.id]})")
        else:
            seen[rule.id] = str(path)
            rules.append(rule)

    for r in merged.rules:
        path = origin[id(r)]
        try:
            if isinstance(r, SigmaCorrelationRule):
                if r in ok:
                    products = {ref.rule.logsource.product for ref in r.rules}
                    keep(_to_correlation(backend, r, path), products, path)
            else:
                queries = tuple(backend.convert_rule(r))
                if queries:  # a correlation base converts to [] and is not a standalone rule
                    mitre, level = _meta(r)
                    keep(Rule(str(r.id), r.title, level, mitre, r.logsource.product, queries, str(path)),
                         {r.logsource.product}, path)
        except Exception as e:
            warnings.append(f"{path.name}: {e}")
    if skipped:
        names = ", ".join(sorted(skipped))[:200]
        warnings.append(f"{len(skipped_rules)} rules skipped: product not collected ({names})")
    return tuple(rules), tuple(warnings)


def load_rules(*rules_dirs: Path) -> tuple[list[Rule | Correlation], list[str]]:
    """Returns (rules, warnings). A rule that fails to parse or convert is skipped, not fatal.

    All .yml/.yaml files of all dirs form one collection, so a correlation may reference a rule in another file.
    Conversion is cached and re-run only when a rule file is added, removed or modified.
    On a duplicate id the first dir wins; rules for products we do not collect are skipped.
    """
    signature, warnings = [], []
    for d in rules_dirs or (RULES_DIR,):
        try:
            files = sorted([*Path(d).rglob("*.yml"), *Path(d).rglob("*.yaml")])
            signature.append((str(d), tuple((str(p), p.stat().st_mtime_ns) for p in files)))
        except OSError as e:
            warnings.append(f"rules dir unreadable: {d} ({e.strerror or e})")
    rules, load_warnings = _load(tuple(signature))
    return list(rules), warnings + list(load_warnings)


def rules_for(cfg: Config) -> tuple[list[Rule | Correlation], list[str]]:
    """Builtin rules + cfg.rules_dirs, minus cfg.disabled_rules. Never raises on a bad dir."""
    warnings, dirs = [], []
    for d in cfg.rules_dirs:
        path = Path(d).expanduser()
        if path.is_dir():
            dirs.append(path)
        else:
            warnings.append(f"rules dir not found: {d}")
    rules, load_warnings = load_rules(RULES_DIR, *dirs)
    known = {r.id for r in rules}
    warnings += [f"disabled_rules: unknown id {i}" for i in cfg.disabled_rules if i not in known]
    warnings += [f"suppress: unknown rule_id {i}" for i in dict.fromkeys(s.rule_id for s in cfg.suppress)
                 if i not in known]
    off = set(cfg.disabled_rules)
    return [r for r in rules if r.id not in off], warnings + load_warnings


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
    # ponytail: 1h lookback bounds the re-scan, so a long attack is re-detected every cycle with a shifted first event;
    # `store.insert_alerts` merges it into the open alert (group_window) and adds only `fresh` (new) events to count
    start = fmt_ts(parse_ts(first_new) - LOOKBACK)
    rows = query_tolerant(
        conn, f"SELECT id, ts, {quote(c.key)} AS k FROM logs WHERE ({c.where}) AND ts >= :start "
        f"AND {quote(c.key)} IS NOT NULL ORDER BY k, ts", {"start": start})
    alerts = []
    for _, group in groupby(rows, key=lambda r: r["k"]):
        for burst in _bursts(list(group), c.window):
            if max(r["id"] for r in burst) <= since_id:
                continue
            if _dense([parse_ts(r["ts"]) for r in burst], c.threshold, c.window):
                alerts.append(Alert(rule_id=c.id, rule_title=c.title, sigma_level=c.level, mitre=list(c.mitre),
                                    ts=parse_ts(burst[0]["ts"]), event_ids=[r["id"] for r in burst[:50]],
                                    count=len(burst), fresh=sum(r["id"] > since_id for r in burst),
                                    last_ts=parse_ts(burst[-1]["ts"]), group_key=str(burst[0]["k"])))
    return alerts


def detect(conn: sqlite3.Connection, rules: list[Rule | Correlation], since_id: int,
           warnings: list[str] | None = None) -> list[Alert]:
    """A rule that fails at runtime (bad regex, SQL error) is skipped and appended to `warnings`."""
    alerts = []
    for r in rules:
        try:
            alerts += (_run_correlation if isinstance(r, Correlation) else _run_rule)(conn, r, since_id)
        except (sqlite3.Error, re.error) as e:
            if "locked" in str(e) or "busy" in str(e):
                raise  # transient: fail the cycle so the cursor stays put and nothing is lost
            if warnings is not None:
                warnings.append(f"rule {r.id}: {e}")
    return sorted(alerts, key=lambda a: a.ts)
