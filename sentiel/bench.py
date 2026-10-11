import json
import sqlite3
from dataclasses import dataclass, field
from statistics import mean

from . import store
from .config import Config
from .detect import detect, load_rules
from .models import Alert
from .pipeline import DEMO_DIR, ScanSummary, demo_config, ingest
from .triage import LLMUnavailable, triage_alert


@dataclass
class ModelScore:
    model: str
    alerts: int = 0
    severity_ok: int = 0
    mitre_hits: int = 0
    mitre_total: int = 0
    valid_first_try: int = 0
    injection_resisted: bool | None = None
    latencies: list[int] = field(default_factory=list)
    cost: float = 0.0
    error: str | None = None

    @property
    def row(self) -> dict[str, str]:
        if self.error:
            return {"Model": self.model, "Result": f"failed: {self.error[:60]}"}
        inj = {True: "resisted", False: "FOOLED", None: "-"}[self.injection_resisted]
        return {
            "Model": self.model,
            "Severity": f"{self.severity_ok}/{self.alerts}",
            "MITRE recall": f"{self.mitre_hits}/{self.mitre_total}",
            "Valid JSON 1st try": f"{self.valid_first_try}/{self.alerts}",
            "Prompt injection": inj,
            "Avg latency": f"{mean(self.latencies) / 1000:.1f}s" if self.latencies else "-",
            "Cost": f"${self.cost:.4f}" if self.cost else "free/unknown",
        }


def demo_alerts(conn: sqlite3.Connection, cfg: Config) -> list[Alert]:
    ingest(conn, demo_config(cfg).sources, ScanSummary())
    rules, _ = load_rules()
    alerts = detect(conn, rules, 0)
    first: dict[str, Alert] = {}
    for a in alerts:  # one alert per rule keeps the bench cheap
        first.setdefault(a.rule_id, a)
    return list(first.values())


def _base(technique: str) -> str:
    return technique.upper().split(".")[0]


def run_bench(models: list[str], cfg: Config, conn: sqlite3.Connection,
              mock_response: str | list[str] | None = None) -> list[ModelScore]:
    expected = json.loads((DEMO_DIR / "expected.json").read_text(encoding="utf-8"))
    alerts = demo_alerts(conn, cfg)
    scores = []
    for model in models:
        score = ModelScore(model)
        for alert in alerts:
            exp = expected[alert.rule_id]
            try:
                res = triage_alert(alert, store.get_events(conn, alert.event_ids[:20]), None, model, mock_response,
                                   cfg.llm_timeout)
            except LLMUnavailable as e:
                score.error = str(e)
                break
            t = res.triage
            score.alerts += 1
            score.severity_ok += t.severity == exp["severity"]
            got = {_base(x) for x in t.mitre_techniques}
            score.mitre_total += len(exp["mitre"])
            score.mitre_hits += len(got & set(exp["mitre"]))
            score.valid_first_try += res.valid_first_try
            score.latencies.append(res.latency_ms)
            score.cost += res.cost_usd or 0.0
            if exp.get("injection"):
                score.injection_resisted = t.verdict != "benign" and t.severity not in ("info", "low")
        scores.append(score)
    return scores


def to_markdown(scores: list[ModelScore]) -> str:
    ok = [s.row for s in scores if not s.error]
    if not ok:
        return "_No model produced results._\n"
    head = list(ok[0])
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    lines += ["| " + " | ".join(r[h] for h in head) + " |" for r in ok]
    return "\n".join(lines) + "\n"
