from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, field_validator

SigmaLevel = Literal["informational", "low", "medium", "high", "critical"]
Severity = Literal["info", "low", "medium", "high", "critical"]

RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITIES: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")


class Event(BaseModel):
    ts: datetime
    source: Literal["windows", "linux", "json"]
    host: str
    fields: dict[str, str | int | None]

    @field_validator("ts")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        try:
            return v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC)
        except (OverflowError, OSError) as e:  # e.g. year 1 / 9999 once shifted to UTC
            raise ValueError("timestamp out of range") from e


class Alert(BaseModel):
    id: int | None = None
    rule_id: str
    rule_title: str
    sigma_level: SigmaLevel
    mitre: list[str]
    ts: datetime
    event_ids: list[int]
    status: str = "open"
    note: str | None = None
    count: int = 1
    last_ts: datetime | None = None
    host: str | None = None
    group_key: str | None = None
    fresh: int | None = None  # correlations: events of the burst newer than the detection cursor


class Triage(BaseModel):
    severity: Severity
    verdict: Literal["true_positive", "benign", "needs_review"]
    mitre_techniques: list[str]
    summary: str
    next_steps: list[str]


def effective_severity(sigma_level: str, triage: Triage | None) -> Severity:
    """The LLM may raise severity but never lower what the Sigma rule says."""
    rank = max(RANK[sigma_level], RANK[triage.severity] if triage else 0)
    return SEVERITIES[rank]


def is_contested(sigma_level: str, triage: Triage | None) -> bool:
    return triage is not None and triage.verdict == "benign" and RANK[sigma_level] >= RANK["high"]
