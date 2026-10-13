import os
import re
import sys
import tomllib
import unicodedata
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from .models import Severity

ENV_KEYS = {
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "virustotal": "VT_API_KEY",
}
ENV_NOTIFY = {
    "telegram_bot_token": "TELEGRAM_BOT_TOKEN",
    "telegram_chat_id": "TELEGRAM_CHAT_ID",
    "discord_webhook": "DISCORD_WEBHOOK",
}


class FileSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    regex: str
    product: Literal["windows", "linux", "json"] = "json"

    @field_validator("regex")
    @classmethod
    def _compiles_with_named_groups(cls, v: str) -> str:
        try:
            rx = re.compile(v)
        except re.error as e:
            raise ValueError(f"invalid regex: {e}") from e
        if not rx.groupindex:
            raise ValueError("regex needs at least one named group, e.g. (?P<IpAddress>\\S+)")
        return v


class Sources(BaseModel):
    model_config = ConfigDict(extra="forbid")
    windows: bool = sys.platform == "win32"
    linux_auth: str | None = "/var/log/auth.log" if Path("/var/log/auth.log").exists() else None
    json_files: list[str] = Field(default_factory=list, alias="json")
    files: list[FileSource] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_paths(self) -> "Sources":
        seen: set[str] = set()
        for f in self.files:
            if f.path in seen:
                raise ValueError(f"duplicate path in sources.files: {f.path}")
            seen.add(f.path)
        return self


class Suppress(BaseModel):
    """Human-written rule: alerts of `rule_id` whose first event has `field == equals` are stored as suppressed."""
    rule_id: str = Field(min_length=1)
    field: str = Field(min_length=1)
    model_config = ConfigDict(extra="forbid")
    equals: StrictStr | StrictInt
    reason: str = Field(min_length=1)

    @field_validator("equals")
    @classmethod
    def _not_bool(cls, v: str | int) -> str | int:
        if isinstance(v, bool):  # bool is an int subclass: `equals = true` is almost surely a mistake
            raise ValueError("equals must be a string or an integer, not a boolean")
        return v

    @field_validator("reason")
    @classmethod
    def _reason_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("reason must not be blank")
        return v


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = "ollama/llama3.1:8b"
    interval: int = Field(30, ge=1)
    llm_timeout: int = Field(120, ge=5)
    max_triage_per_cycle: int = Field(50, ge=0)
    triage_concurrency: int = Field(1, ge=1)
    group_window: int = Field(3600, ge=0, le=2592000)  # seconds (max 30 days); 0 turns alert grouping off
    digest_hour: int | None = Field(None, ge=0, le=23)  # local hour of the daily summary; unset = off
    notify_min_severity: Severity = "high"
    db_path: str = "sentiel.db"
    enrich: bool = False
    rules_dirs: list[str] = Field(default_factory=list)
    disabled_rules: list[str] = Field(default_factory=list)
    suppress: list[Suppress] = Field(default_factory=list)
    sources: Sources = Field(default_factory=Sources)
    keys: dict[str, str] = Field(default_factory=dict)
    notify: dict[str, str] = Field(default_factory=dict)

    @field_validator("keys", "notify")
    @classmethod
    def _known_names(cls, v: dict[str, str], info: ValidationInfo) -> dict[str, str]:
        valid = ENV_KEYS if info.field_name == "keys" else ENV_NOTIFY
        for name in v:
            if name not in valid:
                raise ValueError(f"unknown key '{clean_text(name, 80)}' in [{info.field_name}] "
                                 f"(valid: {', '.join(valid)})")
        return v


def clean_text(text: str, limit: int | None = None, *, keep_newlines: bool = False) -> str:
    """Untrusted text made printable: control/format/separator characters (Cc, Cf, Zl, Zp) become '?'.

    With `limit`, longer text is cut and ends in '...'. Plain spaces are kept.
    """
    if limit is not None and len(text) > limit:
        text = text[:limit - 3] + "..."
    return "".join("?" if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") and not (keep_newlines and c == "\n")
                   else c for c in text)


def describe_error(e: Exception) -> str:
    """Short config error text. For validation errors only field path and message: never the offending input.

    Key names come from the (possibly hostile) file: they are cleaned of terminal controls and capped.
    """
    if isinstance(e, ValidationError):
        errors = e.errors()
        parts = [f"{'.'.join(clean_text(str(p), 80) for p in x['loc'])}: {clean_text(x['msg'], 300)}"
                 for x in errors[:10]]
        if len(errors) > 10:
            parts.append(f"... and {len(errors) - 10} more")
        return clean_text("; ".join(parts), 1500)
    return clean_text(str(e), 500, keep_newlines=True)


def load_config(path: str | Path = "sentiel.toml") -> Config:
    path = Path(path)
    data = tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    cfg = Config.model_validate(data)
    cfg.model = os.environ.get("SENTIEL_MODEL", cfg.model)
    for target, env in ((cfg.keys, ENV_KEYS), (cfg.notify, ENV_NOTIFY)):
        for name, var in env.items():
            if os.environ.get(var):
                target[name] = os.environ[var]
    return cfg
