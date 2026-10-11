import os
import sys
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field

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


class Sources(BaseModel):
    windows: bool = sys.platform == "win32"
    linux_auth: str | None = "/var/log/auth.log" if Path("/var/log/auth.log").exists() else None
    json_files: list[str] = Field(default_factory=list, alias="json")


class Config(BaseModel):
    model: str = "ollama/llama3.1:8b"
    interval: int = Field(30, ge=1)
    llm_timeout: int = Field(120, ge=5)
    max_triage_per_cycle: int = Field(50, ge=0)
    triage_concurrency: int = Field(1, ge=1)
    notify_min_severity: Severity = "high"
    db_path: str = "sentiel.db"
    enrich: bool = False
    sources: Sources = Field(default_factory=Sources)
    keys: dict[str, str] = Field(default_factory=dict)
    notify: dict[str, str] = Field(default_factory=dict)


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
