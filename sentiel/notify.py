import httpx

from .models import Alert, Severity, Triage


def format_message(alert: Alert, triage: Triage | None, severity: Severity, host: str, contested: bool) -> str:
    """Title, severity, host and summary only; never raw log content."""
    lines = [f"[{severity.upper()}] {alert.rule_title}", f"Host: {host}"]
    if contested:
        lines.append("WARNING: the AI called this benign but the detection rule rates it high. Check manually.")
    if triage:
        lines.append(triage.summary)
    return "\n".join(lines)[:1900]


def send(cfg: dict[str, str], text: str, client: httpx.Client | None = None) -> dict[str, bool]:
    """Channel name ("telegram", "discord") -> delivered; an empty dict means nothing is configured.
    Errors are swallowed on purpose: httpx messages contain the Telegram bot token in the URL."""
    client = client or httpx.Client(timeout=10)
    ok: dict[str, bool] = {}
    if cfg.get("telegram_bot_token") and cfg.get("telegram_chat_id"):
        try:
            r = client.post(f"https://api.telegram.org/bot{cfg['telegram_bot_token']}/sendMessage",
                            json={"chat_id": cfg["telegram_chat_id"], "text": text})
            ok["telegram"] = r.is_success
        except httpx.HTTPError:
            ok["telegram"] = False
    if cfg.get("discord_webhook"):
        try:
            # empty allowed_mentions: model/log text must not be able to @everyone
            r = client.post(cfg["discord_webhook"], json={"content": text, "allowed_mentions": {"parse": []}})
            ok["discord"] = r.is_success
        except httpx.HTTPError:
            ok["discord"] = False
    return ok
