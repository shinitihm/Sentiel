import ipaddress
import json
import sqlite3
from datetime import UTC, datetime, timedelta

import httpx

TTL = timedelta(hours=24)
MAX_IPS = 10


def public_ips(events: list[dict]) -> list[str]:
    """Global (routable) IPs found in any string field, in first-seen order."""
    seen: dict[str, None] = {}
    for e in events:
        for v in e.get("fields", {}).values():
            if isinstance(v, str) and len(v) <= 45:
                try:
                    ip = ipaddress.ip_address(v)
                except ValueError:
                    continue
                if ip.is_global:
                    seen[str(ip)] = None
    return list(seen)[:MAX_IPS]


def _lookup(ip: str, keys: dict[str, str], client: httpx.Client) -> dict:
    out: dict = {}
    try:
        g = client.get(f"http://ip-api.com/json/{ip}", params={"fields": "status,country,city,isp,hosting"}).json()
        if g.get("status") == "success":
            out["geo"] = {k: g[k] for k in ("country", "city", "isp", "hosting") if k in g}
    except (httpx.HTTPError, ValueError):
        pass
    if key := keys.get("abuseipdb"):
        try:
            d = client.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                           headers={"Key": key, "Accept": "application/json"}).json()["data"]
            out["abuseipdb"] = {"score": d["abuseConfidenceScore"], "reports": d["totalReports"]}
        except (httpx.HTTPError, ValueError, KeyError):
            pass
    if key := keys.get("virustotal"):
        try:
            s = client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                           headers={"x-apikey": key}).json()["data"]["attributes"]["last_analysis_stats"]
            out["virustotal"] = {"malicious": s["malicious"], "suspicious": s["suspicious"]}
        except (httpx.HTTPError, ValueError, KeyError):
            pass
    return out


def enrich_ips(conn: sqlite3.Connection, ips: list[str], keys: dict[str, str],
               client: httpx.Client | None = None) -> dict[str, dict]:
    """IP -> reputation/geo, cached 24h. Failed lookups are not cached, so they retry next cycle."""
    result: dict[str, dict] = {}
    client = client or httpx.Client(timeout=8)
    now = datetime.now(UTC)
    for ip in ips:
        row = conn.execute("SELECT data, fetched_at FROM ip_cache WHERE ip = ?", (ip,)).fetchone()
        if row and now - datetime.fromisoformat(row["fetched_at"]) < TTL:
            result[ip] = json.loads(row["data"])
            continue
        data = _lookup(ip, keys, client)
        if data:
            conn.execute("INSERT OR REPLACE INTO ip_cache (ip, data, fetched_at) VALUES (?, ?, ?)",
                         (ip, json.dumps(data), now.isoformat()))
            conn.commit()
            result[ip] = data
    return result
