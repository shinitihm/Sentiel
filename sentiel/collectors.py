import json
import re
import socket
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from .models import Event

INT64 = 2**63 - 1

# ---------- JSON (jsonl) ----------


def _flatten(obj: dict, prefix: str = "") -> dict[str, str | int | None]:
    out: dict[str, str | int | None] = {}
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, f"{key}."))
        elif v is None or isinstance(v, str) or (type(v) is int and abs(v) <= INT64):
            out[key] = v
        else:
            out[key] = json.dumps(v) if isinstance(v, list) else str(v)
    return out


def read_json(path: str | Path, stats: Counter | None = None) -> Iterator[Event]:
    """JSON Lines. Lines already in Event shape keep their source; anything else becomes source='json'."""
    stats = stats if stats is not None else Counter()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError("not an object")
                if "fields" in obj and "source" in obj:
                    yield Event.model_validate(obj)
                    continue
                ts = obj.get("ts") or obj.get("@timestamp") or obj.get("timestamp") or datetime.now(UTC)
                yield Event(ts=ts, source="json", host=str(obj.get("host", "unknown")), fields=_flatten(obj))
            except (ValueError, ValidationError):
                stats["skipped"] += 1


# ---------- Linux auth.log ----------

_SYSLOG = re.compile(
    r"^(?:(?P<iso>\d{4}-\d\d-\d\dT\S+)|(?P<bsd>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d))\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ssh_failed", re.compile(r"Failed \S+ for (?:invalid user )?(?P<User>\S+) from (?P<IpAddress>\S+)")),
    ("ssh_accepted", re.compile(r"Accepted \S+ for (?P<User>\S+) from (?P<IpAddress>\S+)")),
    ("sudo_failed", re.compile(r"^\s*(?P<User>\S+) : .*(?:incorrect password attempt|NOT in sudoers)")),
    ("sudo_failed", re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*\buser=(?P<User>\S+)")),
    ("sudo_command", re.compile(r"^\s*(?P<User>\S+) : .*COMMAND=(?P<CommandLine>.*)$")),
    ("useradd", re.compile(r"new user: name=(?P<TargetUserName>[^,\s]+)")),
]


def parse_auth_line(line: str, now: datetime | None = None) -> Event | None:
    m = _SYSLOG.match(line.rstrip("\r\n"))
    if not m:
        return None
    if m["iso"]:
        try:
            ts = datetime.fromisoformat(m["iso"])
        except ValueError:  # regex-shaped but not a real date, e.g. month 13
            return None
    else:
        now = now or datetime.now()
        for y in (now.year, now.year - 1):
            try:
                ts = datetime.strptime(f"{y} {m['bsd']}", "%Y %b %d %H:%M:%S")
            except ValueError:  # Feb 29 in a non-leap year
                continue
            if ts <= now + timedelta(days=1):  # 1 day of slack for clock skew
                break
        else:
            return None
        ts = ts.astimezone()  # BSD syslog has no zone: assume local time
    fields: dict[str, str | int | None] = {
        "program": m["program"], "pid": int(m["pid"]) if m["pid"] else None, "message": m["message"],
        "event": "other",
    }
    for name, pattern in _PATTERNS:
        if m["program"].startswith(("sshd", "sudo", "useradd")) and (pm := pattern.search(m["message"])):
            fields["event"] = name
            fields.update({k: v for k, v in pm.groupdict().items() if v})
            break
    return Event(ts=ts, source="linux", host=m["host"], fields=fields)


def read_linux_auth(path: str | Path, state: dict, stats: Counter | None = None) -> Iterator[Event]:
    """Reads only complete lines after state['offset']; resets on rotation (file shrank)."""
    stats = stats if stats is not None else Counter()
    path = Path(path)
    offset = int(state.get("offset", 0))
    if path.stat().st_size < offset:
        offset = 0
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
    end = data.rfind(b"\n") + 1
    for line in data[:end].decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        ev = parse_auth_line(line)
        if ev is None:
            stats["skipped"] += 1
        else:
            yield ev
    state["offset"] = offset + end


# ---------- Windows Event Log ----------

WINDOWS_CHANNELS = ("Security", "System", "Microsoft-Windows-Sysmon/Operational")
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _num(v: str | None) -> str | int | None:
    return int(v) if v is not None and v.isdigit() and int(v) <= INT64 else v


def parse_event_xml(xml: str) -> Event:
    root = ET.fromstring(xml)
    system = root.find(f"{_NS}System")
    get = lambda tag: system.find(f"{_NS}{tag}")  # noqa: E731
    fields: dict[str, str | int | None] = {
        "EventID": _num(get("EventID").text),
        "Channel": get("Channel").text,
        "Provider_Name": get("Provider").get("Name"),
        "EventRecordID": _num(get("EventRecordID").text),
    }
    data = root.find(f"{_NS}EventData")
    if data is not None:
        for i, d in enumerate(data.findall(f"{_NS}Data")):
            fields[d.get("Name") or f"Data{i}"] = _num(d.text)
    user_data = root.find(f"{_NS}UserData")
    if user_data is not None:
        for el in user_data.iter():
            if len(el) == 0 and el.text and el.text.strip():
                fields[el.tag.split("}")[-1]] = _num(el.text.strip())
    ts = datetime.fromisoformat(get("TimeCreated").get("SystemTime").rstrip("Z")[:26]).replace(tzinfo=UTC)
    return Event(ts=ts, source="windows", host=get("Computer").text or socket.gethostname(), fields=fields)


def read_windows(state: dict, stats: Counter | None = None, channels=WINDOWS_CHANNELS) -> Iterator[Event]:
    """New events per channel since the last EventRecordID (first run: last 24h)."""
    if sys.platform != "win32":
        return
    import pywintypes
    import win32evtlog

    stats = stats if stats is not None else Counter()
    for channel in channels:
        last = state.get(channel)
        query = (f"*[System[EventRecordID > {int(last)}]]" if last
                 else "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]")
        try:
            handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryForwardDirection, query)
        except pywintypes.error as e:
            if e.winerror == 5:
                stats[f"denied:{channel}"] += 1
            continue  # channel missing (e.g. no Sysmon) or no permission
        while batch := win32evtlog.EvtNext(handle, 256):
            for evt in batch:
                try:
                    ev = parse_event_xml(win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml))
                except (ET.ParseError, AttributeError, ValueError, ValidationError):
                    stats["skipped"] += 1
                    continue
                state[channel] = ev.fields["EventRecordID"]
                yield ev
