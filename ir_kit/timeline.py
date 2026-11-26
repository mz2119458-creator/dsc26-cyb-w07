from datetime import datetime, timezone
import json
import re
from zoneinfo import ZoneInfo

from ir_kit import Event
from ir_kit.redact import redact_text

_ALLOWED_SOURCES: set[str] = {"wazuh", "nginx", "app"}
_SOURCE_ORDER: dict[str, int] = {"wazuh": 0, "nginx": 1, "app": 2}
_CAIRO_TZ = ZoneInfo("Africa/Cairo")

_RE_NGINX = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)$')
_RE_WAZUH = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (.+)$")


def _parse_nginx_line(line: str) -> tuple[datetime, str]:
    m = _RE_NGINX.match(line)
    if not m:
        raise ValueError("Invalid nginx line")
    ip, ts_raw, req, status, _size = m.groups()
    dt = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
    dt_utc = dt.astimezone(timezone.utc)
    msg = redact_text(f'{ip} "{req}" {status}')
    return dt_utc, msg


def _parse_app_line(line: str) -> tuple[datetime, str]:
    obj = json.loads(line)
    if not isinstance(obj, dict):
        raise ValueError("App line must be JSON object")

    ts_val = obj.get("ts")
    level_val = obj.get("level")
    msg_val = obj.get("msg")

    if not isinstance(ts_val, str) or not isinstance(level_val, str) or not isinstance(msg_val, str):
        raise ValueError("Missing or invalid required fields")

    dt = datetime.fromisoformat(ts_val)
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("Timestamp missing timezone offset")

    dt_utc = dt.astimezone(timezone.utc)
    base = f"{level_val.upper()} {msg_val}"
    if "user" in obj and obj["user"] is not None:
        base += f" user={obj['user']}"
    if "doc_id" in obj and obj["doc_id"] is not None:
        base += f" doc_id={obj['doc_id']}"

    return dt_utc, redact_text(base)


def _parse_wazuh_line(line: str) -> tuple[datetime, str]:
    m = _RE_WAZUH.match(line)
    if not m:
        raise ValueError("Invalid wazuh line")
    ts_raw, msg_raw = m.groups()
    dt_naive = datetime.strptime(ts_raw, "%Y-%m-%d %H:%M:%S")
    dt_cairo = dt_naive.replace(tzinfo=_CAIRO_TZ, fold=0)
    dt_utc = dt_cairo.astimezone(timezone.utc)
    return dt_utc, redact_text(msg_raw)


def build_timeline(sources: dict[str, str]) -> tuple[list[Event], list[str]]:
    for src_name in sources:
        if src_name not in _ALLOWED_SOURCES:
            raise ValueError(f"Unknown source: {src_name}")

    events: list[Event] = []
    errors: list[str] = []

    for src_name, content in sources.items():
        lines = content.splitlines()
        for lineno, raw_line in enumerate(lines, start=1):
            if not raw_line.strip():
                continue
            try:
                if src_name == "nginx":
                    dt_utc, msg = _parse_nginx_line(raw_line)
                elif src_name == "app":
                    dt_utc, msg = _parse_app_line(raw_line)
                else:
                    dt_utc, msg = _parse_wazuh_line(raw_line)
            except Exception:
                errors.append(f"{src_name}:{lineno}")
                continue

            events.append(Event(time=dt_utc, source=src_name, line=lineno, message=msg))

    events.sort(key=lambda ev: (ev.time, _SOURCE_ORDER[ev.source], ev.line))

    deduped: list[Event] = []
    seen: set[tuple[datetime, str, str]] = set()
    for ev in events:
        key = (ev.time, ev.source, ev.message)
        if key not in seen:
            seen.add(key)
            deduped.append(ev)

    return deduped, errors


def render_markdown(events: list[Event]) -> str:
    out_lines = [
        "| Time (UTC) | Source | Event |",
        "|---|---|---|",
    ]
    for ev in events:
        dt = ev.time
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        ts_str = dt.strftime("%Y-%m-%d %H:%M:%SZ")
        escaped_msg = ev.message.replace("|", r"\|")
        out_lines.append(f"| {ts_str} | {ev.source} | {escaped_msg} |")

    return "\n".join(out_lines) + "\n"
