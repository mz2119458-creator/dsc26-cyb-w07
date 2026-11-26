import datetime
import json
import re

from ir_kit import GOVERNORATES
from ir_kit.secrets import iter_secrets

_RE_NATIONAL_ID_CANDIDATE = re.compile(r"(?<![0-9])[23][0-9]{13}(?![0-9])")
_RE_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}")
_RE_PHONE = re.compile(r"(?<![0-9+])(?:\+20|0020|0)?1[0125][0-9]{8}(?![0-9])")
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_SENSITIVE_KEYS: set[str] = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
}


def is_national_id(s: str) -> bool:
    if not isinstance(s, str) or len(s) != 14 or not s.isascii() or not s.isdigit():
        return False
    century_digit = s[0]
    if century_digit == "2":
        year = 1900 + int(s[1:3])
    elif century_digit == "3":
        year = 2000 + int(s[1:3])
    else:
        return False

    month = int(s[3:5])
    day = int(s[5:7])
    try:
        datetime.date(year, month, day)
    except ValueError:
        return False

    gov_code = s[7:9]
    return gov_code in GOVERNORATES


def redact_text(text: str) -> str:
    if not text:
        return ""

    out = text.replace("\r", r"\r").replace("\n", r"\n")

    spans = iter_secrets(out)
    if spans:
        parts: list[str] = []
        cursor = 0
        for rule_id, start, end in spans:
            parts.append(out[cursor:start])
            parts.append(f"[REDACTED:{rule_id}]")
            cursor = end
        parts.append(out[cursor:])
        out = "".join(parts)

    out = _RE_BEARER.sub(lambda m: f"{m.group(1)} [REDACTED:bearer]", out)
    out = _RE_NATIONAL_ID_CANDIDATE.sub(
        lambda m: "[REDACTED:national_id]" if is_national_id(m.group(0)) else m.group(0),
        out,
    )
    out = _RE_PHONE.sub("[REDACTED:phone]", out)
    out = _RE_EMAIL.sub("[REDACTED:email]", out)
    return out


def _redact_json_value(val):
    if isinstance(val, dict):
        new_obj = {}
        for k, v in val.items():
            if isinstance(k, str) and k.lower() in _SENSITIVE_KEYS:
                if v is not None and v != "":
                    new_obj[k] = "[REDACTED:field]"
                else:
                    new_obj[k] = v
            else:
                new_obj[k] = _redact_json_value(v)
        return new_obj
    if isinstance(val, list):
        return [_redact_json_value(item) for item in val]
    if isinstance(val, str):
        return redact_text(val)
    return val


def redact_line(line: str) -> str:
    stripped = line.lstrip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except Exception:
            return redact_text(line)
        if isinstance(parsed, dict):
            redacted_obj = _redact_json_value(parsed)
            return json.dumps(redacted_obj, ensure_ascii=False)
    return redact_text(line)
