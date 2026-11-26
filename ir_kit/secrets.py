from collections import Counter
import math
from pathlib import Path
import re

from ir_kit import SecretFinding

_RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)
_RE_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_RE_GITHUB_TOKEN = re.compile(
    r"\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b"
)
_RE_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")
_RE_GENERIC_SECRET = re.compile(
    r"(?i)([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|api_key|apikey|token))"
    r"""["']?\s*[:=]\s*["']?([^\s"',;]{8,})"""
)

_PLACEHOLDERS: set[str] = {
    "changeme",
    "password",
    "example",
    "redacted",
    "xxxxxxxx",
    "secret",
    "your_token_here",
}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())


def _is_placeholder_secret(val: str) -> bool:
    low = val.lower()
    if low in _PLACEHOLDERS:
        return True
    if "example" in low:
        return True
    if val.startswith(("${", "<", "{{")) or low.startswith("[redacted"):
        return True
    if val and set(val) <= {"x", "*"}:
        return True
    return False


def iter_secrets(line: str) -> list[tuple[str, int, int]]:
    candidates: list[tuple[int, int, str, int, int]] = []

    for m in _RE_PRIVATE_KEY.finditer(line):
        s, e = m.start(), m.end()
        candidates.append((s, -(e - s), "private_key", s, e))

    for m in _RE_AWS_KEY.finditer(line):
        token = m.group(0)
        if "EXAMPLE" in token:
            continue
        s, e = m.start(), m.end()
        candidates.append((s, -(e - s), "aws_access_key_id", s, e))

    for m in _RE_GITHUB_TOKEN.finditer(line):
        s, e = m.start(), m.end()
        candidates.append((s, -(e - s), "github_token", s, e))

    for m in _RE_SLACK_TOKEN.finditer(line):
        s, e = m.start(), m.end()
        candidates.append((s, -(e - s), "slack_token", s, e))

    for m in _RE_GENERIC_SECRET.finditer(line):
        val = m.group(2)
        if _is_placeholder_secret(val):
            continue
        if entropy(val) < 3.0:
            continue
        s, e = m.start(2), m.end(2)
        candidates.append((s, -(e - s), "generic_secret", s, e))

    candidates.sort(key=lambda item: (item[0], item[1], item[2]))

    selected: list[tuple[str, int, int]] = []
    last_end = -1
    for _start, _neg_len, rule_id, s, e in candidates:
        if s >= last_end:
            selected.append((rule_id, s, e))
            last_end = e

    selected.sort(key=lambda item: (item[1], item[2], item[0]))
    return selected


def _mask_secret(secret: str) -> str:
    if len(secret) > 8:
        return f"{secret[:4]}****"
    return "****"


def scan_text(text: str, path: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        if "dsc:allow-secret" in line:
            continue
        for rule_id, start, end in iter_secrets(line):
            secret_val = line[start:end]
            findings.append(
                SecretFinding(
                    path=path,
                    line=lineno,
                    column=start + 1,
                    rule_id=rule_id,
                    masked=_mask_secret(secret_val),
                )
            )
    return findings


def scan_tree(root) -> list[SecretFinding]:
    root_path = Path(root)
    if not root_path.exists():
        return []

    all_findings: list[SecretFinding] = []
    for entry in sorted(root_path.rglob("*")):
        if entry.is_symlink():
            continue
        rel = entry.relative_to(root_path)
        if ".git" in rel.parts:
            continue
        if not entry.is_file():
            continue
        try:
            st = entry.stat()
        except OSError:
            continue
        if st.st_size > 1_000_000:
            continue

        try:
            raw = entry.read_bytes()
        except OSError:
            continue

        if b"\x00" in raw[:1024]:
            continue

        text = raw.decode("utf-8", errors="replace")
        rel_posix = rel.as_posix()
        all_findings.extend(scan_text(text, rel_posix))

    all_findings.sort(key=lambda f: (f.path, f.line, f.column, f.rule_id))
    return all_findings
