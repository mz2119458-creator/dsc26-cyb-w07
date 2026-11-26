from pathlib import Path

from ir_kit.redact import is_national_id, redact_line, redact_text
from ir_kit.secrets import entropy, scan_text
from ir_kit.timeline import build_timeline, render_markdown


def test_aws_key_and_example():
    line = "AKIAIOSFODNN7EXAMPLE AKIA1234567890ABCDEF"
    findings = scan_text(line, "test.env")
    assert len(findings) == 1
    assert findings[0].rule_id == "aws_access_key_id"
    assert findings[0].masked == "AKIA****"


def test_generic_secret_entropy_vs_placeholder():
    assert entropy("changeme") < 3.0
    assert len(scan_text("API_KEY=changeme\nAPI_KEY=p9xK4mQ2vL8nR7wT\n", "a.env")) == 1


def test_national_id_and_phone():
    assert is_national_id("29603150101234") is True
    assert is_national_id("29902300101234") is False
    redacted = redact_text("id=29603150101234 phone=01012345678 mail=test@example.com")
    assert "[REDACTED:national_id]" in redacted
    assert "[REDACTED:phone]" in redacted
    assert "[REDACTED:email]" in redacted


def test_redact_line_json():
    line = '{"user":"alice","password":"SuperSecretValue123","note":"call 01012345678"}'
    out = redact_line(line)
    assert "SuperSecretValue123" not in out
    assert "[REDACTED:field]" in out
    assert "[REDACTED:phone]" in out


def test_timeline_merge():
    base = Path(__file__).resolve().parent.parent / "fixtures"
    events, errors = build_timeline({
        "wazuh": (base / "wazuh_alerts.log").read_text(encoding="utf-8"),
        "nginx": (base / "nginx_access.log").read_text(encoding="utf-8"),
        "app": (base / "app.jsonl").read_text(encoding="utf-8"),
    })
    assert len(events) >= 3
    assert "nginx:3" in errors
    assert "app:3" in errors
    md = render_markdown(events)
    assert md.startswith("| Time (UTC) | Source | Event |")
    assert md.endswith("\n")
