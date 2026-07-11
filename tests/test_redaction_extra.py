"""Regressão de redação (webhooks, JWT, telegram)."""

import redaction


def test_discord_webhook_redacted():
    s = "curl https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEF"
    out = redaction.redact(s)
    assert "abcdefghijklmnopqrstuvwxyz" not in out
    assert "WEBHOOK-REDACTED" in out or "REDACTED" in out


def test_jwt_redacted():
    s = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    out = redaction.redact(s)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in out or "JWT" in out


def test_redact_findings_counts():
    findings = [{
        "name": "ps",
        "status": "suspicious",
        "items": [{
            "label": "ps",
            "detail": "password=supersecret123",
            "matched": "pwd",
            "severity": "low",
        }],
    }]
    _, n = redaction.redact_findings(findings)
    assert n >= 1
    assert "supersecret123" not in findings[0]["items"][0]["detail"]


def test_sensitive_process_list_includes_bitwarden():
    assert "bitwarden.exe" in redaction.SENSITIVE_PROCESSES
    assert "cryptomator.exe" in redaction.SENSITIVE_PROCESSES
