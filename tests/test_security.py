"""
Testes dos módulos de SEGURANÇA: redação de credenciais + assinatura HMAC.

Por que importam:
  - redaction.py mascara senhas/tokens/emails ANTES do relatório. Se vazar,
    um relatório compartilhado no Discord expõe credenciais do suspeito.
  - report_signing.py garante que o .tsr não foi adulterado depois de gerado.

Nenhum segredo real é usado — só padrões sintéticos que casam os regexes.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import redaction        # noqa: E402
import report_signing   # noqa: E402


# ============================ Redação ============================

def test_redacts_bearer_and_basic():
    assert "[REDACTED]" in redaction.redact("Authorization: Bearer abc123def456ghi789")
    assert "[REDACTED]" in redaction.redact("Authorization: Basic QWxhZGRpbjpvcGVuc2VzYW1l")


def test_redacts_password_assignment():
    out = redaction.redact("password=hunter2secret")
    assert "hunter2secret" not in out
    assert "[REDACTED]" in out
    # variantes
    assert "senha" not in redaction.redact("senha: minhasenha123").lower() or "[REDACTED]" in redaction.redact("senha: minhasenha123")


def test_redacts_api_keys():
    cases = [
        "sk-" + "a" * 30,                      # OpenAI-style
        "sk-ant-" + "b" * 30,                  # Anthropic-style
        "ghp_" + "c" * 36,                     # GitHub
        "xoxb-" + "1234567890-abcdef",         # Slack
        "AIza" + "d" * 35,                     # Google
        "AKIA" + "A" * 16,                     # AWS
    ]
    for c in cases:
        out = redaction.redact(f"key found: {c}")
        assert c not in out, f"não mascarou: {c}"


def test_redacts_email_keeps_domain():
    out = redaction.redact("contato joao.silva@gmail.com aqui")
    assert "joao.silva" not in out
    assert "gmail.com" in out          # domínio preservado pra contexto
    assert "[EMAIL]" in out


def test_redacts_long_hex():
    h = "a1b2c3d4" * 6  # 48 hex chars
    out = redaction.redact(f"hash {h} fim")
    assert h not in out
    assert "[HEX-REDACTED]" in out


def test_redacts_url_with_creds():
    out = redaction.redact("https://user:senha123@example.com/path")
    assert "senha123" not in out
    assert "[CREDS]" in out


def test_redacts_cpf_and_card():
    assert "[CPF]" in redaction.redact("CPF 123.456.789-00")
    assert "[CARD]" in redaction.redact("cartao 1234 5678 9012 3456")


def test_redacts_discord_webhook():
    # URL de webhook (id + token no path) vaza acesso de POST no canal. Montada
    # de PARTES com valores fake pra nenhum literal de segredo entrar no repo
    # (o push protection do GitHub flaga webhook mesmo sintetico contiguo).
    fake_id, fake_token = "1" * 18, "AbC" + "x" * 60
    url = "https://discord.com/api/webhooks/" + fake_id + "/" + fake_token
    out = redaction.redact(f'Invoke-RestMethod -Uri "{url}" -Method POST')
    assert fake_token not in out            # token some
    assert fake_id not in out               # id some junto
    assert "[WEBHOOK-REDACTED]" in out


def test_redacts_slack_webhook():
    fake_path, fake_token = "T0/B0/", "z" * 24
    url = "https://hooks.slack.com/services/" + fake_path + fake_token
    out = redaction.redact(f"curl -X POST {url}")
    assert fake_token not in out
    assert "[WEBHOOK-REDACTED]" in out


def test_does_not_touch_benign_text():
    benign = r"C:\Users\bob\AppData\Local\Solara\Solara.exe"
    assert redaction.redact(benign) == benign


def test_redact_findings_applies_and_counts():
    findings = [{
        "items": [
            {"label": "key sk-" + "z" * 30, "detail": "email joao@gmail.com", "matched": "x"},
            {"label": "limpo", "detail": "nada aqui", "matched": "solara"},
        ]
    }]
    out, count = redaction.redact_findings(findings)
    assert count >= 2  # label do 1º (sk-key) + detail do 1º (email)
    assert "sk-" + "z" * 30 not in out[0]["items"][0]["label"]
    assert "joao@gmail.com" not in out[0]["items"][0]["detail"]
    # item benigno intacto
    assert out[0]["items"][1]["matched"] == "solara"


def test_redact_handles_none_and_nonstring():
    assert redaction.redact(None) is None
    assert redaction.redact(123) == 123
    assert redaction.redact("") == ""


# ============================ Assinatura HMAC ============================

def test_hmac_roundtrip():
    content = '{"verdict": "CONFIRMED", "target": "solara"}'
    sig = report_signing.compute_hmac(content)
    assert isinstance(sig, str) and len(sig) == 64  # sha256 hex
    assert report_signing.verify_hmac(content, sig)


def test_hmac_detects_tampering():
    content = '{"verdict": "CLEAN"}'
    sig = report_signing.compute_hmac(content)
    tampered = '{"verdict": "CONFIRMED"}'   # cheater muda o veredito
    assert not report_signing.verify_hmac(tampered, sig)


def test_hmac_rejects_empty_signature():
    assert not report_signing.verify_hmac("qualquer", "")
    assert not report_signing.verify_hmac("qualquer", None)


def test_hmac_accepts_bytes_and_str():
    s = report_signing.compute_hmac("abc")
    b = report_signing.compute_hmac(b"abc")
    assert s == b  # str e bytes do mesmo conteúdo = mesmo HMAC


def test_self_hash_is_sha256_hex():
    h = report_signing.get_self_hash()
    # Em dev roda sobre o .py; deve devolver hex de 64 chars ou None se erro
    if h is not None:
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)
