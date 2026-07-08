"""
Redação de dados sensíveis antes do relatório.

Procura padrões de credenciais/tokens/emails nos campos `detail` e `label`
de todos os items e substitui por [REDACTED]. Previne vazamento se o
relatório for compartilhado.
"""

import re

# (pattern, replacement). Mantenha tudo case-insensitive onde fizer sentido.
PATTERNS = [
    # Bearer tokens
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-]{8,}", re.I), "Bearer [REDACTED]"),
    # Basic auth
    (re.compile(r"Basic\s+[A-Za-z0-9+/=]{16,}", re.I), "Basic [REDACTED]"),
    # password / pwd / senha = ...
    (re.compile(r"(password|passwd|pwd|senha)\s*[=:]\s*[\"']?[^\s\"',;]{3,}", re.I),
     r"\1=[REDACTED]"),
    # token / apikey / secret = ...
    (re.compile(r"(token|api[_-]?key|secret|client[_-]?secret)\s*[=:]\s*[\"']?[^\s\"',;]{6,}", re.I),
     r"\1=[REDACTED]"),
    # OpenAI / Anthropic / etc style keys
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), "sk-[REDACTED]"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "sk-ant-[REDACTED]"),
    # GitHub tokens (ghp_, gho_, ghs_, ghu_)
    (re.compile(r"\bgh[opsu]_[A-Za-z0-9]{30,}\b"), "gh_[REDACTED]"),
    # Slack tokens
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "xox_[REDACTED]"),
    # Google API keys
    (re.compile(r"\bAIza[A-Za-z0-9_\-]{30,}\b"), "AIza_[REDACTED]"),
    # AWS access key
    (re.compile(r"\bAKIA[A-Z0-9]{16}\b"), "AKIA[REDACTED]"),
    # Discord/Slack webhook URLs (id + token no path) — vazam acesso de POST no
    # canal. Regex do webhook ANTES do token de bot pra casar a URL inteira.
    (re.compile(r"https?://(?:\w+\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d+/[\w-]{20,}", re.I),
     "https://discord.com/api/webhooks/[WEBHOOK-REDACTED]"),
    (re.compile(r"https?://hooks\.slack\.com/services/[A-Za-z0-9+/_-]{20,}", re.I),
     "https://hooks.slack.com/services/[WEBHOOK-REDACTED]"),
    # Discord bot/user tokens (heuristic - long base64-ish strings after specific keywords)
    (re.compile(r"\b(M[A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,})\b"), "[DISCORD-TOKEN-REDACTED]"),
    # Emails (mantém domain pra contexto, redige local-part)
    (re.compile(r"\b[A-Za-z0-9._%+-]{2,}@([A-Za-z0-9.-]+\.[A-Z]{2,})\b", re.I),
     r"[EMAIL]@\1"),
    # Hex strings que parecem hashes/tokens longos (40+ hex chars não-palavra)
    (re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40,128}(?![A-Fa-f0-9])"),
     "[HEX-REDACTED]"),
    # URLs com user:pass embedded
    (re.compile(r"(https?://)[^:/@\s]+:[^@\s]+@", re.I), r"\1[CREDS]@"),
    # CPF (formato XXX.XXX.XXX-XX ou só números)
    (re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), "[CPF]"),
    # Cartão de crédito (formato comum)
    (re.compile(r"\b\d{4}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b"), "[CARD]"),
]


def redact(text):
    """Aplica todos os padrões de redação numa string."""
    if not text or not isinstance(text, str):
        return text
    for pat, repl in PATTERNS:
        text = pat.sub(repl, text)
    return text


def redact_findings(findings):
    """Aplica redação em todos os items de todos os findings (in-place)."""
    count = 0
    for f in findings:
        for item in f.get("items", []):
            for key in ("detail", "label", "matched"):
                original = item.get(key)
                if not original:
                    continue
                redacted = redact(original)
                if redacted != original:
                    item[key] = redacted
                    count += 1
    return findings, count


# Lista de processos onde dados sensíveis podem estar abertos.
# Se um deles tá rodando, telador AVISA e pula screenshot por padrão.
SENSITIVE_PROCESSES = {
    "keepass.exe", "keepassxc.exe", "keepassxc-cli.exe",
    "1password.exe", "1passwordmini.exe", "agile1pAgent.exe",
    "bitwarden.exe", "bitwarden-cli.exe",
    "dashlane.exe", "lastpass.exe", "lastpass_desktop.exe",
    "pwsafe.exe", "roboform.exe", "enpass.exe",
    "authy.exe", "authy desktop.exe",
    "yubikey-manager.exe",
    "buttercup.exe", "nordpass.exe",
}


def detect_sensitive_processes():
    """Retorna lista de processos sensíveis rodando agora (lowercase names)."""
    try:
        import psutil
    except ImportError:
        return []

    found = []
    try:
        for proc in psutil.process_iter(["name"]):
            try:
                name = (proc.info.get("name") or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if name in SENSITIVE_PROCESSES:
                found.append(name)
    except Exception:
        pass
    return list(set(found))
