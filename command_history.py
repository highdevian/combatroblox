"""
Histórico de comandos:
  - PowerShell: ConsoleHost_history.txt (linha por linha de TUDO já digitado)
  - RunMRU: Win+R history (Registry HKCU)
  - TypedPaths: caminhos digitados no Explorer

90% dos cheats instalados via 'iex (irm krnl.cat/...)' ficam aqui.
"""

import os
from datetime import datetime

from database import (
    POWERSHELL_HISTORY_PATH,
    POWERSHELL_RED_FLAGS,
    SUSPICIOUS_DOMAINS,
    EXECUTOR_KEYWORDS,
    RUNMRU_KEY,
    TYPED_PATHS_KEY,
    PS_HIGH_REQUIRES_DOWNLOAD_CONTEXT,
    PS_DOWNLOAD_KEYWORDS,
)

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


def _result(name, description, items, error=None):
    if error:
        status = "error"
        summary = f"Erro: {error}"
    elif not items:
        status = "clean"
        summary = "Nenhum comando suspeito"
    else:
        status = "suspicious"
        summary = f"{len(items)} comando(s) suspeito(s)"
    return {
        "name": name, "description": description, "status": status,
        "items": items, "summary": summary, "error": error,
    }


def _item(label, detail, severity, matched, timestamp=""):
    return {
        "label": label, "detail": detail, "severity": severity,
        "matched": matched, "timestamp": timestamp,
    }


# Verbos do PowerShell/cmd que indicam BUSCA por padrão, não execução.
# Quem digita `-match 'winring0|kdmapper|gmer'` está PROCURANDO esses tokens,
# não rodando eles — frequente em script de auditoria/diagnóstico.
_PS_SEARCH_VERBS = (
    "-match", "-cmatch", "-imatch", "-notmatch", "-notcmatch",
    "select-string", " sls ", "| sls", "findstr", "where-object",
)


def _is_search_pattern(line: str, matched_kw: str) -> bool:
    """True quando o keyword cai dentro de uma string de BUSCA (regex de
    Where-Object -match, Select-String, findstr…). Quem procura o token não
    está executando o token.

    Heurística:
      1) a linha tem um verbo de busca; E
      2) o keyword aparece numa enumeração regex (com `|` adjacente) OU
         entre aspas como literal de busca.
    """
    if not matched_kw:
        return False
    low = line.lower()
    if not any(v in low for v in _PS_SEARCH_VERBS):
        return False
    kw = matched_kw.lower()
    # Enumeração regex: '...|kw|...' ou 'kw|...' ou '...|kw'
    if f"|{kw}" in low or f"{kw}|" in low:
        return True
    # Literal entre aspas: 'kw' ou "kw"
    for q in ("'", '"'):
        if f"{q}{kw}{q}" in low:
            return True
    return False


def _match_in_line(line: str) -> tuple[str | None, str | None]:
    """Procura red flag em uma linha. Retorna (matched, severity) ou (None, None).

    Usa o matching CENTRAL pra keyword (word-boundary) e domínio (fronteira),
    evitando o FP de substring (ex.: 'solara' em 'solarapanel', 'wave.gg' em
    'soundwave.gg'). POWERSHELL_RED_FLAGS continua substring de propósito —
    são fragmentos de comando ('iex', 'downloadstring').

    Se a linha for um comando de BUSCA por esses tokens (Where-Object -match,
    Select-String, findstr) com o keyword dentro da regex, ignora — o token
    é alvo de pesquisa, não execução."""
    import matching
    lower = line.lower()

    def _first_domain():
        for dom, sev in SUSPICIOUS_DOMAINS.items():
            if matching.domain_in_text(dom, lower):
                return dom, sev
        return None, None

    # 1. PowerShell red flags
    for kw, sev in POWERSHELL_RED_FLAGS.items():
        if kw in lower:
            # Se tem URL suspeita junto, sobe pra HIGH
            dom, _ = _first_domain()
            if dom:
                return f"{kw} + {dom}", "high"

            # Keywords HIGH que precisam de contexto: só permanecem HIGH
            # se tiver keyword de download na mesma linha. Senão, MEDIUM.
            # ExecutionPolicy Bypass sozinho ≠ cheat (admins/devs usam).
            if kw in PS_HIGH_REQUIRES_DOWNLOAD_CONTEXT and sev == "high":
                has_download = any(dl in lower for dl in PS_DOWNLOAD_KEYWORDS)
                if not has_download:
                    return kw, "medium"

            return kw, sev

    # 2. URLs de cheat sem comando explícito (já é suspeito)
    dom, dsev = _first_domain()
    if dom:
        return dom, dsev

    # 3. Executor keywords no comando (word-boundary, anti-FP)
    kw, sev = matching.match_keyword(line)
    if kw:
        # FP: comando de BUSCA por esses tokens (auditoria, não execução).
        # Ex.: `Where-Object PathName -match 'winring0|kdmapper|gmer'`
        if _is_search_pattern(line, kw):
            return None, None
        return kw, sev

    return None, None


# ============================ PowerShell ============================

def scan_powershell_history() -> dict:
    """
    Lê ConsoleHost_history.txt — append-only, fica registrado TUDO que o
    user digitou no PowerShell desde sempre (cap padrão = 4096 linhas).
    """
    path = os.path.expandvars(POWERSHELL_HISTORY_PATH)
    if not os.path.isfile(path):
        return _result("PowerShell History",
                       "Histórico de comandos do PowerShell", [],
                       error="ConsoleHost_history.txt não existe")

    items = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as e:
        return _result("PowerShell History",
                       "Histórico de comandos do PowerShell", [], error=str(e))

    # File mtime como timestamp aproximado
    try:
        mtime = os.path.getmtime(path)
        last_mod = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    except OSError:
        last_mod = ""

    seen_lines = set()
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or len(line) < 4:
            continue
        if line in seen_lines:
            continue
        seen_lines.add(line)

        matched, sev = _match_in_line(line)
        if not matched:
            continue

        # Trunca pra UI
        display = line if len(line) < 200 else line[:197] + "..."
        items.append(_item(
            label=f"L{i}: {display}",
            detail=line,
            severity=sev, matched=matched, timestamp=last_mod,
        ))

    desc = f"Histórico do PowerShell ({len(lines)} linhas analisadas)"
    return _result("PowerShell History", desc, items)


# ============================ RunMRU (Win+R history) ============================

def scan_runmru() -> dict:
    """
    HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU
    Cada tecla "a", "b", ... contém uma entry. Cara digitou caminho
    do executor ou comando suspeito no Win+R fica aqui.
    """
    if not HAS_WINREG:
        return _result("Win+R History (RunMRU)",
                       "Comandos digitados no Win+R", [],
                       error="winreg indisponível")

    items = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUNMRU_KEY)
    except OSError:
        return _result("Win+R History (RunMRU)",
                       "Comandos digitados no Win+R", [], error="Sem acesso")

    try:
        i = 0
        while True:
            try:
                name, value, _typ = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            if not isinstance(value, str) or not value:
                continue
            # Format: "comando\1" — remove o \1
            cmd = value.rstrip("\1").strip()
            if not cmd:
                continue

            matched, sev = _match_in_line(cmd)
            if not matched:
                continue

            items.append(_item(
                label=f"[{name}] {cmd}",
                detail=cmd, severity=sev, matched=matched,
            ))
    finally:
        winreg.CloseKey(key)

    return _result("Win+R History (RunMRU)",
                   "Comandos digitados na caixa Executar (Win+R)",
                   items)


# ============================ TypedPaths (Explorer address bar) ============================

def scan_typed_paths() -> dict:
    """
    HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths
    Cada caminho digitado na barra de endereço do Explorer.
    """
    if not HAS_WINREG:
        return _result("Typed Paths (Explorer)",
                       "Caminhos digitados na barra do Explorer", [],
                       error="winreg indisponível")

    items = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, TYPED_PATHS_KEY)
    except OSError:
        return _result("Typed Paths (Explorer)",
                       "Caminhos digitados na barra do Explorer", [],
                       error="Sem acesso (talvez ninguém usou)")

    try:
        i = 0
        while True:
            try:
                name, value, _typ = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            if not isinstance(value, str) or not value:
                continue
            matched, sev = _match_in_line(value)
            if not matched:
                continue
            items.append(_item(
                label=f"[{name}] {value}",
                detail=value, severity=sev, matched=matched,
            ))
    finally:
        winreg.CloseKey(key)

    return _result("Typed Paths (Explorer)",
                   "Caminhos digitados na barra de endereço do Explorer",
                   items)


ALL_COMMAND_HISTORY_SCANNERS = [
    scan_powershell_history,
    scan_runmru,
    scan_typed_paths,
]
