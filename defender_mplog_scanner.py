"""
Defender MPLog files — arquivos de texto que o Defender escreve continuamente
em %ProgramData%\\Microsoft\\Windows Defender\\Support\\.

Diferente de:
  - scan_defender_events    (Event Log 1116/1117 — apagável via wevtutil cl)
  - scan_defender_detection_history (arquivo de quarantine — cheater pode
                                     limpar via Windows Security UI)

MPLogs são arquivos de log em texto plano que:
  - São recriados pelo Defender se deletados (ele reabre o handle)
  - Rotacionam por tamanho (Defender mantém últimos ~N MB)
  - Contêm TODAS as ações do RTP (real-time protection): detecções, scans,
    exclusões aplicadas, updates de assinaturas
  - Contêm PATH completo do arquivo detectado + ThreatName + Timestamp

O cheater precisaria bloquear o handle do arquivo (impossível sem kernel) ou
formatar C: pra sumir com isso. Sobrevive a Clear History.
"""

from models import _result, _item
import os
import re
from datetime import datetime, timedelta


_MPLOG_DIR = r"%ProgramData%\Microsoft\Windows Defender\Support"

# Linhas relevantes no MPLog. O formato exato varia por versão; procuramos
# padrões estáveis presentes desde Windows 10 1809+.
_DETECTION_MARKERS = (
    "DETECTION_ADD",
    "RealTimeThreat",
    "Threat_",
    "WD_STATUS_ERROR:0x800106ba",  # scan error apontando pra threat
)

# ThreatName prefixes que indicam cheat/hacktool.
_HACKTOOL_THREAT_PREFIXES = (
    "hacktool", "exploit", "trojan:win", "backdoor", "riskware",
    "cheatengine", "hktl", "trojandownloader",
)

# ThreatName prefixes de PUAs benignas — não flagga.
_BENIGN_PUA_PREFIXES = (
    "pua:win32/",  # frequentemente uTorrent, etc.
    "puadlmanager:", "pua_conduit",
)

# Só olha detecções dos últimos N dias (evita FP de detecção antiga já resolvida).
_MPLOG_LOOKBACK_DAYS = 90


def _extract_path_from_line(line: str) -> str:
    """Extrai path de arquivo de uma linha do MPLog."""
    # Formato comum: "path: C:\Users\..."
    m = re.search(r"[Pp]ath[:\s]+([A-Za-z]:\\[^\r\n\t\"]+)", line)
    if m:
        return m.group(1).strip()
    # Fallback: qualquer path Windows na linha
    m = re.search(r"([A-Za-z]:\\[A-Za-z0-9_.\\ \-()]+\.(?:exe|dll|sys|scr))", line)
    if m:
        return m.group(1).strip()
    return ""


def _extract_threat_name(line: str) -> str:
    """Extrai ThreatName de uma linha do MPLog."""
    m = re.search(r"ThreatName[:=]?\s*([A-Za-z][\w:/.\-]+)", line)
    if m:
        return m.group(1).strip()
    m = re.search(r"threat[:\s]+(HackTool|Exploit|Trojan|Backdoor|Riskware)[^\s]*",
                  line, re.IGNORECASE)
    if m:
        return m.group(0).strip()
    return ""


def _parse_line_timestamp(line: str) -> datetime | None:
    """Extrai timestamp da linha do MPLog (formato YYYY-MM-DDTHH:MM:SS ou similar)."""
    m = re.search(r"(\d{4})[-/](\d{2})[-/](\d{2})[T ](\d{2}):(\d{2}):(\d{2})", line)
    if not m:
        return None
    try:
        return datetime(
            int(m.group(1)), int(m.group(2)), int(m.group(3)),
            int(m.group(4)), int(m.group(5)), int(m.group(6)),
        )
    except (ValueError, OverflowError):
        return None


def scan_defender_mplog() -> dict:
    """
    Lê arquivos MPLog-*.log do Defender procurando detecções de hacktool/exploit
    em pasta de usuário. Persiste mesmo após Clear History.
    """
    name = "Defender MPLog (persistente)"
    desc = ("Log de ação em texto plano do Defender — sobrevive a Clear History "
            "e a wevtutil clear. Registra todas as detecções recentes.")

    log_dir = os.path.expandvars(_MPLOG_DIR)
    if not os.path.isdir(log_dir):
        return _result(name, desc, [],
                       error=f"Diretório MPLog não encontrado: {log_dir}")

    try:
        files = [f for f in os.listdir(log_dir)
                 if f.lower().startswith("mplog") and f.lower().endswith(".log")]
    except PermissionError:
        return _result(name, desc, [],
                       error="Acesso negado ao MPLog (rode como admin)")
    except OSError as e:
        return _result(name, desc, [], error=str(e))

    if not files:
        return _result(name, desc, [])

    import matching

    cutoff = datetime.now() - timedelta(days=_MPLOG_LOOKBACK_DAYS)
    items = []
    seen: set[tuple] = set()

    for fname in files:
        fpath = os.path.join(log_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-16-le", errors="replace") as fh:
                content = fh.read(10_000_000)  # cap 10MB por arquivo
        except OSError:
            # MPLog pode ser UTF-8 dependendo da versão
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read(10_000_000)
            except OSError:
                continue

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            has_detection_marker = any(m in line for m in _DETECTION_MARKERS)
            if not has_detection_marker:
                continue

            # Filtra por data
            ts = _parse_line_timestamp(line)
            if ts and ts < cutoff:
                continue

            threat = _extract_threat_name(line)
            path = _extract_path_from_line(line)
            threat_low = threat.lower()

            # Skip PUAs benignas
            if any(threat_low.startswith(p) for p in _BENIGN_PUA_PREFIXES):
                continue

            # Precisa ter threat OU path com keyword
            kw, sev = matching.match_keyword(path)
            is_hacktool = any(threat_low.startswith(p)
                              for p in _HACKTOOL_THREAT_PREFIXES)

            if not (kw or is_hacktool):
                continue

            dedup = (threat_low, path.lower())
            if dedup in seen:
                continue
            seen.add(dedup)

            # Severity: hacktool + path = critical; keyword only = high
            if is_hacktool and path:
                severity = "critical"
            elif is_hacktool:
                severity = "high"
            elif kw:
                severity = sev
            else:
                severity = "medium"

            matched = f"mplog:{threat}" if threat else f"mplog:{kw}"

            items.append(_item(
                label=f"[MPLog] {threat or 'detecção'}: {os.path.basename(path) or '?'}",
                detail=(f"ThreatName: {threat or '(não extraído)'}\n"
                        f"Path: {path or '(não extraído)'}\n"
                        f"Log: {fname}\n"
                        f"Timestamp: {ts.isoformat() if ts else '(não parseado)'}\n"
                        f"MPLog persiste mesmo após Clear History no Windows "
                        f"Security. O Defender viu e agiu neste arquivo."),
                severity=severity, matched=matched,
                timestamp=ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "",
            ))

    return _result(name, desc, items)


ALL_DEFENDER_MPLOG_SCANNERS = [
    scan_defender_mplog,
]
