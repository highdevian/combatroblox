"""
Network forensics:
  - Conexões TCP/UDP ativas (psutil)
  - DNS cache (ipconfig /displaydns)
  - Hosts file modificações (bloqueio de telemetria do Roblox)
"""

import os
import re
import subprocess

from database import SUSPICIOUS_DOMAINS, EXECUTOR_PROCESS_NAMES

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# Domínios de telemetria do Roblox — bloquear isso no hosts = red flag forte
ROBLOX_TELEMETRY_DOMAINS = [
    "roblox.com",
    "rbx.com",
    "rbxcdn.com",
    "rbxstatic.com",
    "robloxlabs.com",
    "ec.rbxcdn.com",
    "telemetry.roblox.com",
    "presence.roblox.com",
    "metrics.roblox.com",
]

HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"


def _result(name, description, items, error=None):
    if error:
        status = "error"
        summary = f"Erro: {error}"
    elif not items:
        status = "clean"
        summary = "Sem indícios"
    else:
        status = "suspicious"
        summary = f"{len(items)} indício(s)"
    return {
        "name": name, "description": description, "status": status,
        "items": items, "summary": summary, "error": error,
    }


def _item(label, detail, severity, matched, timestamp=""):
    return {"label": label, "detail": detail, "severity": severity,
            "matched": matched, "timestamp": timestamp}


# ============================ Conexões ativas ============================

def scan_network_connections() -> dict:
    """Lista conexões TCP/UDP ativas com IPs e processos."""
    if not HAS_PSUTIL:
        return _result("Conexões de Rede", "Conexões ativas", [], error="psutil indisponível")

    items = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return _result("Conexões de Rede", "Conexões ativas", [],
                       error="Acesso negado (rode como admin)")
    except Exception as e:
        return _result("Conexões de Rede", "Conexões ativas", [], error=str(e))

    suspicious_pids = {}

    for c in conns:
        if c.status not in ("ESTABLISHED", "SYN_SENT"):
            continue
        if not c.raddr:
            continue

        try:
            proc = psutil.Process(c.pid)
            pname = proc.name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        # Processo é suspeito? (executor conhecido conectado em algum lugar)
        if pname in EXECUTOR_PROCESS_NAMES:
            sev = EXECUTOR_PROCESS_NAMES[pname]
            items.append(_item(
                label=f"{pname} → {c.raddr.ip}:{c.raddr.port}",
                detail=f"Status: {c.status}  |  PID: {c.pid}",
                severity=sev, matched=pname,
            ))
            suspicious_pids[c.pid] = pname

    return _result("Conexões de Rede",
                   "Conexões TCP/UDP de processos suspeitos",
                   items)


# ============================ DNS cache ============================

DNS_RECORD_RE = re.compile(r"Record Name[.\s]+:\s+([^\s]+)", re.IGNORECASE)
DNS_RECORD_RE_PT = re.compile(r"Nome do registro[.\s]+:\s+([^\s]+)", re.IGNORECASE)
# Fallback genérico: linhas com 1+ pontos que parecem domínio
DNS_FALLBACK_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?){1,5}\.[a-z]{2,24})\b",
    re.IGNORECASE,
)


def scan_dns_cache() -> dict:
    """ipconfig /displaydns mostra todos os domínios resolvidos recentemente."""
    try:
        result = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True, text=True, timeout=15,
            encoding="cp850", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as e:  # OSError cobre FileNotFound + winerror genérico
        return _result("DNS Cache", "Cache DNS do Windows", [], error=str(e))

    if result.returncode != 0:
        return _result("DNS Cache", "Cache DNS do Windows", [],
                       error=(result.stderr or "ipconfig falhou")[:200])

    output = result.stdout
    # Pega nomes de domínio: PT/EN primeiro (preciso), fallback se nenhum encontrado
    domains = set()
    for line in output.split("\n"):
        m = DNS_RECORD_RE.search(line) or DNS_RECORD_RE_PT.search(line)
        if m:
            domains.add(m.group(1).strip().rstrip(".").lower())

    # Fallback: se PT/EN não pegou nada, busca padrão genérico (outros locales)
    if not domains:
        for line in output.split("\n"):
            for m in DNS_FALLBACK_RE.finditer(line):
                d = m.group(1).strip().rstrip(".").lower()
                # Filtra lixo (IPs, números de linha, palavras curtas)
                if "." in d and len(d) >= 6 and not d[0].isdigit():
                    domains.add(d)

    items = []
    for domain in sorted(domains):
        matched_kw = None
        severity = None
        for sus_dom, sev in SUSPICIOUS_DOMAINS.items():
            if sus_dom in domain:
                matched_kw, severity = sus_dom, sev
                break
        if not matched_kw:
            continue

        items.append(_item(
            label=domain, detail="Domínio cacheado no DNS local",
            severity=severity, matched=matched_kw,
        ))

    desc = f"Cache DNS local ({len(domains)} domínios resolvidos recentemente)"
    return _result("DNS Cache", desc, items)


# ============================ Hosts file ============================

def scan_hosts_file() -> dict:
    """
    Bloqueio do telemetria do Roblox no hosts é red flag forte —
    cheaters fazem isso pra não enviarem telemetria de cheat detection.
    """
    if not os.path.isfile(HOSTS_FILE):
        return _result("Hosts File", "Modificações em hosts", [],
                       error="hosts file não encontrado")

    try:
        with open(HOSTS_FILE, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except (PermissionError, OSError) as e:
        return _result("Hosts File", "Modificações em hosts", [],
                       error=f"Sem acesso: {e}")

    items = []
    for line_num, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Linha não-comentada — verifica se bloqueia telemetria do Roblox
        lower = stripped.lower()
        for tele_dom in ROBLOX_TELEMETRY_DOMAINS:
            if tele_dom in lower:
                # Verifica se aponta pra 0.0.0.0 / 127.0.0.1 (bloqueio)
                if any(blocker in lower for blocker in ("0.0.0.0", "127.0.0.1", "::1")):
                    # MEDIUM (não HIGH) — pode ser bloqueio parental, escola,
                    # empresa. Cheater fazer isso é possível mas pais
                    # bloqueando filho de jogar Roblox é caso comum.
                    items.append(_item(
                        label=f"L{line_num}: bloqueia {tele_dom}",
                        detail=f"{stripped[:200]}\n"
                               f"⚠ Pode ser bloqueio parental/escola/empresa. Verifique contexto.",
                        severity="medium", matched=f"hosts-block:{tele_dom}",
                    ))
                break

    return _result("Hosts File",
                   "Modificações em C:\\Windows\\System32\\drivers\\etc\\hosts",
                   items)


ALL_NETWORK_SCANNERS = [
    scan_network_connections,
    scan_dns_cache,
    scan_hosts_file,
]
