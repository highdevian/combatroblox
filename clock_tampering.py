"""
Detecção de manipulação do relógio — anti-bypass de linha do tempo.

Truque: voltar o relógio do sistema pra trás antes/durante a SS, pra que os
artefatos de execução do cheat (Prefetch/Amcache/BAM) caiam FORA da janela de
tempo da sessão — a correlação por horário deixa de bater.

Sinal: evento 4616 do log de Security ("a hora do sistema foi alterada"), que
registra a hora anterior e a nova. Foco em saltos PARA TRÁS de 10+ min (o
ataque). Salto pra frente é ignorado (sync de NTP / bateria de CMOS morta
corrigem o relógio pra frente — comum e legítimo).

Lê via wevtutil (igual o check de 1102). Precisa de admin; sem admin = erro.
"""

from models import _result, _item
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

import win_tools


_JUMP_MIN_SECONDS = 600   # ignora saltos < 10 min (drift de NTP)
_JUMP_BIG_SECONDS = 3600  # >= 1h = mais grave

# SIDs de contas de SERVIÇO (locale-independente). Mudança de relógio por uma
# destas é correção automática do SO, não o ataque:
#   S-1-5-18 = SYSTEM        (kernel / correção de boot / dual-boot)
#   S-1-5-19 = LOCAL SERVICE (W32Time / NTP roda aqui)
#   S-1-5-20 = NETWORK SERVICE
# Empiricamente, num PC real TODO 4616 legítimo vem de S-1-5-19 via svchost.exe,
# e o nome do subject é LOCALIZADO ("SERVIÇO LOCAL" em PT-BR) — por isso a
# classificação é por SID, nunca por nome.
_SERVICE_SID_PREFIXES = ("s-1-5-18", "s-1-5-19", "s-1-5-20")


def _is_service_actor(sid: str, process: str) -> bool:
    """True se quem mudou o relógio é conta de serviço/sistema (NTP, boot,
    dual-boot) — não o usuário interativo. Primário: SID de serviço. Fallback
    defensivo: processo é svchost.exe (host do W32Time) quando o SID falta."""
    s = (sid or "").strip().lower()
    if s and any(s.startswith(p) for p in _SERVICE_SID_PREFIXES):
        return True
    if not s:  # sem SID no evento — usa o processo como pista fraca
        base = (process or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
        if base == "svchost.exe":
            return True
    return False


def _parse_iso(s: str):
    """'2026-06-08T17:00:00.000000000Z' -> datetime (naive UTC), ou None."""
    s = (s or "").strip().rstrip("Z")
    if not s:
        return None
    if "." in s:  # fractional de 9 dígitos -> trunca pra 6 (limite do strptime)
        head, frac = s.split(".", 1)
        s = head + "." + frac[:6]
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _fmt_delta(seconds: float) -> str:
    s = int(seconds)
    h, m = s // 3600, (s % 3600) // 60
    if h and m:
        return f"{h}h {m}min"
    if h:
        return f"{h}h"
    return f"{m}min"


def _clock_item(prev: str, new: str, subject: str = "", process: str = "",
                sid: str = ""):
    """Constrói o item se for um salto PARA TRÁS relevante; senão None.
    Núcleo testável, sem subprocess.

    Salto pra trás por conta de SERVIÇO (NTP/boot/dual-boot) vira LOW contexto —
    não é o ataque. Por usuário INTERATIVO mantém MEDIUM/HIGH (anti-bypass real)."""
    p, n = _parse_iso(prev), _parse_iso(new)
    if not p or not n:
        return None
    delta = (n - p).total_seconds()
    # Só interessa salto pra trás (delta negativo) de 10+ min.
    if delta > -_JUMP_MIN_SECONDS:
        return None
    back = -delta
    human = _fmt_delta(back)
    who = subject or "?"
    proc = f" via {process}" if process else ""
    when = n.strftime("%Y-%m-%d %H:%M:%S")

    # Correção do SO (NTP / kernel no boot / skew de dual-boot) → contexto, não ataque.
    if _is_service_actor(sid, process):
        return _item(
            label=f"Relógio ajustado {human} pra trás (serviço do sistema)",
            detail=f"Hora alterada de {prev} para {new} (salto de {human} pra trás) por "
                   f"conta de serviço{proc}. Mudança feita pelo próprio Windows (sync de "
                   f"NTP/W32Time, correção no boot, ou skew de dual-boot Linux/Windows) — "
                   f"NÃO é o usuário voltando o relógio pra burlar a SS. Listado só como "
                   f"contexto.",
            severity="low", matched="clock-rollback-servico", timestamp=when,
        )

    # Usuário interativo voltando o relógio = o anti-bypass de verdade.
    severity = "high" if back >= _JUMP_BIG_SECONDS else "medium"
    return _item(
        label=f"Relógio do sistema voltado {human} pra trás",
        detail=f"Hora alterada de {prev} para {new} (salto de {human} PARA TRÁS), por {who}{proc}. "
               f"Voltar o relógio é anti-bypass: joga os artefatos do cheat pra fora da janela "
               f"de tempo da SS. Sync de NTP corrige pra frente em segundos — isto é diferente.",
        severity=severity, matched="clock-rollback", timestamp=when,
    )


def _split_events(xml_text: str) -> list:
    """wevtutil /f:xml concatena <Event>…</Event> sem root único — separa."""
    out = []
    for seg in xml_text.split("</Event>"):
        i = seg.find("<Event")
        if i != -1:
            out.append(seg[i:] + "</Event>")
    return out


def _parse_4616_xml(xml_text: str) -> list:
    events = []
    for chunk in _split_events(xml_text):
        try:
            root = ET.fromstring(chunk)
        except ET.ParseError:
            continue
        data = {}
        for d in root.iter():
            tag = d.tag.rsplit("}", 1)[-1]  # tira namespace
            if tag == "Data":
                name = d.attrib.get("Name")
                if name:
                    data[name] = d.text or ""
        if data.get("PreviousTime") or data.get("NewTime"):
            events.append({
                "prev": data.get("PreviousTime", ""),
                "new": data.get("NewTime", ""),
                "subject": data.get("SubjectUserName", ""),
                "sid": data.get("SubjectUserSid", ""),
                "process": data.get("ProcessName", ""),
            })
    return events


def _query_4616():
    """Eventos 4616 (hora do sistema alterada) via wevtutil, em XML.
    Retorna lista de dicts, [] se sem eventos, None se falhar/sem acesso."""
    try:
        r = subprocess.run(
            [win_tools.tool("wevtutil.exe"), "qe", "Security",
             "/q:*[System[(EventID=4616)]]", "/c:200", "/rd:true", "/f:xml"],
            capture_output=True, timeout=25,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    out = ""
    for enc in ("utf-8", "cp1252", "cp850"):
        try:
            out = (r.stdout or b"").decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if not out.strip():
        return []
    return _parse_4616_xml(out)


def scan_clock_tampering() -> dict:
    """Detecta o relógio do sistema voltado pra trás (anti-bypass de timeline)."""
    events = _query_4616()
    if events is None:
        return _result("Manipulação do relógio do sistema",
                       "Relógio voltado pra trás (anti-bypass de linha do tempo)",
                       [], error="sem acesso ao log de Security (rode como admin)")
    items = []
    for ev in events:
        it = _clock_item(ev["prev"], ev["new"], ev.get("subject", ""),
                         ev.get("process", ""), ev.get("sid", ""))
        if it:
            items.append(it)
    return _result("Manipulação do relógio do sistema",
                   "Relógio voltado pra trás (anti-bypass de linha do tempo)", items)


ALL_CLOCK_SCANNERS = [
    scan_clock_tampering,
]
