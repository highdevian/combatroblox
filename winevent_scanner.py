"""
Análise de Event Log do Windows (estilo Hayabusa) — rastros de EXECUÇÃO que
sobrevivem à deleção do arquivo.

O Telador já lê 4616 (relógio mexido), 1102 (Security limpo) e VSS 8224. Aqui a
gente puxa os eventos que continuam no log mesmo depois do cara apagar o .exe/.sys:

  - 7045 (System / Service Control Manager): serviço ou driver INSTALADO. Pega
    BYOVD (winring0, mhyprot2, capcom…) e kdmapper mesmo que o driver já tenha
    sido desinstalado — o scan_kernel_drivers só vê o que está registrado AGORA;
    o 7045 é a linha do tempo do que JÁ rodou. Usa o mesmo `driver-byovd:<nome>`
    do scan_kernel_drivers, então os dois FUNDEM no mesmo alvo (2 fontes = mais
    confiança).

  - 4104 (PowerShell/Operational): script block logging. Captura o script que
    rodou de fato — download cradle (iwr/iex/DownloadString) e nome de executor —
    mais rico que o histórico de console (que o cara apaga fácil).

Precisa de admin pra alguns logs. Gated por keyword -> FP baixo: serviço/script
comum não casa nada. Reusa as listas que já existem (SUSPECT_DRIVER_NAMES,
PS_DOWNLOAD_KEYWORDS, matching de executor).
"""

from models import _result, _item
import os
import subprocess
import xml.etree.ElementTree as ET

import win_tools
import matching
from extra_forensics import SUSPECT_DRIVER_NAMES


# ============================ Query + parse (wevtutil) ============================

def _split_events(xml_text: str) -> list:
    """wevtutil /f:xml concatena <Event>…</Event> sem root único — separa.
    (Mesmo padrão do clock_tampering.)"""
    out = []
    for seg in xml_text.split("</Event>"):
        i = seg.find("<Event")
        if i != -1:
            out.append(seg[i:] + "</Event>")
    return out


def _parse_events(xml_text: str) -> list:
    """Lista de dicts {Name: valor} de cada <Data>, + '_time' do TimeCreated."""
    events = []
    for chunk in _split_events(xml_text):
        try:
            root = ET.fromstring(chunk)
        except ET.ParseError:
            continue
        data = {}
        ts = ""
        for el in root.iter():
            tag = el.tag.rsplit("}", 1)[-1]  # tira namespace
            if tag == "Data":
                name = el.attrib.get("Name")
                if name:
                    data[name] = el.text or ""
            elif tag == "TimeCreated":
                ts = el.attrib.get("SystemTime", "") or ts
        if data:
            data["_time"] = ts
            events.append(data)
    return events


def _query_events(channel: str, event_id: int, count: int = 300):
    """Eventos de um canal via wevtutil, em XML. Lista de dicts, [] se vazio,
    None se falhar/sem acesso. Isolado pra ser mockável nos testes."""
    try:
        r = subprocess.run(
            [win_tools.tool("wevtutil.exe"), "qe", channel,
             f"/q:*[System[(EventID={event_id})]]",
             f"/c:{count}", "/rd:true", "/f:xml"],
            capture_output=True, timeout=30,
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
    return _parse_events(out)


# ============================ Classificadores puros ============================

def _driver_base(name: str) -> str:
    """'winring0.sys' / caminho -> 'winring0' (igual ao scan_kernel_drivers)."""
    base = os.path.basename((name or "").replace("/", "\\")).lower()
    if base.endswith(".sys"):
        base = base[:-4]
    return base


_USER_PATH_HINTS = ("\\users\\", "\\temp\\", "\\downloads\\", "\\appdata\\",
                    "\\desktop\\")


def _classify_service_install(service_name: str, image_path: str,
                             service_type: str = ""):
    """(severity, matched, label) p/ um 7045 suspeito; senão None.

    Ordem: driver BYOVD conhecido (casa por nome EXATO, como o scan_kernel_drivers,
    pra não dar FP com substring tipo 'asio') -> executor/kdmapper por keyword ->
    DRIVER KERNEL plantado em pasta de usuário."""
    # 1) driver BYOVD conhecido (nome exato do ServiceName ou do binário)
    for cand in (_driver_base(service_name), _driver_base(image_path)):
        if cand in SUSPECT_DRIVER_NAMES:
            return "high", f"driver-byovd:{cand}", f"{cand}.sys"

    # 2) executor / kdmapper por keyword (word-boundary -> FP baixo)
    kw, _ = matching.match_keyword(f"{service_name} {image_path}")
    if kw:
        return "high", kw, service_name or kw

    # 3) DRIVER KERNEL plantado em pasta de usuário. Restrito a kernel-mode de
    #    propósito: serviço USERMODE de %AppData% é comuníssimo em app legítimo
    #    (updaters etc.) — flaggar tudo seria FP. Driver kernel de pasta gravável
    #    é o padrão do BYOVD-dropper, e raro em software legítimo.
    is_kernel = "kernel" in (service_type or "").lower()
    low = (image_path or "").lower().replace("/", "\\")
    if is_kernel and low and any(h in low for h in _USER_PATH_HINTS):
        return "medium", "svc-install-userpath-driver", service_name or image_path

    return None


# Download e execução separados: o cradle malicioso é baixar E executar na mesma
# linha. `iwr`/`Invoke-WebRequest` SOZINHO é download legítimo comum (baixar zip,
# módulo) — não basta pra HIGH.
_PS_EXEC = ("iex ", "iex(", "iex;", "invoke-expression")
_PS_DOWNLOAD = ("downloadstring", "downloadfile", "downloaddata", "net.webclient",
                "invoke-webrequest", "iwr ", "invoke-restmethod", "irm ",
                "start-bitstransfer", "bitsadmin /transfer", "certutil -urlcache",
                "wget ", "curl ")


def _classify_scriptblock(text: str):
    """(severity, matched, label) p/ um 4104 suspeito; senão None.

    HIGH se: (a) cita nome de executor; ou (b) BAIXA e EXECUTA na mesma linha
    (download cradle clássico). Download puro (sem iex) NÃO flagga — é uso
    legítimo comum de PowerShell."""
    if not text:
        return None
    # (a) nome de executor no script -> inequívoco
    ekw, _ = matching.match_keyword(text)
    if ekw:
        return "high", ekw, ekw
    # (b) download + execução juntos -> cradle
    low = text.lower()
    if any(d in low for d in _PS_DOWNLOAD) and any(e in low for e in _PS_EXEC):
        return "high", "ps-scriptblock:download+iex", "download+iex"
    return None


# ============================ Scanner ============================

def _fmt_when(iso: str) -> str:
    """'2026-06-28T18:30:45.123Z' -> '2026-06-28 18:30:45'."""
    s = (iso or "").replace("T", " ")
    return s.split(".")[0].rstrip("Z").strip()


def scan_windows_events() -> dict:
    """Puxa eventos de execução/instalação (7045, 4104) e flagga os suspeitos."""
    name = "Event Log de execução (7045/4104)"
    desc = "Rastros de execução/instalação no Event Log (sobrevivem à deleção)"

    items = []
    any_access = False

    # --- 7045: serviço/driver instalado (canal System) ---
    sys_events = _query_events("System", 7045)
    if sys_events is not None:
        any_access = True
        seen_svc = set()
        for ev in sys_events:
            res = _classify_service_install(
                ev.get("ServiceName", ""), ev.get("ImagePath", ""),
                ev.get("ServiceType", ""))
            if not res:
                continue
            sev, matched, label = res
            # mesmo serviço reinstalado gera vários 7045 — colapsa (a chave inclui
            # o ServiceName pra não fundir serviços distintos que dividem o matched
            # genérico 'svc-install-userpath'). /rd:true => fica com o mais recente.
            dedup_key = (matched, ev.get("ServiceName", ""))
            if dedup_key in seen_svc:
                continue
            seen_svc.add(dedup_key)
            when = _fmt_when(ev.get("_time", ""))
            items.append(_item(
                label=f"Serviço/driver instalado: {label}",
                detail=f"EventID 7045 · ServiceName={ev.get('ServiceName','?')} · "
                       f"ImagePath={ev.get('ImagePath','?')}\n"
                       f"Instalação de serviço/driver registrada no Event Log. "
                       f"Sobrevive à deleção do arquivo — pega BYOVD/loader mesmo "
                       f"se o driver foi removido depois da SS.",
                severity=sev, matched=matched, timestamp=when,
            ))

    # --- 4104: PowerShell script block (canal Operational) ---
    ps_events = _query_events("Microsoft-Windows-PowerShell/Operational", 4104)
    if ps_events is not None:
        any_access = True
        seen = set()
        for ev in ps_events:
            text = ev.get("ScriptBlockText", "")
            res = _classify_scriptblock(text)
            if not res:
                continue
            sev, matched, _label = res
            if matched in seen:  # script multi-parte gera vários 4104 iguais
                continue
            seen.add(matched)
            when = _fmt_when(ev.get("_time", ""))
            snippet = " ".join(text.split())[:200]
            items.append(_item(
                label="PowerShell script block suspeito",
                detail=f"EventID 4104 · {ev.get('Path','') or '(sem arquivo)'}\n"
                       f"Trecho: {snippet}\n"
                       f"Script capturado pelo script block logging — download "
                       f"cradle ou referência a executor. Mais difícil de apagar "
                       f"que o histórico de console.",
                severity=sev, matched=matched, timestamp=when,
            ))

    if not any_access:
        return _result(name, desc, [],
                       error="sem acesso ao Event Log (rode como admin)")
    return _result(name, desc, items)


ALL_WINEVENT_SCANNERS = [
    scan_windows_events,
]
