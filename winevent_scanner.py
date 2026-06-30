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
from database import TRUSTED_DOMAINS


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


def _parse_event_blobs(xml_text: str) -> list:
    """Variante schema-agnóstica: {'_time', '_blob'} com TODO o texto do evento.
    Pro Defender, cujo schema (UserData/EventXML) nem sempre usa <Data Name=…>."""
    out = []
    for chunk in _split_events(xml_text):
        try:
            root = ET.fromstring(chunk)
        except ET.ParseError:
            continue
        ts = ""
        for el in root.iter():
            if el.tag.rsplit("}", 1)[-1] == "TimeCreated":
                ts = el.attrib.get("SystemTime", "") or ts
        blob = " ".join(t.strip() for t in root.itertext() if t and t.strip())
        out.append({"_time": ts, "_blob": blob})
    return out


def _query_events(channel: str, event_id: int, count: int = 300,
                  parser=_parse_events, provider: str | None = None):
    """Eventos de um canal via wevtutil, em XML. Lista de dicts, [] se vazio,
    None se falhar/sem acesso. Isolado pra ser mockável nos testes.

    `provider` filtra por Provider[@Name=...] — essencial pra EventIDs
    promíscuos (104 disparado por vários providers, 501 só faz sentido com
    Ntfs)."""
    if provider:
        q = f"/q:*[System[Provider[@Name='{provider}'] and (EventID={event_id})]]"
    else:
        q = f"/q:*[System[(EventID={event_id})]]"
    try:
        r = subprocess.run(
            [win_tools.tool("wevtutil.exe"), "qe", channel, q,
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
    return parser(out)


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
    # (a) nome de executor no script -> inequívoco (domínio confiável NÃO limpa
    #     isto: se cita executor real, é evidência independente).
    ekw, _ = matching.match_keyword(text)
    if ekw:
        return "high", ekw, ekw
    # (b) download + execução juntos -> cradle. Mas se a fonte é um domínio
    #     CONFIÁVEL (allowlist), o cradle é instalador legítimo do dono — não
    #     flagga. Pega tanto o install-plugin.ps1 baixado quanto scripts grandes
    #     que só casam (b) por terem download e iex em linhas não relacionadas.
    low = text.lower()
    if any(d in low for d in _PS_DOWNLOAD) and any(e in low for e in _PS_EXEC):
        if any(matching.domain_in_text(dom, low) for dom in TRUSTED_DOMAINS):
            return None
        return "high", "ps-scriptblock:download+iex", "download+iex"
    return None


def _classify_process_creation(new_process: str, command_line: str):
    """(severity, matched) p/ um 4688 (criação de processo) que casa executor.

    4688 (Security) registra TODO processo criado quando 'Audit Process Creation'
    está ligado — então pega o executor pelo nome/cmdline mesmo se o .exe foi
    deletado depois. Gated por keyword de executor (word-boundary) -> FP baixo;
    processo comum não casa nada."""
    kw, _ = matching.match_keyword(f"{new_process} {command_line}")
    if kw:
        return "high", kw
    return None


# Termos de ameaça do Defender ligados a cheat (gate anti-FP: NÃO flagga toda
# detecção — PUA/trojan genérico não é prova de cheat de Roblox).
_AV_CHEAT_TERMS = ("hacktool", "exploit", "injector", "cheat", "keylogger")


def _classify_log_cleared(channel_label: str):
    """(severity, matched, label) p/ 104 (log limpo via API) num canal NÃO-Security.

    O 1102 (já em extra_forensics) cobre Security limpo; 104 pega System,
    Application, PowerShell sendo zerados — anti-forense além do clássico.
    Sempre HIGH — limpar log via clear-log é deliberado, não tem fluxo legítimo
    rotineiro num PC de jogador."""
    if not channel_label:
        return None
    return "high", f"log-cleared:{channel_label.lower()}", channel_label


def _classify_usn_cleared(channel_label: str):
    """(severity, matched, label) p/ 3079/501 — USN journal apagado.

    O journal de mudanças do NTFS é a fonte de timeline de filesystem. Apagar
    mata a evidência de criação/delete de arquivos. Pode ocorrer em desfrag
    pesada ou chkdsk — MEDIUM por isso, não HIGH."""
    return "medium", f"usn-cleared:{channel_label.lower()}", channel_label


def _classify_defender_detection(blob: str):
    """(severity, matched, label) p/ uma detecção do Defender ligada a cheat.

    O Defender PEGOU o arquivo (1116/1117) e o cara manteve/excluiu — prova forte.
    HIGH se o nome da ameaça/caminho casa um executor conhecido (smoking gun que
    FUNDE no cluster do executor); MEDIUM se é HackTool/exploit genérico."""
    if not blob:
        return None
    ekw, _ = matching.match_keyword(blob)
    if ekw:
        return "high", ekw, ekw
    low = blob.lower()
    for term in _AV_CHEAT_TERMS:
        if term in low:
            return "medium", f"defender-detection:{term}", term
    return None


# ============================ Scanner ============================

def _fmt_when(iso: str) -> str:
    """'2026-06-28T18:30:45.123Z' -> '2026-06-28 18:30:45'."""
    s = (iso or "").replace("T", " ")
    return s.split(".")[0].rstrip("Z").strip()


def scan_windows_events() -> dict:
    """Puxa eventos de execução/instalação (7045, 4104, 4688) e flagga os
    suspeitos."""
    name = "Event Log de execução (7045/4104/4688)"
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

    # --- 4688: criação de processo (canal Security, precisa de audit ligado) ---
    sec_events = _query_events("Security", 4688)
    if sec_events is not None:
        any_access = True
        seen_proc = set()
        for ev in sec_events:
            new_proc = ev.get("NewProcessName", "")
            res = _classify_process_creation(new_proc, ev.get("CommandLine", ""))
            if not res:
                continue
            sev, matched = res
            if matched in seen_proc:  # executor rodado várias vezes -> 1 item
                continue
            seen_proc.add(matched)
            when = _fmt_when(ev.get("_time", ""))
            items.append(_item(
                label=f"Processo de executor criado: {os.path.basename(new_proc) or matched}",
                detail=f"EventID 4688 · {new_proc or '?'}\n"
                       f"Criação de processo registrada no Security log (audit de "
                       f"processo ligado). Pega o executor pelo nome mesmo se o "
                       f".exe foi deletado depois da SS.",
                severity=sev, matched=matched, timestamp=when,
            ))

    if not any_access:
        return _result(name, desc, [],
                       error="sem acesso ao Event Log (rode como admin)")
    return _result(name, desc, items)


def scan_defender_events() -> dict:
    """Detecções do Windows Defender no Event Log (1116/1117) ligadas a cheat.

    Complementa o scan_defender_tampering (que vê exclusões/RTP no registro):
    aqui é o evento de DETECÇÃO — o próprio antivírus pegou o cheat e o cara
    manteve. Gated por nome de ameaça/executor pra não flaggar PUA/trojan
    genérico (que não é prova de cheat de Roblox)."""
    name = "Defender: detecção de ameaça (Event Log 1116/1117)"
    desc = "O Windows Defender detectou um hacktool/executor (prova forte)"

    events = None
    for eid in (1116, 1117):
        r = _query_events("Microsoft-Windows-Windows Defender/Operational",
                          eid, parser=_parse_event_blobs)
        if r is None:
            continue
        events = (events or []) + r

    if events is None:
        return _result(name, desc, [],
                       error="sem acesso ao log do Defender (rode como admin)")

    items = []
    seen = set()
    for ev in events:
        res = _classify_defender_detection(ev.get("_blob", ""))
        if not res:
            continue
        sev, matched, label = res
        if matched in seen:  # mesma ameaça detectada várias vezes -> 1 item
            continue
        seen.add(matched)
        when = _fmt_when(ev.get("_time", ""))
        snippet = ev.get("_blob", "")[:220]
        items.append(_item(
            label=f"Defender DETECTOU: {label}",
            detail=f"EventID 1116/1117 · {snippet}\n"
                   f"O Windows Defender detectou esta ameaça e ela está/esteve no "
                   f"PC mesmo assim (mantida/excluída/restaurada). O antivírus do "
                   f"próprio Windows flaggou — prova forte de cheat.",
            severity=sev, matched=matched, timestamp=when,
        ))

    return _result(name, desc, items)


def scan_log_clearance() -> dict:
    """Outros logs do Windows limpos/apagados (104 / 3079 / 501 NTFS).

    Complementa o 1102 (cobre Security limpo, em extra_forensics) e o
    scan_event_log_gap (cobre EventLog deletado FURTIVAMENTE, sem evento). Aqui
    pegamos a limpeza via API que SOBROU evento:
      - 104 (canais System/Application, Provider=Microsoft-Windows-Eventlog):
        clear-log de um log NÃO-Security. Filtrar provider é OBRIGATÓRIO — sem
        ele pega 104 de DOTNETRuntime, Office etc. (vira FP em qualquer PC).
      - 3079 (canal Application, Provider Ntfs) e 501 (canal
        Microsoft-Windows-Ntfs/Operational com fallback System, Provider Ntfs):
        USN journal apagado/truncado."""
    name = "Event Log: limpeza (104/501/3079)"
    desc = "Outros logs limpos via clear-log e USN journal apagado (anti-forense)"
    items = []
    any_access = False

    # --- 104 em System e Application (Provider=Microsoft-Windows-Eventlog) ---
    for channel in ("System", "Application"):
        events = _query_events(channel, 104, parser=_parse_event_blobs,
                                provider="Microsoft-Windows-Eventlog")
        if events is None:
            continue
        any_access = True
        if not events:
            continue
        ev = events[0]  # /rd:true -> mais recente primeiro
        res = _classify_log_cleared(channel)
        if not res:
            continue
        sev, matched, label = res
        when = _fmt_when(ev.get("_time", ""))
        items.append(_item(
            label=f"Log do Windows LIMPO: {label}",
            detail=f"EventID 104 · canal {channel} · Provider Microsoft-Windows-Eventlog\n"
                   f"Alguém usou clear-log na API pra zerar este log. Diferente do "
                   f"1102 (que cobre Security): aqui é System/Application sendo "
                   f"apagado. Anti-forense deliberado.",
            severity=sev, matched=matched, timestamp=when,
        ))

    # --- 3079: USN journal apagado, canal Application + Provider Ntfs ---
    events = _query_events("Application", 3079, parser=_parse_event_blobs,
                            provider="Ntfs")
    if events is not None:
        any_access = True
        if events:
            ev = events[0]
            sev, matched, label = _classify_usn_cleared("Application")
            when = _fmt_when(ev.get("_time", ""))
            items.append(_item(
                label="USN journal apagado (Application / EID 3079)",
                detail=f"EventID 3079 · canal Application · Provider Ntfs\n"
                       f"O journal de mudanças do NTFS (USN) foi truncado/apagado. "
                       f"Mata a linha do tempo de filesystem usada pelo scan_usn. "
                       f"Pode ocorrer em desfrag pesada/chkdsk — confira janela.",
                severity=sev, matched=matched, timestamp=when,
            ))

    # --- 501: USN journal apagado. Canal correto é Microsoft-Windows-Ntfs/Operational;
    #     fallback System pra builds antigas que ainda emitem lá. Provider=Ntfs sempre. ---
    ev501 = None
    used_channel = None
    for ch in ("Microsoft-Windows-Ntfs/Operational", "System"):
        r = _query_events(ch, 501, parser=_parse_event_blobs, provider="Ntfs")
        if r is None:
            continue
        any_access = True
        if r:
            ev501 = r[0]
            used_channel = ch
            break  # achou em um canal, não precisa do outro
    if ev501 is not None:
        sev, matched, _ = _classify_usn_cleared("System")
        when = _fmt_when(ev501.get("_time", ""))
        items.append(_item(
            label=f"USN journal apagado (NTFS / EID 501)",
            detail=f"EventID 501 · canal {used_channel} · Provider Ntfs\n"
                   f"O journal de mudanças do NTFS (USN) foi truncado/apagado. "
                   f"Mesmo papo do 3079 — pode ocorrer em desfrag pesada/chkdsk.",
            severity=sev, matched=matched, timestamp=when,
        ))

    if not any_access:
        return _result(name, desc, [],
                       error="sem acesso ao Event Log (rode como admin)")
    return _result(name, desc, items)


ALL_WINEVENT_SCANNERS = [
    scan_windows_events,
    scan_defender_events,
    scan_log_clearance,
]
