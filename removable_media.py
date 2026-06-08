"""
Detecção de mídia removível (USB / HD externo) — anti-bypass de pendrive.

Dois truques que os cursos de telagem ensinam ("trapaças em pen drives"):
  1. Rodar o cheat de um pendrive e DESPLUGAR — o .exe some do disco, mas o
     Windows registrou o dispositivo em USBSTOR. `scan_usb_history` lista as
     USBs conectadas recentemente (contexto pra cruzar com o horário de jogo).
  2. Rodar o cheat com a USB ainda plugada (esqueceu, ou roda ao vivo) —
     `scan_removable_drives` varre o conteúdo da unidade removível conectada.

Tudo leitura. Lê o registro (USBSTOR) e o conteúdo de drives removíveis montados.
FAT32 de pendrive não tem USN journal — desplugar não deixa rastro NA USB, mas
o registro do host e os artefatos de execução do C: ainda contam a história.
"""

import os
import ctypes
import winreg
from datetime import datetime, timedelta

import matching


# ----------------------------- helpers -----------------------------

def _result(name, description, items, error=None):
    if error:
        status, summary = "error", f"Erro: {error}"
    elif items:
        status, summary = "suspicious", f"{len(items)} item(s) suspeito(s)"
    else:
        status, summary = "clean", "Nenhum vestígio encontrado"
    return {"name": name, "description": description, "status": status,
            "items": items, "summary": summary, "error": error}


def _item(label, detail, severity, matched, timestamp=""):
    return {"label": label, "detail": detail, "severity": severity,
            "matched": matched, "timestamp": timestamp}


def _fmt_ts(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, OverflowError):
        return ""


def _filetime_to_dt(ft100ns):
    """100ns desde 1601 (formato do winreg.QueryInfoKey) -> datetime, ou None."""
    if not ft100ns:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=ft100ns / 10)
    except (OverflowError, OSError, ValueError):
        return None


# ====================== Histórico de USB (USBSTOR) ======================

_USBSTOR_KEY = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
_RECENT_HOURS = 24  # USB com atividade nas últimas N horas = relevante pra SS


def _friendly_usb_name(dev_class: str) -> str:
    # "Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00" -> "SanDisk Cruzer Blade 1.00"
    # Parse por token (split em '&') pra não colidir com 'Disk' dentro do vendor
    # (ex.: SanDisk) nem com substrings.
    parts = []
    for tok in dev_class.split("&"):
        for prefix in ("Ven_", "Prod_", "Rev_"):
            if tok.startswith(prefix):
                parts.append(tok[len(prefix):])
                break
        # tokens sem prefixo conhecido (Disk, CdRom, …) são descartados
    return " ".join(" ".join(parts).replace("_", " ").split())


def _usb_history_item(dev_class: str, last_seen, now=None):
    """Constrói o item se a USB teve atividade recente; senão None.
    Isolado do winreg pra ser testável sem registro."""
    if last_seen is None:
        return None
    now = now or datetime.now()
    if (now - last_seen) > timedelta(hours=_RECENT_HOURS):
        return None
    friendly = _friendly_usb_name(dev_class)
    ts = last_seen.strftime("%Y-%m-%d %H:%M:%S")
    return _item(
        label=f"USB conectada recentemente: {friendly}",
        detail=f"Dispositivo de armazenamento USB com atividade no registro em {ts} "
               f"(últimas {_RECENT_HOURS}h). Numa SS, pendrive plugado perto do horário "
               f"de jogo é vetor de cheat rodado de USB — que despluga sem deixar o .exe "
               f"no disco. Cruze com o horário dos artefatos de execução. (Contexto, não prova.)",
        severity="low",
        matched=f"usb-recente:{friendly.lower()[:40]}", timestamp=ts,
    )


def scan_usb_history() -> dict:
    """Lista dispositivos USB de armazenamento conectados recentemente.

    Usa o last-write do registro (winreg.QueryInfoKey) da instância em USBSTOR
    como proxy de 'última atividade' — robusto e independente de versão do
    Windows. Só surfa os recentes (< 24h) e em severidade BAIXA (contexto), pra
    não poluir nem inflar o veredito com toda USB que já passou pela máquina."""
    items = []
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _USBSTOR_KEY)
    except OSError as e:
        return _result("Histórico de USB",
                       "Dispositivos USB de armazenamento conectados recentemente",
                       [], error=f"sem acesso a USBSTOR (rode como admin): {e}")

    try:
        i = 0
        while True:
            try:
                dev_class = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                cls_key = winreg.OpenKey(root, dev_class)
            except OSError:
                continue
            last_seen = None
            try:
                j = 0
                while True:
                    try:
                        inst = winreg.EnumKey(cls_key, j)
                    except OSError:
                        break
                    j += 1
                    try:
                        ik = winreg.OpenKey(cls_key, inst)
                        ft = winreg.QueryInfoKey(ik)[2]
                        winreg.CloseKey(ik)
                    except OSError:
                        continue
                    dt = _filetime_to_dt(ft)
                    if dt and (last_seen is None or dt > last_seen):
                        last_seen = dt
            finally:
                winreg.CloseKey(cls_key)

            it = _usb_history_item(dev_class, last_seen)
            if it:
                items.append(it)
    finally:
        winreg.CloseKey(root)

    return _result("Histórico de USB",
                   "Dispositivos USB de armazenamento conectados recentemente", items)


# ====================== Conteúdo de drive removível plugado ======================

_DRIVE_REMOVABLE = 2
_REMOVABLE_EXTS = (".exe", ".dll", ".bat", ".cmd", ".lua")
_MAX_DEPTH = 2


def _removable_drive_letters() -> list:
    """Letras de unidade montadas AGORA cujo tipo é removível (USB/cartão)."""
    out = []
    try:
        k32 = ctypes.windll.kernel32
        mask = k32.GetLogicalDrives()
    except (AttributeError, OSError):
        return out
    for n in range(26):
        if not (mask >> n) & 1:
            continue
        root = f"{chr(65 + n)}:\\"
        try:
            if k32.GetDriveTypeW(ctypes.c_wchar_p(root)) == _DRIVE_REMOVABLE:
                out.append(root)
        except (OSError, AttributeError):
            pass
    return out


def scan_removable_drives() -> dict:
    """Varre o conteúdo de unidades REMOVÍVEIS montadas agora, procurando
    arquivo/pasta com nome de executor conhecido. Pega o cheat que está no
    pendrive ainda plugado durante a SS (esqueceu de desplugar, ou roda ao vivo).

    Só flaga match de keyword de executor (anti-FP): app portátil legítimo numa
    USB não casa, então não dispara."""
    items = []
    seen = set()
    for drive in _removable_drive_letters():
        try:
            for dirpath, dirnames, filenames in os.walk(drive):
                if dirpath[len(drive):].count(os.sep) > _MAX_DEPTH:
                    dirnames[:] = []
                    continue
                for f in filenames:
                    if not f.lower().endswith(_REMOVABLE_EXTS):
                        continue
                    kw, _sev = matching.match_keyword(f)
                    if not kw:
                        kw, _sev = matching.match_keyword(dirpath)
                    if not kw:
                        continue
                    full = os.path.join(dirpath, f)
                    if full.lower() in seen:
                        continue
                    seen.add(full.lower())
                    try:
                        mtime = _fmt_ts(os.path.getmtime(full))
                    except OSError:
                        mtime = ""
                    items.append(_item(
                        label=f"Cheat em mídia removível: {f}",
                        detail=f"{full}\nArquivo de executor numa unidade REMOVÍVEL ({drive}) "
                               f"conectada agora. Rodar o cheat de pendrive e desplugar é truque "
                               f"de anti-SS — aqui a USB ainda está plugada.",
                        severity="high", matched=kw, timestamp=mtime,
                    ))
        except (OSError, PermissionError):
            continue
    return _result("Mídia removível plugada",
                   "Conteúdo de cheat em USB/HD externo conectado durante a SS", items)


ALL_REMOVABLE_SCANNERS = [
    scan_usb_history,
    scan_removable_drives,
]
