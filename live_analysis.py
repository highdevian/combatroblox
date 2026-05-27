"""
Análise AO VIVO do processo Roblox:
  - Lista TODAS as DLLs carregadas (memory_maps)
  - Flagga DLLs em paths suspeitos (Temp/Downloads/Desktop/AppData)
  - Verifica assinatura digital via WinVerifyTrust
  - Match contra database de keywords

Cheat injetado fica EXPOSTO mesmo se o arquivo foi apagado depois,
porque a DLL ainda tá no espaço de endereço do Roblox.
"""

import os
import ctypes
from ctypes import wintypes
from datetime import datetime

from database import (
    EXECUTOR_KEYWORDS,
    ROBLOX_PROCESS_NAMES,
    TRUSTED_DLL_PATHS,
    SUSPICIOUS_DLL_PATHS,
)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ============================ WinVerifyTrust setup ============================

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pcwszFilePath", ctypes.c_wchar_p),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID)),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.c_ulong),
        ("fdwRevocationChecks", ctypes.c_ulong),
        ("dwUnionChoice", ctypes.c_ulong),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", ctypes.c_ulong),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", ctypes.c_ulong),
        ("dwUIContext", ctypes.c_ulong),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


WTD_UI_NONE      = 2
WTD_REVOKE_NONE  = 0
WTD_CHOICE_FILE  = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE  = 2

# {00AAC56B-CD44-11d0-8CC2-00C04FC295EE} - WINTRUST_ACTION_GENERIC_VERIFY_V2
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11d0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


def _is_dll_signed(path: str) -> bool | None:
    """
    Retorna True se DLL é assinada e válida, False se inválida, None se erro.
    """
    if not os.path.isfile(path):
        return None

    try:
        wintrust = ctypes.windll.wintrust
    except OSError:
        return None

    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = path
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwUnionChoice = WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = 0
    data.dwUIContext = 0

    try:
        result = wintrust.WinVerifyTrust(None,
                                          ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                                          ctypes.byref(data))
        # Cleanup
        data.dwStateAction = WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None,
                                 ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                                 ctypes.byref(data))
        return result == 0
    except (OSError, ctypes.ArgumentError):
        return None


# ============================ Helpers ============================

def _result(name, description, items, error=None):
    # Itens meta_only (ex: cabeçalho de processo) não contam como DLL suspeita
    real_items = [i for i in items if not i.get("meta_only")]
    if error:
        status = "error"
        summary = f"Erro: {error}"
    elif not real_items:
        status = "clean"
        summary = "Nenhuma DLL suspeita"
    else:
        status = "suspicious"
        summary = f"{len(real_items)} DLL(s) suspeita(s)"

    return {
        "name": name, "description": description, "status": status,
        "items": items, "summary": summary, "error": error,
    }


def _item(label, detail, severity, matched, timestamp="", meta_only=False):
    return {
        "label": label, "detail": detail, "severity": severity,
        "matched": matched, "timestamp": timestamp, "meta_only": meta_only,
    }


def _match_keyword(text: str):
    if not text:
        return None, None
    lower = text.lower()
    for keyword, severity in EXECUTOR_KEYWORDS.items():
        if keyword in lower:
            return keyword, severity
    return None, None


def _classify_dll_path(path: str) -> tuple[str, str]:
    """
    Retorna (categoria, severity).
    Categorias: trusted, suspicious-path, user-folder, normal.
    """
    if not path:
        return "unknown", "low"

    lower = path.lower().replace("/", "\\")

    # Path-based suspicious
    for sus in SUSPICIOUS_DLL_PATHS:
        if sus in lower:
            return "suspicious-path", "high"

    # Trusted system paths
    for trust in TRUSTED_DLL_PATHS:
        if lower.startswith(trust):
            return "trusted", "low"

    # Outside C:\Windows + outside Program Files = suspeito
    if not lower.startswith(("c:\\windows", "c:\\program files",
                              "c:\\programdata\\microsoft",
                              "c:\\users\\all users\\microsoft")):
        return "non-standard", "medium"

    return "normal", "low"


# ============================ Main scanner ============================

def scan_roblox_dll_injection() -> dict:
    """
    Lista todas as DLLs carregadas em cada processo do Roblox que estiver rodando.
    Flag as não-assinadas, as de paths suspeitos, e as que matcham keyword.

    Pega cheat INJETADO mesmo se rodando agora.
    """
    if not HAS_PSUTIL:
        return _result("DLL Injection (Roblox)", "Análise live do processo Roblox",
                       [], error="psutil não instalado")

    items = []
    target_pids = []

    # Acha processos do Roblox
    for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            name = (proc.info.get("name") or "")
            if name in ROBLOX_PROCESS_NAMES or name.lower() in {n.lower() for n in ROBLOX_PROCESS_NAMES}:
                target_pids.append((proc.info["pid"], name, proc.info.get("exe", ""),
                                    proc.info.get("create_time", 0)))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not target_pids:
        return _result("DLL Injection (Roblox)",
                       "Análise live do processo Roblox",
                       [], error="Nenhum processo Roblox rodando agora — abra o jogo primeiro")

    # Pra cada PID alvo, lista DLLs
    for pid, name, exe, created in target_pids:
        try:
            proc = psutil.Process(pid)
            mmaps = proc.memory_maps(grouped=True)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            items.append(_item(
                label=f"PID {pid} ({name})",
                detail=f"Sem acesso ao processo (rode como admin): {e}",
                severity="medium", matched="access-denied",
            ))
            continue

        ts_created = ""
        try:
            ts_created = datetime.fromtimestamp(created).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError):
            pass

        # Header sobre o processo (informativo, não conta como DLL suspeita)
        items.append(_item(
            label=f"[PROCESSO] PID {pid} — {name}",
            detail=f"Iniciado em {ts_created}  |  exe: {exe}",
            severity="low", matched="roblox-running", timestamp=ts_created,
            meta_only=True,
        ))

        for m in mmaps:
            path = getattr(m, "path", "") or ""
            if not path:
                continue
            # Só DLLs (e .ocx, .acm — bibliotecas em geral)
            if not path.lower().endswith((".dll", ".ocx", ".acm", ".drv", ".exe")):
                continue

            category, severity = _classify_dll_path(path)
            matched = None

            # Keyword match
            kw, kw_sev = _match_keyword(path)
            if kw:
                matched = kw
                severity = "high"

            # Path suspeito mata o rolê
            if category == "suspicious-path":
                matched = matched or "path-suspeito"

            # Trusted = pula
            if category == "trusted" and not matched:
                continue

            # Verifica assinatura SE não é trusted nem matched
            signed = None
            if category not in ("trusted",):
                signed = _is_dll_signed(path)
                if signed is False:
                    if severity == "low":
                        severity = "medium"
                    matched = matched or "DLL não assinada"
                elif signed is True and not matched:
                    # Assinada + não-trusted-path = ainda informativo
                    if category == "non-standard":
                        continue  # Skip - signed, just outside normal paths

            if not matched and category == "non-standard":
                matched = "DLL fora de paths padrão"

            if not matched:
                continue

            sig_tag = "✓ assinada" if signed is True else (
                "✗ NÃO assinada" if signed is False else "? assinatura desconhecida")

            items.append(_item(
                label=f"DLL: {os.path.basename(path)}",
                detail=f"{path}\n[{sig_tag} · cat: {category}]",
                severity=severity, matched=matched, timestamp="",
            ))

    return _result("DLL Injection (Roblox)",
                   "DLLs carregadas no processo do Roblox AGORA (pega cheat ativo)",
                   items)


# ============================ Process tree ============================

def scan_process_tree() -> dict:
    """
    Lista processos com seu parent. Roblox spawnado por algo que NÃO é
    explorer.exe / bloxstrap.exe / RobloxPlayerLauncher.exe = vermelho
    (alguém pode tê-lo executado via injector).
    """
    if not HAS_PSUTIL:
        return _result("Process Tree", "Árvore de processos do Roblox", [],
                       error="psutil não instalado")

    LEGIT_PARENTS = {
        "explorer.exe", "bloxstrap.exe", "robloxplayerlauncher.exe",
        "robloxplayerinstaller.exe", "microsoftedge.exe", "msedge.exe",
        "chrome.exe", "firefox.exe", "brave.exe", "opera.exe",
        "rundll32.exe", "shellexp.exe", "winlogon.exe", "services.exe",
        "svchost.exe", "wininit.exe",
    }

    items = []

    for proc in psutil.process_iter(["pid", "name", "ppid"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name not in {n.lower() for n in ROBLOX_PROCESS_NAMES}:
                continue
            ppid = proc.info.get("ppid", 0)

            parent_unknown = False
            try:
                parent = psutil.Process(ppid)
                parent_name = parent.name()
                try:
                    parent_exe = parent.exe()
                except (psutil.AccessDenied, PermissionError):
                    parent_exe = "(sem acesso)"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                parent_unknown = True
                parent_name = "?"
                parent_exe = "?"

            # Se não conseguiu ler o parent, NÃO flag (precisaria admin)
            if parent_unknown:
                continue

            ok = parent_name.lower() in LEGIT_PARENTS
            if ok:
                continue

            items.append(_item(
                label=f"{proc.info['name']} spawnado por {parent_name}",
                detail=f"Parent exe: {parent_exe}  |  PIDs: {ppid} → {proc.info['pid']}",
                severity="high", matched=f"parent={parent_name}",
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return _result("Process Tree (Roblox)",
                   "Verifica quem spawnou o Roblox (injection chain?)",
                   items)


ALL_LIVE_ANALYSIS_SCANNERS = [
    scan_roblox_dll_injection,
    scan_process_tree,
]
