"""
Análise AO VIVO do processo Roblox:
  - Lista TODAS as DLLs carregadas (memory_maps)
  - Flagga DLLs em paths suspeitos (Temp/Downloads/Desktop/AppData)
  - Verifica assinatura digital via WinVerifyTrust
  - Match contra database de keywords

Cheat injetado fica EXPOSTO mesmo se o arquivo foi apagado depois,
porque a DLL ainda tá no espaço de endereço do Roblox.
"""

from models import _result, _item, _fmt_ts
import os
import ctypes
from ctypes import wintypes
from datetime import datetime
import functools

import debug
from database import (
    ROBLOX_PROCESS_NAMES,
    TRUSTED_DLL_PATHS,
    SUSPICIOUS_DLL_PATHS,
)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ============================ Win32/NT Memory & Debugger setup ============================

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

EXECUTE_PROTECTIONS = (
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY
)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

try:
    kernel32 = ctypes.windll.kernel32
    
    # OpenProcess
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    
    # CloseHandle
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    # VirtualQueryEx
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t

    # ReadProcessMemory
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t)
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL

    # CheckRemoteDebuggerPresent
    kernel32.CheckRemoteDebuggerPresent.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel32.CheckRemoteDebuggerPresent.restype = wintypes.BOOL
except (AttributeError, OSError):
    pass

try:
    ntdll = ctypes.windll.ntdll
    ntdll.NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,  # ProcessInformationClass
        ctypes.c_void_p,  # ProcessInformation
        wintypes.ULONG,  # ProcessInformationLength
        ctypes.POINTER(wintypes.ULONG)  # ReturnLength
    ]
    ntdll.NtQueryInformationProcess.restype = ctypes.c_long  # NTSTATUS
except (AttributeError, OSError):
    pass


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


@functools.lru_cache(maxsize=1024)
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

def _match_keyword(text: str):
    # Delega pro matching central (word-boundary, anti-FP).
    import matching
    return matching.match_keyword(text)


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
    roblox_names_lower = {n.lower() for n in ROBLOX_PROCESS_NAMES}

    # Acha processos do Roblox
    for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            name = (proc.info.get("name") or "")
            if name in ROBLOX_PROCESS_NAMES or name.lower() in roblox_names_lower:
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
    roblox_names_lower = {n.lower() for n in ROBLOX_PROCESS_NAMES}

    for proc in psutil.process_iter(["pid", "name", "ppid"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name not in roblox_names_lower:
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


# ============================ Overlay / ESP externo ============================

# Processos que legitimamente desenham overlay click-through (NÃO são cheat).
OVERLAY_WHITELIST = {
    # Comunicação
    "discord.exe", "discordcanary.exe", "discordptb.exe", "discorddevelopment.exe",
    # NVIDIA / AMD / Intel
    "nvcontainer.exe", "nvidia share.exe", "nvidia web helper.exe",
    "nvidiaoverlay.exe", "amddvr.exe", "radeonsoftware.exe",
    # Captura / streaming
    "obs64.exe", "obs32.exe", "obs.exe", "streamlabs obs.exe",
    "xsplit.core.exe", "action.exe",
    # Steam / launchers
    "steam.exe", "gameoverlayui.exe", "steamwebhelper.exe",
    "epicgameslauncher.exe", "galaxyclient.exe",
    # Monitoramento / RGB
    "rtss.exe", "msiafterburner.exe", "rivatunerstatisticsserver.exe",
    "nahimicsvc.exe", "nahimic3.exe", "lghub.exe", "lghub_agent.exe",
    "razer synapse.exe", "icue.exe", "wallpaper32.exe", "wallpaper64.exe",
    # Windows / shell (overlays nativos: Game Bar, IME, notificações, snip)
    "explorer.exe", "textinputhost.exe", "applicationframehost.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "searchhost.exe", "searchapp.exe", "gamebar.exe", "gamebarft.exe",
    "xboxgamebar.exe", "snippingtool.exe", "screenclippinghost.exe",
    "lockapp.exe", "peopleexperiencehost.exe", "systemsettings.exe",
    # Acessibilidade / utilidades comuns
    "magnify.exe", "narrator.exe", "powertoys.exe", "powertoys.awake.exe",
    "flow.launcher.exe", "translucenttb.exe", "f.lux.exe", "flux.exe",
    "1password.exe", "bitwarden.exe", "everything.exe",
}

# Extended window styles (Win32)
GWL_EXSTYLE        = -20
WS_EX_LAYERED      = 0x00080000
WS_EX_TRANSPARENT  = 0x00000020
WS_EX_TOPMOST      = 0x00000008


def scan_overlay_windows() -> dict:
    """
    Detecta janelas de OVERLAY click-through: LAYERED + TRANSPARENT + TOPMOST.
    Essa combinação = janela invisível ao clique desenhada por cima de tudo —
    assinatura clássica de ESP/radar/aimbot visual externo (que não injeta DLL).

    Whitelist generosa cobre overlays legítimos (Discord, NVIDIA, Steam, OBS,
    RTSS, Game Bar, etc.). O resto vira MEDIUM (pode haver overlay legítimo
    desconhecido — não é prova, é pista pra revisar).
    """
    if not HAS_PSUTIL:
        return _result("Overlay / ESP externo", "Janelas overlay click-through", [],
                       error="psutil não instalado")

    try:
        user32 = ctypes.windll.user32
    except (AttributeError, OSError):
        return _result("Overlay / ESP externo", "Janelas overlay click-through", [],
                       error="user32 indisponível (não é Windows?)")

    items = []
    seen_pids = set()

    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, ctypes.c_void_p)

    def callback(hwnd, _lparam):
        try:
            if not user32.IsWindowVisible(hwnd):
                return True
            ex = user32.GetWindowLongW(hwnd, GWL_EXSTYLE) & 0xFFFFFFFF
            # Assinatura de overlay de cheat: invisível ao clique + por cima
            if not (ex & WS_EX_LAYERED and ex & WS_EX_TRANSPARENT and ex & WS_EX_TOPMOST):
                return True

            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pid_val = pid.value
            if pid_val in seen_pids:
                return True

            seen_pids.add(pid_val)

            try:
                pname = psutil.Process(pid_val).name().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "?"

            if pname in OVERLAY_WHITELIST:
                return True

            # Título da janela (contexto)
            length = user32.GetWindowTextLengthW(hwnd)
            title = ""
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                title = buf.value or ""

            items.append(_item(
                label=f"Overlay click-through: {pname}",
                detail=f"PID {pid_val} · janela invisível ao clique sobreposta "
                       f"(LAYERED+TRANSPARENT+TOPMOST)"
                       + (f" · título: '{title}'" if title else " · sem título"),
                severity="medium", matched=f"overlay:{pname}",
            ))
        except Exception as e:
            debug.dbg(f"overlay scan falhou em {pname}", e)
        return True

    try:
        user32.EnumWindows(EnumWindowsProc(callback), 0)
    except Exception as e:
        return _result("Overlay / ESP externo", "Janelas overlay click-through", [],
                       error=str(e))

    return _result("Overlay / ESP externo",
                   "Janelas overlay invisíveis ao clique sobre a tela (ESP/radar externo)",
                   items)


# ============================ Detecção estrutural (comportamental) ============================

# Locais onde o usuário pode escrever sem admin — onde executores se instalam.
_EXECUTOR_STRUCT_ROOTS = [
    r"%LOCALAPPDATA%",
    r"%APPDATA%",
    r"%LOCALAPPDATA%\Programs",
    r"%USERPROFILE%\Downloads",
]

# Pastas-marcador de runtime embutido que executores modernos (Solara, Wave,
# Velocity, etc.) carregam junto pra renderizar a UI. Apps legítimos com
# WebView2 deixam só DADOS no AppData e o .exe ASSINADO em Program Files —
# executores largam o .exe (não-assinado) NA MESMA pasta do runtime.
_EMBEDDED_RUNTIME_MARKERS = ("EBWebView", "msedgewebview2.exe", "cef", "libcef.dll")

# Pastas do próprio Windows/Microsoft que nunca devem ser flagadas mesmo se
# casarem o padrão (defesa extra contra FP).
_STRUCT_WHITELIST_SUBSTR = (
    "\\microsoft\\", "\\windows\\", "\\packages\\microsoft",
    "\\google\\", "\\discord", "\\microsoftedge",
)


def _has_embedded_runtime(folder: str, subdirs: list, files: list) -> bool:
    """A pasta tem um runtime web embutido (marca de UI de executor)?"""
    lower_subs = {d.lower() for d in subdirs}
    lower_files = {f.lower() for f in files}
    for m in _EMBEDDED_RUNTIME_MARKERS:
        ml = m.lower()
        if ml in lower_subs or ml in lower_files:
            return True
    # EBWebView um nível abaixo (padrão comum: <exe> + <sub>/EBWebView)
    for sub in subdirs:
        try:
            if os.path.isdir(os.path.join(folder, sub, "EBWebView")):
                return True
        except OSError:
            pass
    return False


def scan_executor_structure() -> dict:
    """
    Detecção COMPORTAMENTAL de executor — pega mesmo renomeado.

    Em vez de bater no NOME ('solara.exe'), bate na ESTRUTURA: um .exe
    NÃO-ASSINADO na mesma pasta de um runtime web embutido (EBWebView/CEF),
    em local gravável pelo usuário. Esse é o fingerprint de Solara/Wave/
    Velocity/etc — e sobrevive a renomear o arquivo E a pasta.

    Conservador de propósito (anti-FP):
      - Exige runtime embutido + exe não-assinado JUNTOS (apps legítimos
        com WebView2 deixam o exe assinado em Program Files).
      - Severidade MEDIUM — sozinho vira no máximo SUSPECT no Confidence
        Engine; só CONFIRMA se corroborado por outra fonte.
      - Whitelist de pastas Microsoft/Windows/Google/Discord.
      - Validado: 0 hits em PC limpo com Roblox + dezenas de apps WebView2.
    """
    items = []
    seen = set()
    checked = 0
    MAX_CHECK = 400  # teto de exes verificados (perf)

    for raw_root in _EXECUTOR_STRUCT_ROOTS:
        root = os.path.expandvars(raw_root)
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            if depth > 3:
                dirnames[:] = []
                continue
            if dirpath in seen:
                continue
            seen.add(dirpath)

            low_dir = dirpath.lower()
            if any(w in low_dir for w in _STRUCT_WHITELIST_SUBSTR):
                continue

            exes = [f for f in filenames if f.lower().endswith(".exe")]
            if not exes:
                continue
            if not _has_embedded_runtime(dirpath, dirnames, filenames):
                continue

            for exe in exes:
                if checked >= MAX_CHECK:
                    break
                exe_path = os.path.join(dirpath, exe)
                checked += 1
                signed = _is_dll_signed(exe_path)  # WinVerifyTrust serve p/ exe
                # Só flaga quando é COMPROVADAMENTE não-assinado (False).
                # None = não deu pra determinar (WinVerifyTrust indisponível,
                # erro, arquivo travado) → benefício da dúvida, NÃO flaga.
                # Isso evita tempestade de FP se a verificação de assinatura
                # falhar sistemicamente. Não perde detecção real: executor de
                # verdade é um PE válido não-assinado, que retorna False.
                if signed is not False:
                    continue

                # comprovadamente não-assinado + runtime embutido = sinal
                try:
                    mtime = _fmt_ts(os.path.getmtime(exe_path))
                except OSError:
                    mtime = ""
                folder_name = os.path.basename(dirpath)
                items.append(_item(
                    label=f"Estrutura de executor: {exe}",
                    detail=f"{exe_path}\nExe NÃO-ASSINADO na mesma pasta de um runtime "
                           f"web embutido (EBWebView/CEF) — fingerprint de executor "
                           f"Roblox moderno (Solara/Wave/Velocity/etc). Pega mesmo "
                           f"se o arquivo foi renomeado.",
                    severity="medium",
                    matched=f"executor-struct:{folder_name.lower()}",
                    timestamp=mtime,
                ))
            if checked >= MAX_CHECK:
                break

    return _result(
        "Estrutura de executor (comportamental)",
        "Exe não-assinado + runtime web embutido em pasta de usuário — pega executor renomeado",
        items,
    )


# ============================ Integridade do launcher do Roblox ============================

# Binários oficiais do Roblox — SEMPRE assinados pela Roblox Corporation.
# Um destes com assinatura QUEBRADA = adulterado (patcheado pra injetar).
_ROBLOX_OFFICIAL_BINARIES = {
    "robloxplayerbeta.exe",
    "robloxplayerlauncher.exe",
    "robloxplayerinstaller.exe",
    "robloxstudiobeta.exe",
    "robloxstudiolauncherbeta.exe",
    "robloxstudioinstaller.exe",
}

# Nomes que um dropper usaria pra se passar por launcher do Roblox.
_ROBLOX_MASQUERADE_NAMES = _ROBLOX_OFFICIAL_BINARIES | {
    "roblox.exe", "robloxplayer.exe", "robloxlauncher.exe",
    "roblox launcher.exe", "roblox player.exe",
}

# Raiz oficial de instalação. Tudo com nome de launcher FORA daqui é suspeito.
def _roblox_official_root() -> str:
    return os.path.expandvars(r"%LOCALAPPDATA%\Roblox").lower().replace("/", "\\")

# Pastas graváveis pelo usuário onde um launcher falso/dropper costuma cair.
_LAUNCHER_WRONG_LOCATIONS = [
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Documents",
    r"%TEMP%",
    r"%APPDATA%",
    r"%LOCALAPPDATA%\Temp",
]


def scan_roblox_launcher_integrity() -> dict:
    """
    Detecta LAUNCHER DO ROBLOX MODIFICADO — o que a comunidade pediu.

    Dois cenários:
      1. Binário oficial do Roblox (RobloxPlayerBeta.exe etc) no path de
         instalação, mas com ASSINATURA QUEBRADA → foi patcheado pra
         injetar na inicialização. Sinal forte (HIGH): o Roblox SEMPRE
         assina seus binários.
      2. Arquivo com nome de launcher do Roblox numa pasta de usuário
         (Downloads/Desktop/Temp) e NÃO-ASSINADO → dropper se passando
         por launcher oficial. (Assinado em pasta de usuário = instalador
         real baixado, não flaga.)

    Anti-FP (validado: 9 binários oficiais nesta máquina, todos assinados):
      - Só flaga assinatura COMPROVADAMENTE quebrada (False), nunca
        indeterminada (None).
      - Bloxstrap/Fishstrap (alternativas legítimas) usam o RobloxPlayerBeta
        oficial assinado — não caem aqui.
      - Instalador oficial assinado em Downloads é ignorado.
    """
    items = []
    seen = set()

    # --- Cenário 1: binário oficial adulterado (assinatura quebrada) ---
    roblox_root = _roblox_official_root()
    if os.path.isdir(roblox_root):
        for dirpath, dirnames, filenames in os.walk(roblox_root):
            if dirpath[len(roblox_root):].count(os.sep) > 5:
                dirnames[:] = []
                continue
            for f in filenames:
                if f.lower() not in _ROBLOX_OFFICIAL_BINARIES:
                    continue
                p = os.path.join(dirpath, f)
                if p.lower() in seen:
                    continue
                seen.add(p.lower())
                signed = _is_dll_signed(p)
                if signed is False:  # comprovadamente quebrada/ausente
                    try:
                        mtime = _fmt_ts(os.path.getmtime(p))
                    except OSError:
                        mtime = ""
                    items.append(_item(
                        label=f"Launcher do Roblox ADULTERADO: {f}",
                        detail=f"{p}\nBinário oficial do Roblox com assinatura digital "
                               f"QUEBRADA/INVÁLIDA. O Roblox sempre assina seus binários — "
                               f"assinatura quebrada = arquivo modificado (patcheado pra "
                               f"injetar na inicialização). Sinal forte de bypass.",
                        severity="high",
                        matched=f"launcher-tampered:{f.lower()}",
                        timestamp=mtime,
                    ))

    # --- Cenário 2: dropper se passando por launcher em pasta de usuário ---
    for raw_loc in _LAUNCHER_WRONG_LOCATIONS:
        loc = os.path.expandvars(raw_loc)
        if not os.path.isdir(loc):
            continue
        try:
            entries = os.listdir(loc)
        except OSError:
            continue
        for name in entries:
            if name.lower() not in _ROBLOX_MASQUERADE_NAMES:
                continue
            p = os.path.join(loc, name)
            if not os.path.isfile(p) or p.lower() in seen:
                continue
            seen.add(p.lower())
            # Já está fora do path oficial. Assinado = instalador real baixado
            # (ignora). Não-assinado/quebrado = dropper disfarçado.
            signed = _is_dll_signed(p)
            if signed is False:
                try:
                    mtime = _fmt_ts(os.path.getmtime(p))
                except OSError:
                    mtime = ""
                items.append(_item(
                    label=f"Launcher do Roblox FALSO: {name}",
                    detail=f"{p}\nArquivo com nome de launcher do Roblox numa pasta de "
                           f"usuário, NÃO-ASSINADO. O launcher oficial fica em "
                           f"%LOCALAPPDATA%\\Roblox\\Versions e é assinado. Um não-assinado "
                           f"aqui é um dropper/executor se passando por Roblox.",
                    severity="high",
                    matched=f"launcher-fake:{name.lower()}",
                    timestamp=mtime,
                ))

    return _result(
        "Integridade do launcher do Roblox",
        "Launcher/player oficial adulterado (assinatura quebrada) ou dropper disfarçado de Roblox",
        items,
    )


# ============================ Processo suspenso (anti-bypass) ============================

# Apps que o Windows (ou o próprio app) legitimamente deixam em estado suspenso:
# UWP/Store em background, processos-filho de navegador, etc. Suspender esses é
# rotina do SO — não é sinal. Whitelist generosa pra não virar tempestade de FP.
_SUSPEND_WHITELIST = {
    # Navegadores (suspendem abas/processos-filho)
    "chrome.exe", "msedge.exe", "msedgewebview2.exe", "firefox.exe",
    "brave.exe", "opera.exe", "opera_gx.exe", "iexplore.exe", "vivaldi.exe",
    # Comunicação
    "discord.exe", "discordcanary.exe", "discordptb.exe",
    "slack.exe", "teams.exe", "msteams.exe", "whatsapp.exe", "telegram.exe",
    # Plataformas / launchers
    "steam.exe", "steamwebhelper.exe", "epicgameslauncher.exe",
    # Shell / UWP comuns (o Windows suspende em background)
    "explorer.exe", "searchhost.exe", "searchapp.exe", "searchindexer.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "textinputhost.exe", "applicationframehost.exe", "systemsettings.exe",
    "widgets.exe", "widgetservice.exe", "phoneexperiencehost.exe",
    "yourphone.exe", "gamebar.exe", "xboxgamebar.exe", "gamebarftserver.exe",
    "lockapp.exe", "peopleexperiencehost.exe", "runtimebroker.exe",
}

# Processos suspensos vivendo em pasta de app empacotado (UWP/Store) ou system
# app são esperados — o Windows suspende esses em background. Não flaga.
_SUSPEND_SKIP_PATH_SUBSTR = (
    "\\windowsapps\\", "\\appdata\\local\\packages\\",
    "\\systemapps\\", "\\windows\\systemapps\\",
)

# Debuggers / IDEs: quando depuram um programa, o processo-FILHO fica em estado
# SUSPENSO no breakpoint. Um dev pausando o próprio .exe não-assinado (recém
# compilado em pasta de usuário) cairia no MEDIUM — FP. Se o PAI do suspenso é
# um destes, é sessão de debug, não cheat pausado. (Só afeta o MEDIUM; executor
# conhecido suspenso continua HIGH independentemente do pai.)
_DEBUGGER_PARENT_NAMES = {
    "devenv.exe", "vsdbg.exe", "vshost.exe", "msvsmon.exe",
    "windbg.exe", "windbgx.exe", "cdb.exe", "x64dbg.exe", "x32dbg.exe",
    "ollydbg.exe", "dnspy.exe", "dnspy-x86.exe", "ida.exe", "ida64.exe",
    "pycharm64.exe", "pycharm.exe", "idea64.exe", "idea.exe",
    "clion64.exe", "rider64.exe", "webstorm64.exe", "goland64.exe",
    "code.exe", "cursor.exe", "gdb.exe", "lldb.exe", "node.exe",
    "_pydevd_bundle", "debugpy",
}


def _parent_is_debugger(proc) -> bool:
    """True se o processo-pai do suspenso é um debugger/IDE conhecido.
    Defensivo: qualquer erro de acesso → False (não suprime na dúvida)."""
    try:
        parent = proc.parent()
        if parent is None:
            return False
        pname = (parent.name() or "").lower()
        return pname in _DEBUGGER_PARENT_NAMES
    except Exception:
        return False


def scan_suspended_processes() -> dict:
    """
    Detecta processos em estado SUSPENSO (pausado) — método de anti-bypass.

    Pausar o cheat durante a SS (Process Hacker → Suspend) faz ele parar de
    aparecer como "rodando" e congela a atividade, mas o processo continua
    carregado na memória. É um dos truques "anti-bypass" ensinados nos cursos
    de telagem — e some quando o cara "reativa" o processo depois.

    Conservador de propósito (anti-FP): o Windows suspende MUITO processo
    legítimo (UWP em background, abas de navegador). Por isso só flaga quando,
    ALÉM de suspenso, o processo é:
      - de um executor conhecido (nome/exe casa keyword) -> HIGH; ou
      - NÃO-ASSINADO rodando de pasta de usuário (Temp/Downloads/AppData) -> MEDIUM.

    Whitelist cobre navegadores/Discord/shell e apps empacotados
    (WindowsApps/Packages). Binário suspenso em system/Program Files é ignorado.
    Sozinho, vira no máximo SUSPECT no Confidence Engine (medium) — só pesa de
    verdade somado a outra fonte do mesmo alvo.
    """
    if not HAS_PSUTIL:
        return _result("Processos suspensos (anti-bypass)",
                       "Processos pausados/suspensos durante a SS",
                       [], error="psutil não instalado")

    items = []
    for proc in psutil.process_iter(["pid", "name", "exe", "status", "create_time"]):
        try:
            if proc.info.get("status") != psutil.STATUS_STOPPED:
                continue

            name = proc.info.get("name") or ""
            exe = proc.info.get("exe") or ""
            low_name = name.lower()
            low_exe = exe.lower().replace("/", "\\")

            # Suspensos legítimos: whitelist de app + paths de UWP/system app
            if low_name in _SUSPEND_WHITELIST:
                continue
            if any(s in low_exe for s in _SUSPEND_SKIP_PATH_SUBSTR):
                continue

            category, _ = _classify_dll_path(exe)
            # Suspenso em system/Program Files = raro mas benigno, ignora
            if category == "trusted" or low_exe.startswith(
                    ("c:\\windows", "c:\\program files")):
                continue

            ts = _fmt_ts(proc.info.get("create_time") or 0)
            pid = proc.info.get("pid")

            # Sinal 1: executor conhecido em estado suspenso -> forte
            kw, _ = _match_keyword(name)
            if not kw and exe:
                kw, _ = _match_keyword(exe)
            if kw:
                items.append(_item(
                    label=f"Processo SUSPENSO: {name}",
                    detail=f"PID {pid} · {exe or '(exe desconhecido)'}\n"
                           f"Processo de executor conhecido em estado SUSPENSO (pausado). "
                           f"Pausar o cheat durante a SS pra ele parecer inativo é truque de "
                           f"anti-bypass — reative o processo pra inspecionar.",
                    severity="high", matched=kw, timestamp=ts,
                ))
                continue

            # Sinal 2: suspenso + não-assinado em pasta de usuário -> médio
            if exe and category in ("suspicious-path", "non-standard"):
                # FP de dev: processo pausado por debugger/IDE no breakpoint.
                if _parent_is_debugger(proc):
                    continue
                if _is_dll_signed(exe) is False:
                    items.append(_item(
                        label=f"Processo SUSPENSO não-assinado: {name}",
                        detail=f"PID {pid} · {exe}\n"
                               f"Processo NÃO-ASSINADO rodando de pasta de usuário e em estado "
                               f"SUSPENSO. Pode ser cheat pausado pra escapar da SS.",
                        severity="medium",
                        matched="processo-suspenso-nao-assinado", timestamp=ts,
                    ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    return _result(
        "Processos suspensos (anti-bypass)",
        "Processos pausados/suspensos — cheat pausado durante a SS pra parecer inativo",
        items,
    )


# ============================ Processo disfarçado de sistema (masquerading) ============================

# Nomes de processo do PRÓPRIO Windows que SÓ rodam de pasta do sistema. Renomear
# o cheat pra um destes e rodar de pasta de usuário é "process masquerading" —
# no Gerenciador de Tarefas/SS manual o cara vê "svchost.exe" e passa batido.
# FP ~zero: esses binários nunca rodam fora de System32/SysWOW64/WinSxS (e o
# explorer, de %WINDIR%). Os reais costumam ser protegidos (PPL) e nem expõem o
# path — esses a gente pula; o disfarçado em pasta de usuário expõe e é pego.
def _system_dirs():
    win = os.environ.get("SystemRoot", r"C:\Windows").lower().replace("/", "\\").rstrip("\\")
    sys32 = (f"{win}\\system32\\", f"{win}\\syswow64\\", f"{win}\\winsxs\\")
    return win, sys32


_WINDIR, _SYS32_DIRS = _system_dirs()

# nome -> tupla de prefixos de path LEGÍTIMOS (lowercase, com barra final).
_SYSTEM_PROCESS_DIRS = {
    name: _SYS32_DIRS for name in (
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "conhost.exe",
        "dllhost.exe", "runtimebroker.exe", "sihost.exe", "taskhostw.exe",
        "ctfmon.exe", "spoolsv.exe", "searchindexer.exe", "searchprotocolhost.exe",
        "searchfilterhost.exe", "fontdrvhost.exe", "audiodg.exe", "wudfhost.exe",
        "smartscreen.exe", "wmiprvse.exe", "dashost.exe", "lsm.exe",
        "securityhealthservice.exe", "securityhealthsystray.exe",
    )
}
# explorer.exe roda direto de %WINDIR%\explorer.exe — match do ARQUIVO exato, não
# do diretório: `c:\windows\` como prefixo deixaria passar um explorer.exe plantado
# em c:\windows\temp\ (subdir de %WINDIR%). O legítimo é só esse caminho.
_SYSTEM_PROCESS_DIRS["explorer.exe"] = (f"{_WINDIR}\\explorer.exe",)


def scan_process_masquerade() -> dict:
    """
    Detecta cheat renomeado pra nome de processo do Windows rodando de fora da
    pasta do sistema (process masquerading) — anti-SS.

    Para cada processo cujo NOME é de um processo conhecido do SO, confere se o
    EXE roda de uma pasta legítima (System32/SysWOW64/WinSxS, ou %WINDIR% pro
    explorer). Se roda de qualquer outro lugar (Downloads/Temp/AppData/Desktop…),
    é disfarce → HIGH.

    Conservador (anti-FP): se o path do exe não dá pra ler (processo protegido
    PPL — justamente os reais), pula. Só flaga quem expõe um path ilegítimo.
    """
    if not HAS_PSUTIL:
        return _result("Processo disfarçado de sistema (masquerading)",
                       "Cheat renomeado pra nome de processo do Windows",
                       [], error="psutil não instalado")

    items = []
    for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            name = (proc.info.get("name") or "").lower()
            allowed = _SYSTEM_PROCESS_DIRS.get(name)
            if not allowed:
                continue
            exe = proc.info.get("exe") or ""
            if not exe:
                # processo protegido (o real) não expõe path — não é o disfarce
                continue
            low_exe = exe.lower().replace("/", "\\")
            if any(low_exe.startswith(p) for p in allowed):
                continue  # roda do lugar certo = legítimo

            pid = proc.info.get("pid")
            ts = _fmt_ts(proc.info.get("create_time") or 0)
            legit = " ou ".join(p.rstrip("\\") for p in allowed)
            items.append(_item(
                label=f"Processo DISFARÇADO de sistema: {name}",
                detail=f"PID {pid} · {exe}\n"
                       f"Um processo chamado '{name}' está rodando de '{exe}', mas o "
                       f"'{name}' legítimo do Windows só roda de {legit}. Renomear o cheat "
                       f"pra nome de processo do sistema e rodar de pasta de usuário é "
                       f"disfarce (masquerading) — no Gerenciador de Tarefas passa por "
                       f"processo do Windows. Inspecione o binário.",
                severity="high", matched=f"masquerade:{name}", timestamp=ts,
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    return _result(
        "Processo disfarçado de sistema (masquerading)",
        "Cheat renomeado pra nome de processo do Windows rodando de fora da pasta do sistema",
        items,
    )


# ============================ DLL sideloading no Roblox (anti-bypass) ============================

# DLLs FORNECIDAS pelo Windows que o RobloxPlayerBeta importa por NOME. A ordem
# de busca de DLL do Windows carrega a do diretório do .exe ANTES da System32 —
# então plantar uma destas ao lado do RobloxPlayerBeta faz o Windows carregar a
# maliciosa quando o Roblox abre. A DLL proxy reexporta as funções reais (pra
# não quebrar o Roblox) E injeta o cheat. NÃO precisa patchear o Roblox, então
# o launcher integrity (que checa a assinatura do .exe) não pega.
#
# Roblox legítimo NUNCA traz nenhuma destas na pasta de versão — vêm da System32.
# Uma destas ao lado do RobloxPlayerBeta, com assinatura QUEBRADA, é proxy DLL.
_SIDELOAD_DLL_NAMES = {
    # Proxy clássicos (apps de jogo importam, fáceis de reexportar)
    "version.dll", "dinput8.dll", "dinput.dll", "winmm.dll", "dwmapi.dll",
    "winhttp.dll", "wininet.dll", "uxtheme.dll", "dbghelp.dll", "msimg32.dll",
    "profapi.dll", "cryptbase.dll", "secur32.dll", "userenv.dll",
    "iphlpapi.dll", "netapi32.dll", "wtsapi32.dll", "apphelp.dll",
    "windowscodecs.dll", "textinputframework.dll", "propsys.dll",
    # Runtimes gráficos (Roblox usa; gate de assinatura evita FP em DLL legítima)
    "d3d9.dll", "d3d10.dll", "d3d11.dll", "d3d12.dll", "dxgi.dll",
    "d3dcompiler_47.dll", "dwrite.dll", "opengl32.dll", "vulkan-1.dll",
}


def scan_roblox_dll_sideload() -> dict:
    """
    Detecta DLL SIDELOADING/PROXY ao lado do RobloxPlayerBeta — anti-bypass.

    Procura DLLs com nome de DLL do SISTEMA (version.dll, dinput8.dll, d3d9.dll…)
    dentro da pasta de instalação do Roblox. O Roblox legítimo não traz nenhuma
    delas — vêm da System32. Uma ali com ASSINATURA QUEBRADA (não-assinada) é
    uma proxy DLL plantada pra injetar quando o Roblox carrega.

    Anti-FP (mesma doutrina do launcher integrity):
      - Só flaga assinatura COMPROVADAMENTE quebrada (False), nunca None.
      - DLL gráfica legítima eventualmente embarcada é assinada → não cai.
      - Fora da pasta do Roblox não é escopo deste scanner.
    """
    items = []
    seen = set()
    roblox_root = _roblox_official_root()
    if not os.path.isdir(roblox_root):
        return _result(
            "DLL sideloading no Roblox (anti-bypass)",
            "DLL proxy de sistema plantada ao lado do RobloxPlayerBeta pra injetar",
            [], error="Roblox não instalado em %LOCALAPPDATA%\\Roblox")

    for dirpath, dirnames, filenames in os.walk(roblox_root):
        if dirpath[len(roblox_root):].count(os.sep) > 5:
            dirnames[:] = []
            continue
        for f in filenames:
            if f.lower() not in _SIDELOAD_DLL_NAMES:
                continue
            p = os.path.join(dirpath, f)
            if p.lower() in seen:
                continue
            seen.add(p.lower())
            if _is_dll_signed(p) is False:  # comprovadamente não-assinada = proxy
                try:
                    mtime = _fmt_ts(os.path.getmtime(p))
                except OSError:
                    mtime = ""
                items.append(_item(
                    label=f"DLL sideloading no Roblox: {f}",
                    detail=f"{p}\nDLL com nome de DLL do SISTEMA ({f}) dentro da pasta "
                           f"de instalação do Roblox, NÃO-ASSINADA. O Roblox não traz "
                           f"essa DLL — ela vem da System32. Plantada aqui, o Windows a "
                           f"carrega ANTES da System32 quando o Roblox abre (DLL search "
                           f"order), injetando o cheat sem patchear o Roblox. Proxy DLL.",
                    severity="high",
                    matched=f"sideload:{f.lower()}",
                    timestamp=mtime,
                ))

    return _result(
        "DLL sideloading no Roblox (anti-bypass)",
        "DLL proxy de sistema plantada ao lado do RobloxPlayerBeta pra injetar na inicialização",
        items,
    )


def scan_roblox_debuggers() -> dict:
    """
    Detecta se um debugger (Cheat Engine, x64dbg, etc.) está ativamente atrelado
    a algum processo do Roblox usando CheckRemoteDebuggerPresent e NtQueryInformationProcess (ProcessDebugPort).
    """
    if not HAS_PSUTIL:
        return _result("Detecção de Debugger (Roblox)", "Verificação de debuggers atrelados ao Roblox", [],
                       error="psutil não instalado")

    items = []
    roblox_names_lower = {n.lower() for n in ROBLOX_PROCESS_NAMES}
    target_pids = []

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info.get("name") or ""
            if name in ROBLOX_PROCESS_NAMES or name.lower() in roblox_names_lower:
                target_pids.append((proc.info["pid"], name))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not target_pids:
        return _result("Detecção de Debugger (Roblox)", "Debugger ativo atrelado ao Roblox", [])

    for pid, name in target_pids:
        handle = None
        try:
            # PROCESS_QUERY_INFORMATION = 0x0400
            handle = kernel32.OpenProcess(0x0400, False, pid)
            if not handle:
                continue

            # 1. CheckRemoteDebuggerPresent
            is_dbg = wintypes.BOOL(False)
            if kernel32.CheckRemoteDebuggerPresent(handle, ctypes.pointer(is_dbg)):
                if is_dbg.value:
                    items.append(_item(
                        label=f"Debugger detectado no Roblox (PID {pid})",
                        detail=f"CheckRemoteDebuggerPresent indicou a presença de um debugger ativo no processo '{name}'.",
                        severity="high",
                        matched="roblox-debugger-present"
                    ))
                    continue

            # 2. NtQueryInformationProcess (ProcessDebugPort = 7)
            # ProcessDebugPort devolve um DWORD_PTR (pointer-sized: 8 bytes no
            # x64). Usar wintypes.DWORD (4 bytes) fazia o kernel devolver
            # STATUS_INFO_LENGTH_MISMATCH → status != 0 → o método NUNCA disparava
            # no x64 (todo Windows/Roblox moderno). c_size_t = pointer-sized.
            dbg_port = ctypes.c_size_t(0)
            ret_len = wintypes.ULONG(0)
            status = ntdll.NtQueryInformationProcess(
                handle,
                7,  # ProcessDebugPort
                ctypes.pointer(dbg_port),
                ctypes.sizeof(dbg_port),
                ctypes.pointer(ret_len)
            )
            if status == 0 and dbg_port.value != 0:
                items.append(_item(
                    label=f"Porta de Debug detectada no Roblox (PID {pid})",
                    detail=f"NtQueryInformationProcess (ProcessDebugPort) retornou porta 0x{dbg_port.value:X}.",
                    severity="high",
                    matched="roblox-debug-port"
                ))

        except Exception as e:
            debug.dbg(f"Falha ao checar debugger no PID {pid}", e)
        finally:
            if handle:
                kernel32.CloseHandle(handle)

    return _result("Detecção de Debugger (Roblox)",
                   "Verifica se ferramentas de debug estão atreladas ao processo Roblox",
                   items)


def _region_is_pe(handle, base_addr, region_size) -> bool:
    """Valida uma imagem PE COMPLETA no início da região: 'MZ' + e_lfanew
    plausível + assinatura 'PE\\0\\0'. Checar só 'MZ' (2 bytes) dá FP com código
    JIT/bytes coincidentes — a estrutura PE inteira é específica de imagem
    mapeada. Qualquer falha de leitura/validação → False (conservador)."""
    try:
        dos = ctypes.create_string_buffer(0x40)
        br = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(
                handle, ctypes.c_void_p(base_addr), dos, 0x40, ctypes.pointer(br)):
            return False
        if br.value != 0x40 or dos.raw[:2] != b"MZ":
            return False
        e_lfanew = int.from_bytes(dos.raw[0x3C:0x40], "little")
        # e_lfanew tem que caber na região e ser plausível
        if e_lfanew <= 0 or e_lfanew > min(region_size - 4, 0x10000000):
            return False
        sig = ctypes.create_string_buffer(4)
        br2 = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(
                handle, ctypes.c_void_p(base_addr + e_lfanew), sig, 4, ctypes.pointer(br2)):
            return False
        return br2.value == 4 and sig.raw[:4] == b"PE\x00\x00"
    except Exception:
        return False


def scan_roblox_manual_map() -> dict:
    """
    Detecta injeção Manual Map / Reflective DLL: páginas de memória PRIVADAS e
    EXECUTÁVEIS (não mapeadas de arquivo) que contêm uma imagem PE COMPLETA.

    Validação: exige a estrutura PE inteira (MZ + e_lfanew + 'PE\\0\\0'), não só
    'MZ' — corta FP de código JIT/bytes coincidentes. Severidade MEDIUM: o
    próprio anti-cheat do Roblox (Hyperion) aloca/mapeia código, então isto sozinho
    NÃO crava veredito — precisa corroboração de outra fonte. Mappers sofisticados
    apagam o header PE (escapam deste check); é sinal complementar, não definitivo.
    """
    if not HAS_PSUTIL:
        return _result("Injeção Manual Map (Roblox)", "Detecção de DLLs injetadas por Manual Map", [],
                       error="psutil não instalado")

    items = []
    roblox_names_lower = {n.lower() for n in ROBLOX_PROCESS_NAMES}
    target_pids = []

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info.get("name") or ""
            if name in ROBLOX_PROCESS_NAMES or name.lower() in roblox_names_lower:
                target_pids.append((proc.info["pid"], name))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not target_pids:
        return _result("Injeção Manual Map (Roblox)", "Detecção de DLLs injetadas por Manual Map", [])

    for pid, _ in target_pids:
        handle = None
        try:
            # PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010
            handle = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
            if not handle:
                continue

            address = 0
            mbi = MEMORY_BASIC_INFORMATION()
            size_mbi = ctypes.sizeof(MEMORY_BASIC_INFORMATION)
            regions_seen = 0
            MAX_REGIONS = 100000  # guarda de perf — não varre infinito

            while True:
                res = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.pointer(mbi), size_mbi)
                if res == 0:
                    break

                base_addr = mbi.BaseAddress or 0
                region_size = mbi.RegionSize or 0
                if region_size == 0:
                    break  # região de tamanho 0 → evita loop infinito

                regions_seen += 1
                if regions_seen > MAX_REGIONS:
                    break

                # Commit, Private, Executável + imagem PE COMPLETA (não só 'MZ')
                if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                        and mbi.Protect in EXECUTE_PROTECTIONS
                        and _region_is_pe(handle, base_addr, region_size)):
                    items.append(_item(
                        label=f"Possível Manual Map no Roblox (PID {pid})",
                        detail=f"Endereço: 0x{base_addr:X} (Tamanho: {region_size} bytes)\n"
                               f"Região de memória PRIVADA e EXECUTÁVEL contendo uma imagem PE "
                               f"completa (MZ + assinatura PE) não mapeada de arquivo — assinatura "
                               f"de Manual Map / Reflective DLL. MEDIUM: o anti-cheat do próprio "
                               f"Roblox também aloca código; corrobore com outra fonte antes de cravar.",
                        severity="medium",
                        matched="manual-map-dll"
                    ))

                next_addr = base_addr + region_size
                if next_addr <= address:  # não avançou → evita loop infinito
                    break
                address = next_addr

        except Exception as e:
            debug.dbg(f"Falha ao checar manual map no PID {pid}", e)
        finally:
            if handle:
                kernel32.CloseHandle(handle)

    return _result("Injeção Manual Map (Roblox)",
                   "Detecção de DLLs injetadas ocultamente (sem carregar no disco) no Roblox",
                   items)


ALL_LIVE_ANALYSIS_SCANNERS = [
    scan_roblox_dll_injection,
    scan_process_tree,
    scan_overlay_windows,
    scan_executor_structure,
    scan_roblox_launcher_integrity,
    scan_suspended_processes,
    scan_process_masquerade,
    scan_roblox_dll_sideload,
    scan_roblox_debuggers,
    scan_roblox_manual_map,
]
