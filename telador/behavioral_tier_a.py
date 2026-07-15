"""
Tier A — detecções comportamentais que forçam o cheater a mudar
arquitetura, não só renomear binário.

  1) scan_scheduled_task_dropper — task criada nas últimas 24h com
     trigger AtLogon + action rodando exe em user path (C:\\Users\\...).
     Padrão de dropper de loader/cheat. Ortogonal ao scan_scheduled_tasks
     existente (que só faz keyword match).

  2) scan_amsi_bypass — inspeciona amsi.dll do processo powershell.exe.
     Se a primeira instrução de AmsiScanBuffer virou `ret` ou
     `xor eax, eax; ret`, cheater patcheou pra silenciar o Defender
     antes de baixar payload.

  3) scan_apc_injection — busca módulos não-Windows carregados no
     Roblox via APC injection. Diferente de scan_remote_threads_in_roblox
     (thread com StartAddress fora de módulos), APC injection queue
     código pra thread existente — não deixa thread nova.
"""

from __future__ import annotations

from .models import _result, _item
import ctypes
from ctypes import wintypes
import os
import subprocess
from datetime import datetime, timedelta, timezone

from . import debug
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from . import win_tools
    HAS_WIN_TOOLS = True
except ImportError:
    HAS_WIN_TOOLS = False


def _tool(name: str) -> str:
    if HAS_WIN_TOOLS:
        return win_tools.tool(name)
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", name)


# ============================ (1) Scheduled Task Dropper ============================

# Padrão dropper: task criada nas últimas 24h + AtLogon + exe em user path.
# Instaladores legítimos criam tasks tipo Discord/Steam/Chrome updater, mas
# esses ficam em Program Files (system path). User path é onde loader cai.
_DROPPER_RECENT_HOURS = 24
# Paths onde loader/cheat cai: user profile e programdata (não system32).
# %localappdata%/%appdata% ficam sob c:\users\ (schtask expande) — não
# precisamos deles como prefix separado.
_DROPPER_SUSPICIOUS_PREFIXES = (
    "c:\\users\\",
    "c:\\programdata\\",
)

# TaskPaths de apps legítimos que criam tasks em user-path na instalação/
# update (Squirrel/Electron). Match por SUBSTRING no path (case-insensitive).
# Sem essa lista, instalar/atualizar VS Code / Discord / Cursor gera dropper-FP.
_DROPPER_LEGIT_TASK_PATH_MARKERS = (
    "\\discord\\", "\\slack\\", "\\cursor\\", "\\vscode\\",
    "\\microsoft vs code\\", "\\visual studio code\\",
    "\\code -", "\\code_",
    "\\zoom\\", "\\telegram\\", "\\whatsapp\\",
    "\\dropbox\\", "\\onedrive\\",
    "\\notion\\", "\\github desktop\\", "\\githubdesktop\\",
    "\\adobe\\", "\\creative cloud\\", "\\creativecloud\\",
    "\\squirrel\\",
    "\\roblox\\", "\\bloxstrap\\",
    "\\riot\\", "\\valorant\\", "\\league of legends\\",
    "\\battle.net\\", "\\blizzard\\", "\\steam\\",
    "\\epic games\\", "\\epicgames\\", "\\ubisoft\\",
    "\\ea desktop\\", "\\eadesktop\\", "\\origin\\", "\\rockstar\\",
    "\\voicemod\\", "\\overwolf\\",
    "\\microsoft\\", "\\google\\",  # Google Chrome/Drive tasks
)

# Basenames de updaters legítimos (Squirrel). Não flaggam sozinho.
_DROPPER_LEGIT_EXE_BASENAMES = frozenset({
    "update.exe", "squirrel.exe", "squirrelsetup.exe",
    "setup.exe", "installer.exe", "updater.exe",
    "onedrivelauncher.exe", "onedrive.exe",
    "googleupdater.exe", "googleupdate.exe",
})


def scan_scheduled_task_dropper() -> dict:
    """Task recente + AtLogon + exe user-path. Persistência clássica de
    loader/cheat que sobrevive a reboot.

    Fonte: `Get-ScheduledTask` via PowerShell (retorna Date, Triggers,
    Actions). Filtro:
      - Date > agora - 24h
      - Trigger.CimClass.CimClassName inclui 'MSFT_TaskLogonTrigger' ou
        'MSFT_TaskBootTrigger'
      - Action.Execute path começa com C:\\Users\\ ou %LocalAppData%
    """
    name = "Scheduled Task Dropper"
    desc = "Task criada nas últimas 24h com AtLogon + exe em user-path"
    items = []

    ps_cmd = (
        "$out = @(); "
        "foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) { "
        "  try { "
        "    $info = Get-ScheduledTaskInfo -TaskPath $t.TaskPath "
        "      -TaskName $t.TaskName -ErrorAction Stop; "
        "  } catch { continue }; "
        "  foreach ($tr in $t.Triggers) { "
        "    $cls = $tr.PSObject.TypeNames[0]; "
        "    foreach ($a in $t.Actions) { "
        "      $out += [pscustomobject]@{ "
        "        Name=$t.TaskName; Path=$t.TaskPath; "
        "        Date=$t.Date; Trigger=$cls; "
        "        Exec=$a.Execute; Args=$a.Arguments "
        "      } "
        "    } "
        "  } "
        "}; "
        "$out | ConvertTo-Json -Compress -Depth 3"
    )
    try:
        r = subprocess.run(
            [
                _tool("WindowsPowerShell\\v1.0\\powershell.exe"),
                "-NoProfile", "-NonInteractive", "-Command", ps_cmd,
            ],
            capture_output=True, text=True,
            encoding="mbcs", errors="replace",
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return _result(name, desc, items, error=f"powershell: {e}")

    if r.returncode != 0 or not (r.stdout or "").strip():
        msg = (r.stderr or "").strip() or "sem output"
        return _result(name, desc, items, error=f"Get-ScheduledTask: {msg[:120]}")

    import json
    try:
        data = json.loads(r.stdout)
    except (ValueError, TypeError) as e:
        return _result(name, desc, items, error=f"JSON parse: {e}")

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return _result(name, desc, items)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=_DROPPER_RECENT_HOURS)

    for row in data:
        if not isinstance(row, dict):
            continue
        trigger = (row.get("Trigger") or "").lower()
        # Filtro 1: só triggers de logon/boot (persistência)
        if not any(k in trigger for k in ("logontrigger", "boottrigger")):
            continue
        exec_path = (row.get("Exec") or "")
        exec_low = exec_path.lower()
        # Expande %VAR% pra comparação
        exec_expanded = os.path.expandvars(exec_low).replace("/", "\\")
        # Filtro 2: exe em user-path (não em Program Files/System32)
        if not any(exec_expanded.startswith(p) for p in _DROPPER_SUSPICIOUS_PREFIXES):
            continue
        # Filtro 2.5: whitelist de apps legítimos (Squirrel updaters etc.)
        task_path_low = (row.get("Path") or "").lower()
        task_name_low = (row.get("Name") or "").lower()
        combined_path = (task_path_low + task_name_low).replace("/", "\\")
        if any(m in combined_path for m in _DROPPER_LEGIT_TASK_PATH_MARKERS):
            continue
        exe_basename = os.path.basename(exec_expanded)
        if exe_basename in _DROPPER_LEGIT_EXE_BASENAMES:
            continue
        # Filtro 3: date recente (formato ISO PS "\/Date(1720...)\/")
        date_raw = row.get("Date")
        created_at = None
        if isinstance(date_raw, str) and date_raw.startswith("/Date("):
            try:
                ms = int(date_raw[len("/Date("):].split(")")[0].split("+")[0])
                created_at = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
            except (ValueError, IndexError):
                pass
        elif isinstance(date_raw, str):
            # Fallback: parse ISO 8601
            try:
                created_at = datetime.fromisoformat(date_raw.replace("Z", "+00:00"))
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        if created_at is None or created_at < cutoff:
            continue

        task_name = (row.get("Name") or "?")
        task_path = (row.get("Path") or "")
        items.append(_item(
            label=f"Task recente: {task_path}{task_name}",
            detail=(
                f"Trigger: {trigger}\n"
                f"Exec: {exec_path}\n"
                f"Args: {row.get('Args') or ''}\n"
                f"Criada: {created_at.isoformat()}\n"
                "Task de persistência criada nas últimas 24h que roda binário "
                "em user-path no logon/boot. Padrão clássico de dropper de "
                "loader — cheat sobrevive reboot sem depender de startup folder."
            ),
            severity="medium",
            matched="dropper-task",
            timestamp=created_at.strftime("%Y-%m-%d %H:%M:%S"),
        ))

    return _result(name, desc, items)


# ============================ (2) AMSI Bypass ============================

# AmsiScanBuffer prologue esperado em Win10/11 x64 (varia entre builds mas
# começa quase sempre com MOV de save-regs).
_AMSI_PATCH_SIGS = [
    (b"\x31\xc0\xc3",         "xor eax, eax; ret"),           # zeroed retval
    (b"\xc3",                 "ret imediato"),
    (b"\x48\x31\xc0\xc3",     "xor rax, rax; ret (REX)"),
    (b"\xb8\x00\x00\x00\x00\xc3",  "mov eax, 0; ret"),
    (b"\xb8\x57\x00\x07\x80\xc3",  "mov eax, S_FALSE; ret"),   # HRESULT S_FALSE
]

_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ = 0x0010


def _find_powershell_pids() -> list[int]:
    if not HAS_PSUTIL:
        return []
    pids = []
    try:
        for p in psutil.process_iter(["name", "pid"]):
            nm = (p.info.get("name") or "").lower()
            if nm in ("powershell.exe", "pwsh.exe"):
                pids.append(p.info["pid"])
    except Exception as e:
        debug.dbg("amsi: process_iter falhou", e)
    return pids


def scan_amsi_bypass() -> dict:
    """Se AmsiScanBuffer no powershell.exe estiver patcheada com ret imediato,
    xor+ret ou similar, o AV local foi silenciado. Cheater usa isso pra baixar
    payload sem o Defender enxergar.

    Só roda se powershell.exe está aberto (senão não tem processo pra inspecionar).
    Requer admin em maioria dos casos (OpenProcess VM_READ).
    """
    name = "AMSI Bypass"
    desc = "AmsiScanBuffer no powershell.exe patcheada (silencia AV)"
    items = []

    if not HAS_PSUTIL:
        return _result(name, desc, items, error="psutil não instalado")

    pids = _find_powershell_pids()
    if not pids:
        return _result(name, desc, items,
                       error="Nenhum powershell.exe/pwsh.exe rodando")

    k32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi

    OpenProcess = k32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE

    ReadProcessMemory = k32.ReadProcessMemory
    ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    ReadProcessMemory.restype = wintypes.BOOL

    EnumProcessModules = psapi.EnumProcessModules
    EnumProcessModules.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    EnumProcessModules.restype = wintypes.BOOL

    GetModuleFileNameExW = psapi.GetModuleFileNameExW
    GetModuleFileNameExW.argtypes = [
        wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD,
    ]
    GetModuleFileNameExW.restype = wintypes.DWORD

    CloseHandle = k32.CloseHandle

    errors = []
    for pid in pids:
        hProc = OpenProcess(
            _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ, False, pid,
        )
        if not hProc:
            errors.append(f"OpenProcess PID {pid} negado (admin?)")
            continue
        try:
            # Enum modules pra achar amsi.dll base
            hMods = (wintypes.HMODULE * 1024)()
            needed = wintypes.DWORD(0)
            if not EnumProcessModules(hProc, hMods,
                                       ctypes.sizeof(hMods),
                                       ctypes.byref(needed)):
                errors.append(f"PID {pid}: EnumProcessModules falhou")
                continue
            amsi_base = None
            count = needed.value // ctypes.sizeof(wintypes.HMODULE)
            for i in range(min(count, 1024)):
                buf = ctypes.create_unicode_buffer(260)
                GetModuleFileNameExW(hProc, hMods[i], buf, 260)
                if (buf.value or "").lower().endswith("amsi.dll"):
                    amsi_base = int(hMods[i])
                    break
            if amsi_base is None:
                # PowerShell sem amsi.dll = versão antiga ou build sem AMSI.
                # Não é bypass — só nota silente.
                continue

            # Carregar amsi.dll local pra descobrir offset de AmsiScanBuffer.
            # Windows carrega DLLs no mesmo base entre processos por boot
            # (system-wide ASLR), então offset local = offset remoto.
            # Usa GetProcAddress explicitamente em vez de acessar por atributo
            # do CDLL (mais robusto entre versões CPython).
            try:
                GetProcAddress = k32.GetProcAddress
                GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]
                GetProcAddress.restype = ctypes.c_void_p
                amsi_local = ctypes.windll.LoadLibrary("amsi.dll")
                local_base = int(amsi_local._handle)
                asb_local_addr = GetProcAddress(
                    wintypes.HMODULE(local_base), b"AmsiScanBuffer",
                )
                if not asb_local_addr:
                    errors.append(f"PID {pid}: GetProcAddress AmsiScanBuffer=NULL")
                    continue
                asb_offset = asb_local_addr - local_base
            except (OSError, AttributeError) as e:
                errors.append(f"amsi.dll local: {e}")
                continue

            target_addr = amsi_base + asb_offset
            buf = (ctypes.c_ubyte * 16)()
            bytes_read = ctypes.c_size_t(0)
            if not ReadProcessMemory(
                hProc, ctypes.c_void_p(target_addr),
                buf, 16, ctypes.byref(bytes_read),
            ):
                errors.append(f"PID {pid}: RPM AmsiScanBuffer falhou")
                continue
            prologue = bytes(buf[:bytes_read.value])
            for sig, label in _AMSI_PATCH_SIGS:
                if prologue.startswith(sig):
                    items.append(_item(
                        label=f"PID {pid}: AmsiScanBuffer patcheada",
                        detail=(
                            f"PowerShell PID {pid}, amsi.dll base 0x{amsi_base:x}.\n"
                            f"Primeiros bytes de AmsiScanBuffer: "
                            f"{prologue.hex(' ')}\n"
                            f"Padrão detectado: {label}. Isso silencia o "
                            "Defender/AV — a função sempre retorna 'não é malware', "
                            "e o cheater pode baixar payload sem detecção."
                        ),
                        severity="high",
                        matched="amsi-bypass",
                    ))
                    break
        finally:
            try:
                CloseHandle(hProc)
            except Exception:
                pass

    if errors and not items:
        return _result(name, desc, items, error=" | ".join(errors[:3]))
    return _result(name, desc, items)


# ============================ (3) APC Injection ============================

# Módulos legítimos vem de: C:\Windows\, C:\Program Files*, próprio Roblox,
# ou overlays/GPU drivers comuns em gamer PCs (NVIDIA, AMD, Discord, RTSS,
# OBS). Suspeito é DLL fora dessa lista — %TEMP%, Downloads, Desktop.
_LEGIT_MODULE_PREFIXES = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\",
    "c:\\programdata\\nvidia",
    "c:\\programdata\\amd",
    "c:\\programdata\\intel",
    "c:\\programdata\\obs",
    # Overlays legit que costumam carregar no Roblox
    "c:\\programdata\\packages",
    "c:\\programdata\\razer",
)

# Paths REALMENTE suspeitos pra DLL de injeção: user-writable comuns em
# cheat loaders. Só flagga se cair aqui — evita FP com overlays exóticos
# de setup de gamer.
_SUSPICIOUS_DLL_PREFIXES = (
    "c:\\users\\",  # Downloads, Desktop, AppData\Roaming exóticos
    "c:\\windows\\temp\\",
    "c:\\temp\\",
)


def _is_roblox_path(path: str) -> bool:
    p = (path or "").lower().replace("/", "\\")
    if "\\roblox\\" in p or "\\bloxstrap\\" in p:
        return True
    if p.endswith("robloxplayerbeta.exe"):
        return True
    # Discord overlay + jogos comuns em %AppData%\Discord — legit
    if "\\discord\\" in p or "\\overwolf\\" in p:
        return True
    return False


def scan_apc_injection() -> dict:
    """DLLs carregadas no Roblox que não vem de path legítimo.

    APC injection queue APCs numa thread existente do target — não cria
    thread nova (por isso scan_remote_threads_in_roblox não pega). O
    resultado observável user-mode é uma DLL nova mapeada no processo
    Roblox vindo de user-path ou %TEMP%.

    Complementa scan_roblox_dll_injection existente que foca em nomes de
    família conhecidos. Aqui pegamos QUALQUER módulo em path suspeito.
    """
    name = "APC Injection (Roblox)"
    desc = "DLLs no Roblox carregadas de path não-oficial (APC/manual map)"
    items = []

    if not HAS_PSUTIL:
        return _result(name, desc, items, error="psutil não instalado")

    roblox_pids = []
    try:
        for p in psutil.process_iter(["name", "pid"]):
            if (p.info.get("name") or "").lower() == "robloxplayerbeta.exe":
                roblox_pids.append(p.info["pid"])
    except Exception as e:
        return _result(name, desc, items, error=f"process_iter: {e}")

    if not roblox_pids:
        return _result(name, desc, items,
                       error="RobloxPlayerBeta não está rodando")

    for pid in roblox_pids:
        try:
            proc = psutil.Process(pid)
            # memory_maps() retorna todas as regiões mapeadas + módulos.
            # Filtramos por .dll com path suspeito.
            for mmap in proc.memory_maps(grouped=False):
                p = (mmap.path or "").lower()
                if not p.endswith(".dll"):
                    continue
                if _is_roblox_path(p):
                    continue
                if any(p.startswith(pref) for pref in _LEGIT_MODULE_PREFIXES):
                    continue
                # Duas camadas de safety: só flagga se cai em path
                # realmente suspeito (Downloads, Desktop, %TEMP%). Overlays
                # de terceiros exóticos ficam em silêncio.
                if not any(p.startswith(pref) for pref in _SUSPICIOUS_DLL_PREFIXES):
                    continue
                # DLL em user-writable suspeito → provável APC/manual map.
                items.append(_item(
                    label=f"PID {pid}: DLL suspeita de injeção",
                    detail=(
                        f"Módulo: {mmap.path}\n"
                        "Carregado no processo Roblox de path user-writable "
                        "(Downloads, Desktop, %TEMP%). Windows / Program Files / "
                        "Roblox / overlays conhecidos são únicos paths esperados. "
                        "Sinal forte de APC injection ou manual map — cross-check "
                        "com scan_roblox_dll_sideload e scan_remote_threads."
                    ),
                    severity="high",
                    matched="apc-injection-dll",
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            debug.dbg(f"apc: PID {pid} inacessível", e)
            continue
        except Exception as e:
            debug.dbg(f"apc: PID {pid} erro", e)
            continue

    return _result(name, desc, items)


# ============================ Chain ============================

ALL_BEHAVIORAL_TIER_A_SCANNERS = [
    scan_scheduled_task_dropper,
    scan_amsi_bypass,
    scan_apc_injection,
]
