"""
Tier S — scanners state-based que dependem do estado do Windows / do processo
Roblox / do timeline persistente do OS. Cheater lendo o repo não escapa sem
custo real: precisa desligar VBS/HVCI/DSE, ou não patchear a .text do Roblox,
ou impedir o SO de registrar a execução no ActivitiesCache.

  1) scan_dse_state — Driver Signature Enforcement OFF ou Test Mode ligado.
     Fonte: `bcdedit /enum` (testsigning/nointegritychecks) + registry
     Control\\CI\\State. Zero FP em máquina normal — Windows vem com DSE ON.

  2) scan_vbs_hvci_disabled — Virtualization-Based Security / HVCI
     desativados. Fonte: Get-CimInstance Win32_DeviceGuard. Pré-requisito
     pra rodar driver kernel arbitrário em Win10+ moderno; nenhum jogador
     comum desliga.

  3) scan_roblox_page_protection — enumera memória do RobloxPlayerBeta via
     VirtualQueryEx e flagga páginas dentro do módulo principal marcadas
     PAGE_EXECUTE_READWRITE (deveriam ser PAGE_EXECUTE_READ). Sinal de
     patching in-memory por internal cheat.

  4) scan_activities_cache_timeline — parse do ActivitiesCache.db SQLite em
     %LOCALAPPDATA%\\ConnectedDevicesPlatform\\<sid>\\. Toda app rodada nos
     últimos ~30 dias, com timestamp. Cleaner popular não sabe limpar.
"""

from __future__ import annotations

from models import _result, _item, _fmt_ts
import ctypes
from ctypes import wintypes
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
from datetime import datetime

import debug

try:
    from database import EXECUTOR_KEYWORDS
except ImportError:
    EXECUTOR_KEYWORDS = ()

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import win_tools
    HAS_WIN_TOOLS = True
except ImportError:
    HAS_WIN_TOOLS = False


def _tool(name: str) -> str:
    """Path absoluto pra ferramenta do System32, com fallback."""
    if HAS_WIN_TOOLS:
        return win_tools.tool(name)
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", name)


# ============================ (1) DSE / Test Mode ============================

# testsigning Yes  → Windows aceita drivers sem assinatura válida (dev/cheat).
# nointegritychecks Yes → checagens de integridade de código desabilitadas.
# Ambos são flags BCD ativadas pelo cheater pra carregar driver kernel.
_BCD_FLAGS = ("testsigning", "nointegritychecks")


def scan_dse_state() -> dict:
    """Detecta Driver Signature Enforcement OFF ou Test Mode ligado.

    Duas fontes independentes:
      - `bcdedit /enum` na entrada {current}: testsigning Yes / nointegritychecks Yes
      - Registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\State (DWORD)
        Bit 0 (0x1) = enforcement OFF; valor != 0x60000 = anomalia.

    Máquina Windows normal: zero flags BCD ativas + CI\\State = 0x60000.
    Cheater com driver custom precisa ligar pelo menos um. HIGH sozinho.
    """
    name = "DSE / Test Mode"
    desc = "Driver Signature Enforcement e Test Mode do Windows"
    items = []
    errors: list[str] = []

    # Fonte 1: bcdedit /enum (sem {current} — argument parsing muda entre
    # shells/versões e faz o comando falhar. `/enum` puro lista todas as
    # entries; a gente procura as flags de dentro.)
    try:
        r = subprocess.run(
            [_tool("bcdedit.exe"), "/enum"],
            capture_output=True, text=True, encoding="mbcs", errors="replace",
            timeout=15,
        )
        if r.returncode == 0:
            for line in (r.stdout or "").splitlines():
                low = line.strip().lower()
                for flag in _BCD_FLAGS:
                    # bcdedit imprime "testsigning              Yes"
                    if low.startswith(flag) and low.endswith("yes"):
                        items.append(_item(
                            label=f"BCD: {flag}=Yes",
                            detail=(
                                f"`bcdedit /enum` reporta `{flag} Yes`. "
                                "Isso remove a exigência de assinatura válida em drivers "
                                "kernel — pré-requisito pra carregar driver custom (cheat "
                                "externo via kernel-mode ou anti-anti-cheat). Jogador comum "
                                "nunca liga isso; se está ligado, foi feito de propósito."
                            ),
                            severity="high",
                            matched=f"dse-bcd-{flag}",
                        ))
        else:
            msg = (r.stderr or r.stdout or "").strip()
            if msg:
                errors.append(f"bcdedit: {msg[:120]}")
    except (OSError, subprocess.TimeoutExpired) as e:
        errors.append(f"bcdedit: {e}")

    # Fonte 2: registry Control\CI\State (existe em Win10; Win11 moderno
    # protege a chave e pode retornar Access Denied ou não existir user-mode).
    # Ausência da chave NÃO é erro — bcdedit já é fonte primária suficiente.
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\CI",
        ) as key:
            state, _ = winreg.QueryValueEx(key, "State")
            state = int(state)
            # 0x60000 = normal enforced. Bit 0x1 = disabled (test mode).
            if state & 0x1:
                items.append(_item(
                    label=f"CI\\State bit0 setado (raw=0x{state:x})",
                    detail=(
                        f"Registry Control\\CI\\State = 0x{state:x}. Bit 0 setado indica "
                        "Code Integrity relaxada — mesmo efeito de test mode. Fonte "
                        "independente da flag BCD."
                    ),
                    severity="high",
                    matched="dse-ci-state-off",
                ))
            elif state != 0x60000:
                items.append(_item(
                    label=f"CI\\State anômalo (raw=0x{state:x})",
                    detail=(
                        f"Registry Control\\CI\\State = 0x{state:x}, valor não-padrão. "
                        "Windows normal reporta 0x60000. Investigar."
                    ),
                    severity="low",
                    matched="dse-ci-state-anomalous",
                ))
    except (FileNotFoundError, PermissionError, OSError) as e:
        # Chave protegida / ausente em Win11 moderno é NORMAL — não é erro
        # de cobertura. Só bcdedit fatalmente cego seria erro.
        debug.dbg("dse: CI\\State indisponível (esperado em Win11)", e)
    except Exception as e:  # winreg indisponível (Linux CI etc.)
        debug.dbg("dse: winreg falhou", e)

    # Só erra se bcdedit (a fonte primária) falhou.
    bcdedit_failed = any(e.startswith("bcdedit:") for e in errors)
    if bcdedit_failed and not items:
        return _result(name, desc, items, error=" | ".join(errors))
    return _result(name, desc, items)


# ============================ (2) VBS / HVCI ============================


def scan_vbs_hvci_disabled() -> dict:
    """Detecta Virtualization-Based Security / Hypervisor-Protected Code
    Integrity desativados.

    Fonte: `Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard
    -ClassName Win32_DeviceGuard`. Campos que importam:
      - VirtualizationBasedSecurityStatus: 0=off, 1=on-not-running, 2=on-running
      - SecurityServicesRunning: array; 2 ∈ = HVCI ativo; 1 ∈ = Credential Guard
      - SecurityServicesConfigured: idem (config vs execução)

    Máquina Windows 10/11 moderna: VBS=2, SecurityServicesRunning contém 2.
    Se ambos zerados, o cheater ganhou permissão pra rodar driver kernel
    arbitrário. CRITICAL sozinho — nenhum jogador comum desliga.
    """
    name = "VBS / HVCI"
    desc = "Virtualization-Based Security e HVCI (Windows 10/11)"
    items = []

    ps_cmd = (
        "Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard "
        "-ClassName Win32_DeviceGuard | Select-Object "
        "VirtualizationBasedSecurityStatus, SecurityServicesConfigured, "
        "SecurityServicesRunning | ConvertTo-Json -Compress"
    )
    try:
        r = subprocess.run(
            [
                _tool("WindowsPowerShell\\v1.0\\powershell.exe"),
                "-NoProfile", "-NonInteractive", "-Command", ps_cmd,
            ],
            capture_output=True, text=True, encoding="mbcs", errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return _result(name, desc, items, error=f"powershell: {e}")

    if r.returncode != 0 or not (r.stdout or "").strip():
        msg = (r.stderr or "").strip() or "sem output"
        return _result(name, desc, items, error=f"Win32_DeviceGuard: {msg[:120]}")

    try:
        data = json.loads(r.stdout)
    except (ValueError, TypeError) as e:
        return _result(name, desc, items, error=f"JSON parse: {e}")

    # Get-CimInstance retorna dict ou lista — normalize.
    if isinstance(data, list):
        data = data[0] if data else {}

    vbs_status = data.get("VirtualizationBasedSecurityStatus")
    running = data.get("SecurityServicesRunning") or []
    configured = data.get("SecurityServicesConfigured") or []
    if isinstance(running, int):
        running = [running]
    if isinstance(configured, int):
        configured = [configured]

    if vbs_status == 0:
        items.append(_item(
            label="VBS desligado",
            detail=(
                "VirtualizationBasedSecurityStatus=0 (Windows 10/11 moderno reporta 2). "
                "Sem VBS, cheater pode carregar driver kernel arbitrário e mapear memória "
                "do Roblox direto do kernel — bypassa Hyperion e todos os anti-cheat "
                "user-mode. Nenhum jogador comum desliga isso."
            ),
            severity="critical",
            matched="vbs-disabled",
        ))
    elif vbs_status == 1:
        items.append(_item(
            label="VBS configurado mas não rodando",
            detail=(
                "VirtualizationBasedSecurityStatus=1. VBS está no BCD mas o "
                "hypervisor não subiu — pode ser Hyper-V desabilitado, virtualização "
                "de CPU desligada na BIOS, ou tampering. Investigar."
            ),
            severity="high",
            matched="vbs-not-running",
        ))

    # HVCI = índice 2 na lista de services. Se está configurado mas não running,
    # é sinal de tampering (alguém desligou em runtime).
    hvci_configured = 2 in configured
    hvci_running = 2 in running
    if hvci_configured and not hvci_running:
        items.append(_item(
            label="HVCI configurado mas não rodando",
            detail=(
                "SecurityServicesConfigured contém 2 (HVCI) mas SecurityServicesRunning "
                "não. HVCI foi desativado em runtime — sinal forte de tampering pra "
                "carregar driver não-assinado."
            ),
            severity="critical",
            matched="hvci-tampered",
        ))
    elif not hvci_running and vbs_status == 2:
        # VBS on mas HVCI never enabled — máquina não usa HVCI (opcional).
        # Não é hit. Fica só como info silenciosa.
        pass

    return _result(name, desc, items)


# ============================ (3) Roblox .text page protection ============================

# Constantes ctypes/Windows
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ = 0x0010

_PAGE_EXECUTE_READWRITE = 0x40
_PAGE_EXECUTE_WRITECOPY = 0x80
_MEM_COMMIT = 0x1000

_MAX_PATH = 260


class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
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


class _MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


def _find_roblox_pid() -> int | None:
    if not HAS_PSUTIL:
        return None
    try:
        for p in psutil.process_iter(["name", "pid"]):
            try:
                nm = (p.info.get("name") or "").lower()
                if nm == "robloxplayerbeta.exe":
                    return p.info["pid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        debug.dbg("roblox-page: process_iter falhou", e)
    return None


def scan_roblox_page_protection() -> dict:
    """Detecta patch in-memory do RobloxPlayerBeta.

    Enumera módulos carregados no processo Roblox, acha o executável principal,
    e via VirtualQueryEx varre as páginas dentro do range [base, base+size).
    Qualquer página COMMITTED com PAGE_EXECUTE_READWRITE ou PAGE_EXECUTE_WRITECOPY
    dentro do módulo é red flag — código carregado do disco é PAGE_EXECUTE_READ.
    Página R+W+X dentro do módulo significa que alguém escreveu por cima do
    código original (internal cheat com detour/inline hook).

    Requer admin em maioria dos casos (Roblox roda com Hyperion). Se OpenProcess
    falhar, retorna error — não é FP-safe pra tentar sem admin.
    """
    name = "Roblox .text page protection"
    desc = "Páginas do módulo RobloxPlayerBeta marcadas RWX (patching in-memory)"
    items = []

    if not HAS_PSUTIL:
        return _result(name, desc, items, error="psutil não instalado")

    pid = _find_roblox_pid()
    if pid is None:
        return _result(name, desc, items, error="RobloxPlayerBeta não está rodando")

    k32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi

    OpenProcess = k32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE

    VirtualQueryEx = k32.VirtualQueryEx
    VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(_MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
    ]
    VirtualQueryEx.restype = ctypes.c_size_t

    EnumProcessModulesEx = psapi.EnumProcessModulesEx
    EnumProcessModulesEx.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
    ]
    EnumProcessModulesEx.restype = wintypes.BOOL

    GetModuleFileNameExW = psapi.GetModuleFileNameExW
    GetModuleFileNameExW.argtypes = [
        wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD,
    ]
    GetModuleFileNameExW.restype = wintypes.DWORD

    GetModuleInformation = psapi.GetModuleInformation
    GetModuleInformation.argtypes = [
        wintypes.HANDLE, wintypes.HMODULE,
        ctypes.POINTER(_MODULEINFO), wintypes.DWORD,
    ]
    GetModuleInformation.restype = wintypes.BOOL

    CloseHandle = k32.CloseHandle

    hProc = OpenProcess(
        _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ, False, pid,
    )
    if not hProc:
        err = ctypes.get_last_error()
        return _result(name, desc, items,
                       error=f"OpenProcess PID {pid} negado (winerror={err}) — precisa admin")

    try:
        # Enumera módulos: aloca buffer suficiente pra ~1024 handles (8KB)
        hMods = (wintypes.HMODULE * 1024)()
        needed = wintypes.DWORD(0)
        LIST_MODULES_ALL = 0x03
        if not EnumProcessModulesEx(
            hProc, hMods, ctypes.sizeof(hMods),
            ctypes.byref(needed), LIST_MODULES_ALL,
        ):
            return _result(name, desc, items,
                           error=f"EnumProcessModules falhou (Hyperion pode bloquear)")

        count = needed.value // ctypes.sizeof(wintypes.HMODULE)
        main_base = None
        main_size = 0
        main_path = ""
        for i in range(min(count, 1024)):
            path_buf = ctypes.create_unicode_buffer(_MAX_PATH)
            GetModuleFileNameExW(hProc, hMods[i], path_buf, _MAX_PATH)
            path = path_buf.value or ""
            if path.lower().endswith("robloxplayerbeta.exe"):
                info = _MODULEINFO()
                if GetModuleInformation(
                    hProc, hMods[i], ctypes.byref(info), ctypes.sizeof(info),
                ):
                    main_base = info.lpBaseOfDll
                    main_size = int(info.SizeOfImage)
                    main_path = path
                break

        if main_base is None:
            return _result(name, desc, items,
                           error="RobloxPlayerBeta.exe não encontrado nos módulos carregados")

        # Varre memoria via VirtualQueryEx dentro do range do módulo principal
        rwx_pages = []
        addr = int(main_base)
        end = addr + main_size
        mbi = _MEMORY_BASIC_INFORMATION()
        while addr < end:
            n = VirtualQueryEx(
                hProc, ctypes.c_void_p(addr),
                ctypes.byref(mbi), ctypes.sizeof(mbi),
            )
            if not n:
                break
            region_size = int(mbi.RegionSize)
            if mbi.State == _MEM_COMMIT and mbi.Protect in (
                _PAGE_EXECUTE_READWRITE, _PAGE_EXECUTE_WRITECOPY,
            ):
                rwx_pages.append((addr, region_size, int(mbi.Protect)))
            if region_size <= 0:
                break
            addr += region_size

        if rwx_pages:
            total_bytes = sum(sz for _, sz, _ in rwx_pages)
            examples = ", ".join(
                f"0x{a:x} ({sz} bytes, P=0x{p:x})"
                for a, sz, p in rwx_pages[:3]
            )
            items.append(_item(
                label=f"{len(rwx_pages)} página(s) RWX em RobloxPlayerBeta",
                detail=(
                    f"Módulo {main_path} tem {len(rwx_pages)} região(ões) marcadas "
                    f"PAGE_EXECUTE_READWRITE/WRITECOPY, total {total_bytes} bytes. "
                    f"Exemplo: {examples}. Código carregado do disco vem R+X apenas. "
                    "Região R+W+X dentro do módulo = alguém patcheou em runtime "
                    "(detour/inline hook de internal cheat)."
                ),
                severity="high",
                matched="roblox-rwx-page",
            ))
    finally:
        try:
            CloseHandle(hProc)
        except Exception:
            pass

    return _result(name, desc, items)


# ============================ (4) ActivitiesCache timeline ============================


def _executor_keyword_regex() -> re.Pattern | None:
    """Regex OR das keywords de executor, com word boundary. None se lista vazia."""
    if not EXECUTOR_KEYWORDS:
        return None
    # Escapar e agrupar. Word-boundary evita FPs tipo "solar" batendo "solara".
    parts = [re.escape(k) for k in EXECUTOR_KEYWORDS if isinstance(k, str) and k.strip()]
    if not parts:
        return None
    return re.compile(r"\b(" + "|".join(parts) + r")\b", re.IGNORECASE)


def scan_activities_cache_timeline() -> dict:
    """Parseia ActivitiesCache.db (Windows Timeline / Connected Devices).

    Toda app rodada nos ~30 dias fica registrada com AppId e timestamps
    precisos. Cleaner popular não sabe limpar esse SQLite. Match dos AppIds
    contra EXECUTOR_KEYWORDS pega cheat que rodou "há uma semana" mas não
    deixou Prefetch/Amcache (ou o cara limpou essas fontes).

    Roda como o usuário atual — a DB é acessível sem admin (é do próprio user).
    """
    name = "ActivitiesCache Timeline"
    desc = "Windows Timeline: apps executadas nos últimos ~30 dias com timestamp"
    items = []

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if not local_app_data:
        return _result(name, desc, items, error="LOCALAPPDATA não definido")

    cdp_root = os.path.join(local_app_data, "ConnectedDevicesPlatform")
    if not os.path.isdir(cdp_root):
        return _result(name, desc, items,
                       error="ConnectedDevicesPlatform ausente (Timeline desligada?)")

    # Cada SID tem subdir; percorrer todos.
    db_paths = []
    try:
        for sub in os.listdir(cdp_root):
            candidate = os.path.join(cdp_root, sub, "ActivitiesCache.db")
            if os.path.isfile(candidate):
                db_paths.append(candidate)
    except OSError as e:
        return _result(name, desc, items, error=f"listar CDP: {e}")

    if not db_paths:
        return _result(name, desc, items,
                       error="ActivitiesCache.db não encontrado em nenhum SID")

    kw_regex = _executor_keyword_regex()
    if kw_regex is None:
        return _result(name, desc, items,
                       error="EXECUTOR_KEYWORDS vazio — nada pra casar")

    errors = []
    for db_path in db_paths:
        # SQLite é travado se Windows tá usando; copia pra %TEMP% e lê a cópia.
        tmp = os.environ.get("TEMP") or r"C:\Windows\Temp"
        copy_dst = os.path.join(tmp, f"telador_actcache_{os.getpid()}.db")
        try:
            shutil.copy2(db_path, copy_dst)
        except OSError as e:
            # Tenta abrir direto — talvez esteja destravado
            copy_dst = db_path
            debug.dbg(f"ActivitiesCache: copy falhou ({e}), tentando direto", e)

        conn = None
        try:
            conn = sqlite3.connect(f"file:{copy_dst}?mode=ro", uri=True, timeout=10)
            cur = conn.cursor()
            # Schema da tabela Activity mudou entre versões do Windows.
            # Descobre colunas disponíveis via PRAGMA e usa só as que existem.
            cur.execute("PRAGMA table_info(Activity)")
            cols = {row[1] for row in cur.fetchall()}
            payload_col = "Payload" if "Payload" in cols else (
                "PayloadJson" if "PayloadJson" in cols else None
            )
            if "AppId" not in cols:
                errors.append(f"{os.path.basename(db_path)}: schema sem AppId")
                continue
            time_col = "LastModifiedOnClient" if "LastModifiedOnClient" in cols else (
                "StartTime" if "StartTime" in cols else None
            )
            select_cols = ["AppId"]
            if "StartTime" in cols:
                select_cols.append("StartTime")
            else:
                select_cols.append("0 AS StartTime")
            if "LastModifiedOnClient" in cols:
                select_cols.append("LastModifiedOnClient")
            else:
                select_cols.append("0 AS LastModifiedOnClient")
            if payload_col:
                select_cols.append(payload_col + " AS Payload")
            else:
                select_cols.append("NULL AS Payload")
            order = f"ORDER BY {time_col} DESC" if time_col else ""
            cur.execute(
                f"SELECT {', '.join(select_cols)} FROM Activity {order} LIMIT 5000"
            )
            for app_id, start_time, last_mod, payload in cur.fetchall():
                blob = " ".join(
                    str(x) for x in (app_id, payload) if x
                )
                m = kw_regex.search(blob)
                if not m:
                    continue
                kw = m.group(1).lower()
                # Severity vem do EXECUTOR_KEYWORDS (dict {kw: severity}).
                # Fallback = MEDIUM (dual-use ambíguo). Timeline sozinho não
                # vira HIGH sem corroboração — o dict já pontua isso ("process
                # hacker": low, "solara": high). Ambientes de cheat-focado
                # ficam com HIGH; ferramentas de dev viram LOW.
                sev = "medium"
                if isinstance(EXECUTOR_KEYWORDS, dict):
                    sev = EXECUTOR_KEYWORDS.get(kw, sev)
                    if sev not in ("critical", "high", "medium", "low"):
                        sev = "medium"
                ts = _fmt_ts(last_mod) if last_mod else _fmt_ts(start_time)
                items.append(_item(
                    label=f"Timeline: {kw}",
                    detail=(
                        f"ActivitiesCache.db: {db_path}\n"
                        f"AppId (fragmento): {(app_id or '')[:200]}\n"
                        f"Match: '{kw}' — SO registrou execução em {ts}. "
                        "Cleaner popular não limpa esse SQLite; se apagou o Prefetch "
                        "mas deixou aqui, é o registro forense sobrevivente."
                    ),
                    severity=sev,
                    matched=f"activities-cache:{kw}",
                    timestamp=ts,
                ))
        except sqlite3.DatabaseError as e:
            errors.append(f"sqlite {os.path.basename(db_path)}: {e}")
        except Exception as e:  # noqa: BLE001 — SQLite pode lançar variantes
            errors.append(f"{os.path.basename(db_path)}: {e}")
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            # Só remove se foi cópia temporária
            if copy_dst != db_path:
                try:
                    os.remove(copy_dst)
                except OSError:
                    pass

    if errors and not items:
        return _result(name, desc, items, error=" | ".join(errors[:2]))
    return _result(name, desc, items)


# ============================ Chain ============================

ALL_SYSTEM_HARDENING_SCANNERS = [
    scan_dse_state,
    scan_vbs_hvci_disabled,
    scan_roblox_page_protection,
    scan_activities_cache_timeline,
]
