"""
Scanners de persistência — cheater esperto coloca executor no autostart
ou agenda task pra reiniciar mesmo após reboot. WER guarda crash dumps
de quando Roblox detecta cheat.

Cobre:
  - Pasta Startup (%APPDATA%\\...\\Start Menu\\Programs\\Startup)
  - Registry: HKCU/HKLM Run, RunOnce
  - Scheduled Tasks
  - WER (Windows Error Reporting) crash dumps
"""

from models import _result, _item, _fmt_ts
import os
import subprocess

import win_tools
from datetime import datetime, timedelta

from database import (
    AUTOSTART_REGISTRY_KEYS_HKCU,
    AUTOSTART_REGISTRY_KEYS_HKLM,
    STARTUP_FOLDERS,
    WER_PATHS,
)

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


def _match_keyword(text: str):
    # Delega pro matching central (word-boundary, anti-FP).
    import matching
    return matching.match_keyword(text)


# ============================ Startup folders ============================

def scan_startup_folders() -> dict:
    """Atalhos/exes na pasta Startup do Windows."""
    items = []

    for path_template in STARTUP_FOLDERS:
        base = os.path.expandvars(path_template)
        if not os.path.isdir(base):
            continue

        try:
            entries = os.listdir(base)
        except (PermissionError, OSError):
            continue

        for fname in entries:
            full = os.path.join(base, fname)
            # Lê target do .lnk se possível
            target = ""
            if fname.lower().endswith(".lnk"):
                try:
                    with open(full, "rb") as fh:
                        raw = fh.read(10_000)
                    # Extrai strings UTF-16 (lnk header tem path do target)
                    target = raw.decode("utf-16-le", errors="ignore")
                except OSError:
                    pass

            blob = f"{fname} {target}"
            kw, sev = _match_keyword(blob)
            if not kw:
                continue

            ts = _fmt_ts(os.path.getmtime(full)) if os.path.isfile(full) else ""
            items.append(_item(
                label=fname,
                detail=f"{full}",
                severity=sev, matched=kw, timestamp=ts,
            ))

    return _result("Startup Folder",
                   "Programas que iniciam junto com o Windows (pasta Startup)",
                   items)


# ============================ Run keys ============================

def _scan_run_key(hive, key_path, label):
    items = []
    try:
        key = winreg.OpenKey(hive, key_path)
    except OSError:
        return items

    try:
        i = 0
        while True:
            try:
                name, value, _typ = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1

            blob = f"{name} {value}"
            kw, sev = _match_keyword(blob)
            if not kw:
                continue
            items.append(_item(
                label=f"[{label}] {name}",
                detail=str(value),
                severity=sev, matched=kw,
            ))
    finally:
        winreg.CloseKey(key)

    return items


def scan_run_keys() -> dict:
    """
    HKCU/HKLM Run, RunOnce. Programas registrados pra rodar no login.
    HKLM precisa de admin.
    """
    if not HAS_WINREG:
        return _result("Run Keys (Registry)", "Autostart via Registry", [],
                       error="winreg indisponível")

    items = []
    hkcu_ok = False
    hklm_ok = False

    for key_path, label in AUTOSTART_REGISTRY_KEYS_HKCU:
        try:
            test = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.CloseKey(test)
            hkcu_ok = True
        except OSError:
            continue
        items.extend(_scan_run_key(winreg.HKEY_CURRENT_USER, key_path, label))

    for key_path, label in AUTOSTART_REGISTRY_KEYS_HKLM:
        try:
            test = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            winreg.CloseKey(test)
            hklm_ok = True
        except OSError:
            continue
        items.extend(_scan_run_key(winreg.HKEY_LOCAL_MACHINE, key_path, label))

    if not hkcu_ok and not hklm_ok:
        return _result("Run Keys (Registry)", "Autostart via Registry", [],
                       error="Não conseguiu acessar nenhuma chave de autostart")

    return _result("Run Keys (Registry)",
                   "Autostart programado via HKCU/HKLM Run + RunOnce",
                   items)


# ============================ Scheduled tasks ============================

def scan_scheduled_tasks() -> dict:
    """
    Lista todas as tasks agendadas via schtasks /query /fo csv /v.
    Procura por task names ou comandos que mencionem executores.
    """
    try:
        # schtasks output usa codepage do console (cp850 em PT-BR, cp1252 em
        # outros). utf-8 era errado — perdia acentos em task names.
        # text=False + decode manual com fallback é mais robusto.
        result = subprocess.run(
            [win_tools.tool("schtasks.exe"), "/query", "/fo", "csv", "/v"],
            capture_output=True, timeout=20,
        )
        # Tenta cp850 (DOS BR), fallback cp1252 (Win ANSI), fallback utf-8
        stdout_bytes = result.stdout or b""
        stderr_bytes = result.stderr or b""
        for enc in ("cp850", "cp1252", "utf-8"):
            try:
                stdout_text = stdout_bytes.decode(enc)
                stderr_text = stderr_bytes.decode(enc, errors="replace")
                break
            except UnicodeDecodeError:
                continue
        else:
            stdout_text = stdout_bytes.decode("utf-8", errors="replace")
            stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        # Reconstrói result mantendo interface esperada abaixo
        class _R:
            pass
        r = _R()
        r.returncode = result.returncode
        r.stdout = stdout_text
        r.stderr = stderr_text
        result = r
    except (OSError, subprocess.TimeoutExpired) as e:  # OSError cobre FileNotFound + winerror genérico
        return _result("Scheduled Tasks", "Tarefas agendadas do Windows", [], error=str(e))

    if result.returncode != 0:
        return _result("Scheduled Tasks", "Tarefas agendadas do Windows", [],
                       error=(result.stderr or "schtasks falhou").strip()[:200])

    items = []
    lines = result.stdout.split("\n")
    # Filtra cada linha (cada task ocupa uma linha CSV completa)
    for line in lines:
        if not line.strip() or line.startswith('"HostName"'):
            continue
        kw, sev = _match_keyword(line)
        if not kw:
            continue

        # Extrai um label legível — pega o nome da task se possível
        fields = line.split(",")
        label = fields[1].strip('"') if len(fields) > 1 else "task suspeita"
        detail = line[:500]

        items.append(_item(
            label=label, detail=detail,
            severity=sev, matched=kw,
        ))

    return _result("Scheduled Tasks",
                   "Tarefas agendadas pelo Windows Task Scheduler",
                   items)


# ============================ WER (crash dumps) ============================

def scan_wer_dumps() -> dict:
    """
    Windows Error Reporting guarda crash dumps de programas que crasharam.
    Cada subpasta tem Report.wer + arquivos com nome do exe que crashou.
    Roblox crashando por anticheat aparece aqui.
    """
    items = []
    cutoff = datetime.now() - timedelta(days=90)

    for path_template in WER_PATHS:
        base = os.path.expandvars(path_template)
        if not os.path.isdir(base):
            continue

        try:
            reports = os.listdir(base)
        except (PermissionError, OSError):
            continue

        for report_dir in reports:
            full = os.path.join(base, report_dir)
            if not os.path.isdir(full):
                continue

            # Skip antigo
            try:
                if datetime.fromtimestamp(os.path.getmtime(full)) < cutoff:
                    continue
            except OSError:
                continue

            # Lê o Report.wer pra pegar AppName
            wer_file = os.path.join(full, "Report.wer")
            content = ""
            if os.path.isfile(wer_file):
                try:
                    with open(wer_file, "r", encoding="utf-16", errors="replace") as fh:
                        content = fh.read(50_000)
                except OSError:
                    try:
                        with open(wer_file, "r", encoding="utf-8", errors="replace") as fh:
                            content = fh.read(50_000)
                    except OSError:
                        pass

            # Procura por keyword em conteúdo + nome da pasta
            search = f"{report_dir} {content}"
            kw, sev = _match_keyword(search)

            # Sinal indireto: Roblox crash com referência a Hyperion/anti-tamper
            roblox_anticheat = (
                "roblox" in search.lower()
                and any(p in search.lower() for p in (
                    "hyperion", "antitamper", "anti-tamper",
                    "processuntrusted", "rbxcrash"))
            )

            if not kw and not roblox_anticheat:
                continue

            if roblox_anticheat and not kw:
                kw, sev = "roblox-anticheat-crash", "medium"

            ts = _fmt_ts(os.path.getmtime(full))
            items.append(_item(
                label=report_dir,
                detail=f"{full}",
                severity=sev, matched=kw, timestamp=ts,
            ))

    return _result("WER (crash dumps)",
                   "Windows Error Reporting: crashes de Roblox vs cheat detection",
                   items)



# ============================ WMI persistence ============================

def scan_wmi_persistence() -> dict:
    """
    Assinaturas WMI em root\\subscription — método de persistência avançado.
    Aplicativos legítimos quase nunca usam root\\subscription; cheaters e loaders
    criam __EventFilter + __EventConsumer pra executar o cheat no boot/login sem
    aparecer em Startup/Run keys (menos detectável).
    Precisa de admin; query via PowerShell.
    """
    name = "WMI Persistence (root\\subscription)"
    desc = "Assinaturas WMI pra execução automática — bypass de Startup/Run keys"

    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-WMIObject -Namespace root\\subscription -Class __EventFilter"
        " | ForEach-Object { Write-Output ('FILTER::' + $_.Name + '::' + $_.Query) };"
        "Get-WMIObject -Namespace root\\subscription -Class __EventConsumer"
        " | ForEach-Object { Write-Output ('CONSUMER::' + $_.__CLASS + '::' + $_.Name + '::' + $_.CommandLineTemplate) };"
        "Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding"
        " | ForEach-Object { Write-Output ('BINDING::' + $_.Filter + '::' + $_.Consumer) }"
    )
    try:
        result = subprocess.run(
            [win_tools.powershell(), "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=20,
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return _result(name, desc, [], error=str(e))

    if result.returncode != 0 and not result.stdout.strip():
        return _result(name, desc, [],
                       error="Não conseguiu consultar WMI (sem admin?)")

    items = []
    filters_seen: set[str] = set()
    consumers_seen: set[str] = set()

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("FILTER::"):
            parts = line[8:].split("::", 1)
            filter_name = parts[0].strip()
            query = parts[1].strip() if len(parts) > 1 else ""
            if filter_name in filters_seen or filter_name.startswith("SCM Event"):
                continue
            filters_seen.add(filter_name)
            items.append(_item(
                label=f"[WMI Filter] {filter_name}",
                detail=(f"Filtro de evento WMI em root\\subscription:\n"
                        f"Nome: {filter_name}\nQuery: {query}\n"
                        f"Filtros em root\\subscription são raros em máquinas limpas. "
                        f"Loaders de cheat criam filtros pra disparar no boot/logon."),
                severity="high", matched="wmi-event-filter",
            ))

        elif line.startswith("CONSUMER::"):
            parts = line[10:].split("::", 2)
            cls = parts[0].strip() if parts else ""
            cname = parts[1].strip() if len(parts) > 1 else ""
            cmd = parts[2].strip() if len(parts) > 2 else ""
            if cname in consumers_seen:
                continue
            # SCM Event Log Consumer/Filter = baseline do Windows (não flaggar)
            if cname.startswith("SCM Event") or "SCM Event Log" in cname:
                continue
            consumers_seen.add(cname)
            # CommandLineEventConsumer executa programa = mais forte
            sev = "critical" if "CommandLine" in cls and cmd else "high"
            label_detail = f"Classe: {cls} | Nome: {cname}"
            if cmd:
                label_detail += f" | Comando: {cmd}"
            items.append(_item(
                label=f"[WMI Consumer] {cname}",
                detail=(f"Consumidor WMI em root\\subscription:\n"
                        f"{label_detail}\n"
                        f"CommandLineEventConsumer executa um executável no trigger — "
                        f"padrão clássico de persistência de malware e cheat loader."),
                severity=sev, matched="wmi-event-consumer",
            ))

    return _result(name, desc, items)


ALL_PERSISTENCE_SCANNERS = [
    scan_startup_folders,
    scan_run_keys,
    scan_scheduled_tasks,
    scan_wer_dumps,
    scan_wmi_persistence,
]
