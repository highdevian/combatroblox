"""
Anti-evasão: detecta tentativas de mascarar a SS.
  - VM (VMware, VirtualBox, QEMU, Hyper-V, Parallels)
  - Sandbox (Sandboxie, Cuckoo) e ferramentas de análise (Wireshark, Fiddler)
  - Clock tampering (relógio do sistema mexido)
"""

import os
import time
from datetime import datetime, timedelta

from database import (
    VM_PROCESS_NAMES,
    SANDBOX_PROCESS_NAMES,
    VM_REGISTRY_PROBES,
    VM_SERVICE_NAMES,
    VM_MAC_PREFIXES,
)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


def _result(name, description, items, error=None):
    if error:
        status = "error"
    else:
        status = "suspicious" if items else "clean"

    if error:
        summary = f"Erro: {error}"
    elif not items:
        summary = "Sem indícios"
    else:
        summary = f"{len(items)} indício(s) encontrado(s)"

    return {
        "name": name, "description": description, "status": status,
        "items": items, "summary": summary, "error": error,
    }


def _item(label, detail, severity, matched, timestamp=""):
    return {
        "label": label, "detail": detail, "severity": severity,
        "matched": matched, "timestamp": timestamp,
    }


# ============================ VM detection ============================

def scan_vm() -> dict:
    """Combina vários sinais de VM: processos, registry, services, MAC."""
    items = []

    # 1. Processos
    if HAS_PSUTIL:
        for proc in psutil.process_iter(["name"]):
            try:
                name = (proc.info.get("name") or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            vm_label = VM_PROCESS_NAMES.get(name)
            if vm_label:
                items.append(_item(
                    label=f"Processo: {name}",
                    detail=f"Indica {vm_label}",
                    severity="high", matched=name,
                ))

    # 2. Registry BIOS strings
    if HAS_WINREG:
        for subkey, value, substring, label in VM_REGISTRY_PROBES:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey)
                val, _ = winreg.QueryValueEx(key, value)
                winreg.CloseKey(key)
                if substring.lower() in str(val).lower():
                    items.append(_item(
                        label=f"BIOS {value}: {val}",
                        detail=f"Indica {label}",
                        severity="high", matched=substring,
                    ))
            except OSError:
                continue

    # 3. Services / drivers de VM
    if HAS_PSUTIL:
        try:
            services = {s.name().lower() for s in psutil.win_service_iter()}
            for svc in VM_SERVICE_NAMES:
                if svc.lower() in services:
                    items.append(_item(
                        label=f"Serviço: {svc}",
                        detail="Driver/service de hypervisor instalado",
                        severity="high", matched=svc,
                    ))
        except (AttributeError, OSError):
            pass

    # 4. MAC addresses (prefixos conhecidos)
    if HAS_PSUTIL:
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family != psutil.AF_LINK:
                        continue
                    mac = (addr.address or "").upper().replace("-", ":")
                    if not mac or len(mac) < 8:
                        continue
                    prefix = mac[:8]
                    label = VM_MAC_PREFIXES.get(prefix)
                    if label:
                        items.append(_item(
                            label=f"MAC {mac} ({iface})",
                            detail=f"Prefixo OUI atribuído a {label}",
                            severity="high", matched=prefix,
                        ))
        except (AttributeError, OSError):
            pass

    return _result("VM Detection",
                   "Detecta máquinas virtuais (VMware, VBox, Hyper-V, QEMU, Parallels)",
                   items)


# ============================ Sandbox detection ============================

SANDBOX_PATHS = [
    r"C:\Sandbox",
    r"C:\Cuckoo",
    r"C:\analysis",
    r"%PROGRAMFILES%\Sandboxie",
    r"%PROGRAMFILES%\Sandboxie-Plus",
]


def scan_sandbox() -> dict:
    items = []

    # 1. Processos
    if HAS_PSUTIL:
        for proc in psutil.process_iter(["name"]):
            try:
                name = (proc.info.get("name") or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            sb_label = SANDBOX_PROCESS_NAMES.get(name)
            if sb_label:
                items.append(_item(
                    label=f"Processo: {name}",
                    detail=f"Indica {sb_label}",
                    severity="high", matched=name,
                ))

    # 2. Pastas
    for raw_path in SANDBOX_PATHS:
        path = os.path.expandvars(raw_path)
        if os.path.isdir(path):
            items.append(_item(
                label=f"Pasta: {path}",
                detail="Diretório típico de ambiente de análise",
                severity="medium", matched=path,
            ))

    # 3. Variáveis de ambiente típicas
    sandbox_env_keys = ("SANDBOX", "CUCKOO_DIR", "ANYRUN")
    for key in sandbox_env_keys:
        if os.environ.get(key):
            items.append(_item(
                label=f"Env: {key}={os.environ[key]}",
                detail="Variável de ambiente típica de sandbox",
                severity="high", matched=key,
            ))

    return _result("Sandbox Detection",
                   "Detecta Sandboxie, Cuckoo e ferramentas de análise",
                   items)


# ============================ Clock tampering ============================

def scan_clock() -> dict:
    """
    Sinais de relógio mexido:
      - Diferença grande entre boot_time + uptime e time.time()
      - Arquivos do sistema com data de modificação no futuro
      - Data de instalação do Windows muito recente (reinstall pra esconder)
    """
    items = []

    if HAS_PSUTIL:
        try:
            boot = psutil.boot_time()
            now = time.time()
            uptime = now - boot
            if uptime < 0:
                items.append(_item(
                    label="Boot time no futuro",
                    detail=f"boot_time={datetime.fromtimestamp(boot)} > agora={datetime.now()}",
                    severity="high", matched="clock-future",
                ))
        except (AttributeError, OSError):
            pass

    # Install date do Windows
    if HAS_WINREG:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            )
            try:
                install_date, _ = winreg.QueryValueEx(key, "InstallDate")
                install_dt = datetime.fromtimestamp(install_date)
                # 2 dias era amplo demais — fresh install + jogar no mesmo dia é
                # suspeito; comprar PC novo não é. Só flagga se instalado nas últimas 6h.
                if install_dt > datetime.now() - timedelta(hours=6):
                    items.append(_item(
                        label="Windows instalado recentemente",
                        detail=f"InstallDate = {install_dt} (últimas 6h)",
                        severity="low", matched="install-recent",
                    ))
            finally:
                winreg.CloseKey(key)
        except OSError:
            pass

    # Arquivos do sistema com timestamp no futuro
    suspect = []
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    test_dirs = [
        os.path.join(system_root, "System32"),
        os.path.join(system_root, "Prefetch"),
    ]
    now = time.time()
    future_threshold = now + 60  # 1 min buffer

    for d in test_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.listdir(d)[:200]:  # cap pra não demorar
                full = os.path.join(d, entry)
                try:
                    mtime = os.path.getmtime(full)
                except OSError:
                    continue
                if mtime > future_threshold:
                    suspect.append((entry, datetime.fromtimestamp(mtime)))
        except (PermissionError, OSError):
            continue

    for fname, ts in suspect[:5]:
        items.append(_item(
            label=f"Arquivo no futuro: {fname}",
            detail=f"mtime = {ts}",
            severity="high", matched="future-mtime",
            timestamp=ts.strftime("%Y-%m-%d %H:%M:%S"),
        ))
    if len(suspect) > 5:
        items.append(_item(
            label=f"...+{len(suspect) - 5} outros arquivos do sistema com mtime futuro",
            detail="Relógio do sistema provavelmente foi recuado",
            severity="high", matched="future-mtime-bulk",
        ))

    return _result("Clock / Tampering",
                   "Detecta relógio mexido e Windows reinstalado pra apagar rastros",
                   items)


ALL_ANTIEVASION_SCANNERS = [
    scan_vm,
    scan_sandbox,
    scan_clock,
]
