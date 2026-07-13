"""
BITS (Background Intelligent Transfer Service) — downloader silencioso do
Windows. Cheaters usam `BITSAdmin /Transfer` ou `Start-BitsTransfer` para
baixar payloads em segundo plano sem abrir browser, sem aparecer no download
history do Chrome/Firefox, sem janela. O job persiste no banco do serviço
mesmo após completar se não for deletado explicitamente.

Difere de `scan_downloads` (que lê pasta de Downloads) e de `scan_network_connections`
(que só vê conexão ativa AGORA) — este pega download AGENDADO ou COMPLETADO
que nunca passou por browser.
"""

from models import _result, _item
import subprocess

try:
    import win_tools
    HAS_WIN_TOOLS = True
except ImportError:
    HAS_WIN_TOOLS = False

import matching
from database import SUSPICIOUS_DOMAINS


# Whitelist de DisplayNames de jobs BITS legítimos do Windows / browsers.
_LEGIT_BITS_DISPLAY_NAMES = (
    "windows update", "microsoft update",
    "google update", "chrome update", "chrome",
    "edge component updater", "edge update", "microsoft edge",
    "msedge", "edge ",
    "onedrive", "office", "teams",
    "windowsdefender", "mpsigstub", "defender",
    "delivery optimization",
    "store", "xbox", "winget", "app installer",
    "visual studio", "nuget",
)

# Owner de jobs legítimos do sistema
_LEGIT_BITS_OWNERS = (
    "nt authority\\system", "system", "network service", "local service",
)


def _powershell():
    if HAS_WIN_TOOLS:
        return win_tools.powershell()
    return "powershell.exe"


def _parse_bits_output(stdout: str) -> list[dict]:
    """
    Parseia output de Get-BitsTransfer (formato Format-List).
    Cada job é um bloco separado por linha em branco; cada linha `Field : Value`.
    """
    jobs: list[dict] = []
    current: dict = {}
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line.strip():
            if current:
                jobs.append(current)
                current = {}
            continue
        if ":" not in line:
            # Continuação da linha anterior (multiline value)
            if current:
                last_key = list(current.keys())[-1] if current else None
                if last_key:
                    current[last_key] = current[last_key] + " " + line.strip()
            continue
        key, _, val = line.partition(":")
        current[key.strip()] = val.strip()
    if current:
        jobs.append(current)
    return jobs


def scan_bits_jobs() -> dict:
    """
    Enumera jobs do BITS (Background Intelligent Transfer Service).
    Flagga jobs cujo RemoteUrl bate em SUSPICIOUS_DOMAINS ou cujo LocalFile
    está em user-path e não é de Windows Update / Chrome Update / OneDrive.
    """
    name = "BITS Jobs (downloader silencioso)"
    desc = ("Transferências em segundo plano via BITS — cheaters usam pra baixar "
            "payload sem aparecer em download history do browser.")

    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-BitsTransfer -AllUsers"
        " | Select-Object DisplayName,JobId,JobState,OwnerAccount,TransferType,"
        "@{n='RemoteUrl';e={($_.FileList | Select-Object -First 1).RemoteName}},"
        "@{n='LocalFile';e={($_.FileList | Select-Object -First 1).LocalName}}"
        " | Format-List"
    )
    try:
        result = subprocess.run(
            [_powershell(), "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=20,
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return _result(name, desc, [], error=str(e))

    if result.returncode != 0 and not result.stdout.strip():
        # BITS pode não estar disponível em WinPE / Server Core
        return _result(name, desc, [],
                       error="Get-BitsTransfer indisponível")

    jobs = _parse_bits_output(result.stdout)
    if not jobs:
        return _result(name, desc, [])

    items = []
    for job in jobs:
        display = (job.get("DisplayName") or "").lower()
        owner = (job.get("OwnerAccount") or "").lower()
        remote = (job.get("RemoteUrl") or "").lower()
        local = (job.get("LocalFile") or "").lower()
        state = job.get("JobState") or ""
        job_id = job.get("JobId") or "?"

        # Skip jobs claramente legítimos (Windows Update, OneDrive, etc.)
        if any(l in display for l in _LEGIT_BITS_DISPLAY_NAMES):
            continue
        if any(o in owner for o in _LEGIT_BITS_OWNERS) and \
           any(l in display for l in _LEGIT_BITS_DISPLAY_NAMES):
            continue

        reason = None
        severity = "medium"
        matched = "bits-job"

        # 1. RemoteUrl em SUSPICIOUS_DOMAINS
        for dom, sev in SUSPICIOUS_DOMAINS.items():
            if matching.domain_in_text(dom, remote):
                reason = f"URL suspeita: {dom}"
                severity = sev
                matched = f"bits-suspicious-url:{dom}"
                break

        # 2. Nome de executor no display, remote ou local
        if not reason:
            for blob in (display, remote, local, job.get("DisplayName") or ""):
                kw, sev = matching.match_keyword(blob)
                if kw:
                    reason = f"Nome de executor no job: {kw}"
                    severity = sev
                    matched = f"bits-executor:{kw}"
                    break

        # 3. LocalFile em user-path com job owner user (não sistema)
        if not reason and local:
            if any(t in local for t in (
                "\\users\\", "\\downloads\\", "\\appdata\\", "\\temp\\"
            )) and not any(o in owner for o in _LEGIT_BITS_OWNERS):
                # DisplayName aleatório (GUID/hex) = quase certo cheat loader
                dn = job.get("DisplayName") or ""
                if len(dn) >= 20 and all(c.isalnum() or c in "-_" for c in dn):
                    reason = "Job com nome aleatório baixando pra user-path"
                    severity = "high"
                    matched = "bits-random-name-user-path"
                else:
                    reason = "Download BITS em user-path (não Windows Update)"
                    severity = "medium"
                    matched = "bits-user-path"

        if not reason:
            continue

        items.append(_item(
            label=f"[BITS] {job.get('DisplayName') or '(sem nome)'} — {state}",
            detail=(f"JobId: {job_id}\nOwner: {owner or '(vazio)'}\n"
                    f"RemoteUrl: {remote or '(vazio)'}\n"
                    f"LocalFile: {local or '(vazio)'}\n"
                    f"Motivo: {reason}\n"
                    f"BITS é o mecanismo do Windows Update — cheaters usam pra "
                    f"baixar payload sem passar por browser, sem aparecer em "
                    f"download history."),
            severity=severity, matched=matched,
        ))

    return _result(name, desc, items)


ALL_BITS_SCANNERS = [
    scan_bits_jobs,
]
