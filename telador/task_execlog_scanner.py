"""
Task Scheduler Execution History — canal Microsoft-Windows-TaskScheduler/Operational.

Diferente de scan_scheduled_tasks (persistence.py — lista tasks ATIVAS agora) e
de scan_scheduled_task_dropper (behavioral_tier_a — tasks criadas nas últimas
24h). Este scanner pega tasks que já foram DELETADAS mas EXECUTARAM antes da
limpeza — cheater cria task, roda executor, deleta task, mas o Event Log 200/201
(action started / completed) mantém o path do exe pra sempre.

Event IDs:
  100 = Task Started
  200 = Action Started (tem ActionName = path do exe rodado)
  201 = Action Completed
  102 = Task Completed

Requer admin pra ler canal Microsoft-Windows-TaskScheduler/Operational.
"""

from .models import _result, _item
import subprocess

try:
    from . import win_tools
    HAS_WIN_TOOLS = True
except ImportError:
    HAS_WIN_TOOLS = False


_TASKSCHED_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"

# Paths de sistema (task legítima roda daqui)
_LEGIT_TASK_PATH_PREFIXES = (
    "c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\",
    "%systemroot%\\", "%programfiles%\\",
    "c:\\programdata\\microsoft\\",
    "c:\\programdata\\nvidia", "c:\\programdata\\amd",
    "c:\\programdata\\intel", "c:\\programdata\\package cache\\",
)

# Tasks de sistema conhecidas (pra dedup)
_LEGIT_TASK_NAMES = (
    "\\microsoft\\", "\\google\\", "\\intel\\", "\\nvidia\\",
    "\\onedrive", "\\windowsupdate",
    # Squirrel-based apps (Update.exe em %LOCALAPPDATA%\<App>\)
    "\\discord", "\\slack", "\\github desktop", "\\githubdesktop",
    "\\notion", "\\cursor", "\\visual studio code", "\\vscode",
    "\\microsoft vs code", "\\code -", "\\code_",
    "\\zoom", "\\telegram", "\\whatsapp", "\\dropbox",
    "\\adobe", "\\creative cloud", "\\creativecloud",
    "\\squirrel", "\\update",
    # Roblox/Bloxstrap update tasks
    "\\roblox", "\\bloxstrap",
    # Riot / Steam / Epic / Ubisoft / EA
    "\\riot", "\\valorant", "\\league of legends",
    "\\battle.net", "\\blizzard",
    "\\steam", "\\epic games", "\\epicgames", "\\ubisoft",
    "\\ea desktop", "\\eadesktop", "\\origin", "\\rockstar",
    # Voicemod / Overwolf
    "\\voicemod", "\\overwolf",
)

# Basenames de exes de updater legítimos em user-path
_LEGIT_UPDATER_BASENAMES = frozenset({
    "update.exe", "squirrel.exe", "squirrelsetup.exe",
    "setup.exe", "installer.exe", "updater.exe",
    "onedrivelauncher.exe", "onedrive.exe",
})


def _powershell():
    if HAS_WIN_TOOLS:
        return win_tools.powershell()
    return "powershell.exe"


def scan_task_scheduler_execlog() -> dict:
    """
    Lê eventos 200/201 (Action Started/Completed) do canal Task Scheduler
    Operational. Extrai TaskName + ActionName (path do exe) e flagga:
      - ActionName com executor keyword
      - ActionName em user-path (fora de Windows/Program Files)
      - TaskName com keyword mas ausente da lista ATIVA (task deletada
        pós-execução)
    """
    name = "Task Scheduler Execlog (tasks deletadas)"
    desc = ("Log de execução do Task Scheduler — pega tasks que rodaram exe "
            "e depois foram deletadas. Path do exe permanece no Event Log.")

    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$evts = Get-WinEvent -LogName '{_TASKSCHED_CHANNEL}' -MaxEvents 1000"
        " -FilterXPath '*[System[EventID=200 or EventID=201]]';"
        "foreach ($e in $evts) {"
        "  $x = [xml]$e.ToXml();"
        "  $d = $x.Event.EventData.Data;"
        "  $task = ''; $action = '';"
        "  foreach ($n in $d) {"
        "    if ($n.Name -eq 'TaskName') { $task = $n.'#text' }"
        "    if ($n.Name -eq 'ActionName') { $action = $n.'#text' }"
        "  }"
        "  if (-not $action) { continue }"
        "  $line = 'EVT::' + $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '::';"
        "  $line += 'TN=' + $task + '::';"
        "  $line += 'AN=' + $action;"
        "  Write-Output $line"
        "}"
    )
    try:
        result = subprocess.run(
            [_powershell(), "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=45,
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return _result(name, desc, [], error=str(e))

    if result.returncode != 0 and not result.stdout.strip():
        return _result(name, desc, [],
                       error="Task Scheduler log inacessível (requer admin)")

    from . import matching
    items = []
    seen: set[tuple] = set()

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("EVT::"):
            continue
        parts = line[5:].split("::")
        if len(parts) < 3:
            continue
        ts_str = parts[0]
        fields: dict[str, str] = {}
        for p in parts[1:]:
            if "=" in p:
                k, _, v = p.partition("=")
                fields[k.strip()] = v.strip()

        task = fields.get("TN", "")
        action = fields.get("AN", "")

        if not action:
            continue

        action_low = action.lower().replace("/", "\\").strip('" ')
        task_low = task.lower()

        # Skip system paths
        if any(action_low.startswith(p) for p in _LEGIT_TASK_PATH_PREFIXES):
            continue

        # Skip system-namespaced tasks
        if any(t in task_low for t in _LEGIT_TASK_NAMES):
            continue

        # Skip updaters legítimos (Squirrel Update.exe etc.) sem keyword
        import os as _os_local
        basename_low = _os_local.path.basename(action_low)
        is_legit_updater = basename_low in _LEGIT_UPDATER_BASENAMES

        dedup = (task, action_low)
        if dedup in seen:
            continue
        seen.add(dedup)

        # Match keyword na TaskName ou ActionName
        kw, sev = matching.match_keyword(action) or matching.match_keyword(task)
        if not kw:
            kw2, sev2 = matching.match_keyword(task)
            if kw2:
                kw, sev = kw2, sev2

        # Path em user-path?
        in_user_path = any(t in action_low for t in (
            "\\users\\", "\\downloads\\", "\\temp\\", "\\appdata\\",
        ))

        if kw:
            severity = sev
            matched = f"tasksched-exec:{kw}"
            reason = f"Nome de executor: {kw}"
        elif in_user_path and not is_legit_updater:
            severity = "medium"
            matched = "tasksched-userpath"
            reason = "Task rodou exe de user-path (não Windows/Program Files)"
        else:
            continue

        items.append(_item(
            label=f"[TaskSched] {task or '(sem nome)'} → {action.split(chr(92))[-1]}",
            detail=(f"Task: {task or '(vazio)'}\n"
                    f"Action: {action}\n"
                    f"Timestamp: {ts_str}\n"
                    f"Motivo: {reason}\n"
                    f"O Event Log do Task Scheduler mantém histórico mesmo se "
                    f"a task foi deletada. Padrão comum: cheater cria task, "
                    f"executa, deleta a task e o exe — log 200/201 permanece."),
            severity=severity, matched=matched, timestamp=ts_str,
        ))

    return _result(name, desc, items)


ALL_TASK_EXECLOG_SCANNERS = [
    scan_task_scheduler_execlog,
]
