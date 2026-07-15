"""
Program Compatibility Assistant Event Log — canal separado do System/Security
que registra inventário de aplicativos executados no Windows.

Canal: Microsoft-Windows-Application-Experience/Program-Inventory
Event IDs relevantes:
  800  = Inventory Change (aplicativo executado / registrado)
  902  = Inventory Startup

Diferente de scan_windows_events (que analisa Security/System 7045/4104/4688/1116)
e de scan_amcache (que lê o hive AppCompat) — este canal é escrito pelo próprio
PCA em runtime e persiste independente do hive; sobrevive a limpeza específica
do Amcache que muitos anti-forense automatizam.

Requer admin pra ler o canal.
"""

from .models import _result, _item
import subprocess

try:
    from . import win_tools
    HAS_WIN_TOOLS = True
except ImportError:
    HAS_WIN_TOOLS = False

from . import matching
_PCA_CHANNEL = "Microsoft-Windows-Application-Experience/Program-Inventory"


# Basenames de apps que rodam de user-path SEM CompanyName (Squirrel/Electron
# minimal metadata, updaters). Não flaggar por "sem publisher" sozinho.
_PCA_LEGIT_NOPUB_BASENAMES = frozenset({
    "update.exe", "squirrel.exe", "squirrelsetup.exe",
    "setup.exe", "installer.exe", "updater.exe",
    "python.exe", "pythonw.exe", "node.exe",
    "npm.exe", "pip.exe", "pipx.exe",
    "code.exe", "cursor.exe", "code - insiders.exe",
    # Roblox / Bloxstrap (identidade legítima às vezes sem publisher no PCA)
    "robloxplayerbeta.exe", "robloxplayerlauncher.exe",
    "robloxstudiobeta.exe", "roblox.exe", "bloxstrap.exe",
})


def _powershell():
    if HAS_WIN_TOOLS:
        return win_tools.powershell()
    return "powershell.exe"


def scan_pca_appcompat_events() -> dict:
    """
    Lê eventos ID 800 do canal Program-Inventory. Extrai path do exe e nome
    da empresa (publisher). Flagga:
      - Path com executor keyword
      - Path em user-path
      - Publisher vazio ou desconhecido em user-path
    """
    name = "PCA AppCompat Events"
    desc = ("Log de inventário do Program Compatibility Assistant — registra "
            "TODA execução mesmo se cheater limpou Amcache.")

    # Get-WinEvent traz XML — extraímos os campos do EventData.
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$evts = Get-WinEvent -LogName '{_PCA_CHANNEL}' -MaxEvents 500;"
        "foreach ($e in $evts) {"
        "  if ($e.Id -ne 800) { continue }"
        "  $x = [xml]$e.ToXml();"
        "  $d = $x.Event.EventData.Data;"
        "  $props = @{};"
        "  foreach ($n in $d) { $props[$n.Name] = $n.'#text' }"
        "  $line = 'EVT::' + $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '::';"
        "  $line += 'FN=' + $props['FileName'] + '::';"
        "  $line += 'CN=' + $props['CompanyName'] + '::';"
        "  $line += 'PN=' + $props['ProgramName'];"
        "  Write-Output $line"
        "}"
    )
    try:
        result = subprocess.run(
            [_powershell(), "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return _result(name, desc, [], error=str(e))

    if result.returncode != 0 and not result.stdout.strip():
        return _result(name, desc, [],
                       error="Canal PCA inacessível (requer admin) ou vazio")

    items = []
    seen: set[tuple] = set()

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("EVT::"):
            continue
        parts = line[5:].split("::")
        if len(parts) < 4:
            continue
        ts_str = parts[0]
        # Cada campo é "KEY=value"
        fields = {}
        for p in parts[1:]:
            if "=" in p:
                k, _, v = p.partition("=")
                fields[k.strip()] = v.strip()

        fn = fields.get("FN", "")
        cn = fields.get("CN", "")
        pn = fields.get("PN", "")

        if not fn:
            continue

        # Dedup por path
        dedup = (fn.lower(), pn.lower())
        if dedup in seen:
            continue
        seen.add(dedup)

        fn_low = fn.lower().replace("/", "\\")

        reason = None
        severity = "medium"
        matched = None

        # 1. Executor keyword no path ou program name
        kw, sev = matching.match_keyword(fn) or matching.match_keyword(pn)
        if not kw:
            kw2, sev2 = matching.match_keyword(pn)
            if kw2:
                kw, sev = kw2, sev2
        if kw:
            reason = f"Nome de executor no path/program: {kw}"
            severity = sev
            matched = f"pca-executor:{kw}"

        # 2. User-path sem publisher (dropper anônimo)
        if not reason:
            in_user_path = any(t in fn_low for t in (
                "\\users\\", "\\downloads\\", "\\temp\\", "\\appdata\\local\\temp",
            ))
            basename_low = fn_low.rsplit("\\", 1)[-1] if "\\" in fn_low else fn_low
            if in_user_path and not cn.strip() and basename_low not in _PCA_LEGIT_NOPUB_BASENAMES:
                reason = "Executado em user-path sem publisher"
                severity = "medium"
                matched = "pca-userpath-nopublisher"

        if not reason:
            continue

        basename = fn.rsplit("\\", 1)[-1] if "\\" in fn else fn
        items.append(_item(
            label=f"[PCA] {pn or basename}",
            detail=(f"Path: {fn}\n"
                    f"Publisher: {cn or '(vazio)'}\n"
                    f"Program name: {pn or '(vazio)'}\n"
                    f"Motivo: {reason}\n"
                    f"O Program Compatibility Assistant registra este exe "
                    f"como executado. Log sobrevive a limpeza do Amcache."),
            severity=severity, matched=matched or "pca-appcompat",
            timestamp=ts_str,
        ))

    return _result(name, desc, items)


ALL_PCA_SCANNERS = [
    scan_pca_appcompat_events,
]
