"""
Hijacking de execução via registro — dois vetores clássicos que não exigem
patchear binário do sistema, apenas escrever chave:

  1) IFEO (Image File Execution Options): valor `Debugger` numa subkey de
     um exe redireciona toda execução daquele exe pro debugger. Cheat pode
     hijackear `RobloxPlayerBeta.exe` pra rodar versão patcheada antes.
     Ou auto-attachar Cheat Engine ao abrir Roblox.

  2) COM Hijack via HKCU: `HKCU\\Software\\Classes\\CLSID` tem precedência
     sobre `HKCR\\CLSID`. Registrar CLSID de um componente carregado pelo
     Explorer/Roblox com `InprocServer32` apontando pra DLL em user-path
     carrega o DLL sem admin, sem UAC.
"""

from models import _result, _item
import os

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

import matching


# ============================ IFEO ============================

# Debuggers legítimos que aparecem no IFEO — Visual Studio JIT debugger.
_LEGIT_DEBUGGERS = (
    "vsjitdebugger.exe",
    "msvsmon.exe",
    r"c:\windows\system32\vsjitdebugger.exe",
)

# Nomes de exe que, se hijackados, são especialmente críticos.
_CRITICAL_HIJACK_TARGETS = (
    "robloxplayerbeta.exe",
    "robloxplayerlauncher.exe",
    "robloxstudiobeta.exe",
    "bloxstrap.exe",
    "fishstrap.exe",
    "roblox.exe",
    "taskmgr.exe",
    "procexp.exe", "procexp64.exe",
    "regedit.exe",
    "mmc.exe",
    "cmd.exe", "powershell.exe",
    "msconfig.exe",
    # Ferramentas de investigação
    "wireshark.exe", "fiddler.exe", "processhacker.exe",
)

_IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"


def _is_legit_debugger(debugger_val: str) -> bool:
    low = (debugger_val or "").lower().replace("/", "\\").strip('" ')
    return any(l in low for l in _LEGIT_DEBUGGERS)


def scan_ifeo_hijack() -> dict:
    """
    Enumera HKLM\\...\\Image File Execution Options e flagga qualquer entrada
    com valor `Debugger` — ou seja, com hijacking configurado. IFEO com Debugger
    é raríssimo em máquina normal (só VS JIT).
    Requer admin pra ler HKLM.
    """
    name = "IFEO Hijack (Debugger redirect)"
    desc = ("Image File Execution Options com Debugger configurado — redireciona "
            "execução de um exe pra outro (hijack pré-load).")

    if not HAS_WINREG:
        return _result(name, desc, [], error="winreg indisponível")

    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _IFEO_KEY)
    except OSError:
        return _result(name, desc, [],
                       error="Chave IFEO inacessível (requer admin)")

    items = []
    try:
        i = 0
        while True:
            try:
                exe_name = winreg.EnumKey(root, i)
                i += 1
            except OSError:
                break

            try:
                sub = winreg.OpenKey(root, exe_name)
            except OSError:
                continue

            try:
                debugger = None
                global_flag = None
                try:
                    debugger, _ = winreg.QueryValueEx(sub, "Debugger")
                except OSError:
                    pass
                try:
                    global_flag, _ = winreg.QueryValueEx(sub, "GlobalFlag")
                except OSError:
                    pass

                # Debugger presente = hijack potencial
                if debugger and isinstance(debugger, str) and debugger.strip():
                    if _is_legit_debugger(debugger):
                        continue

                    target_low = exe_name.lower()
                    is_critical = target_low in _CRITICAL_HIJACK_TARGETS
                    severity = "critical" if is_critical else "high"

                    # Debugger em user-path = quase certo malicioso
                    dbg_low = debugger.lower().replace("/", "\\")
                    user_path_debugger = any(t in dbg_low for t in (
                        "\\users\\", "\\downloads\\", "\\temp\\", "\\appdata\\",
                    ))

                    # Matched keyword no debugger ou target
                    kw_dbg, _ = matching.match_keyword(debugger)
                    kw_target, _ = matching.match_keyword(exe_name)
                    kw = kw_dbg or kw_target or "ifeo-hijack"

                    items.append(_item(
                        label=f"[IFEO] {exe_name} → {os.path.basename(debugger)}",
                        detail=(f"Target hijackado: {exe_name}\n"
                                f"Debugger: {debugger}\n"
                                f"Chave: HKLM\\{_IFEO_KEY}\\{exe_name}\n"
                                f"IFEO com Debugger redireciona TODA execução do "
                                f"target. Se target é RobloxPlayerBeta ou "
                                f"utilitário do sistema = hijack malicioso."
                                + (" User-path no debugger confirma."
                                   if user_path_debugger else "")),
                        severity=severity, matched=kw,
                    ))

                # GlobalFlag non-zero = enable page heap / debug mode
                # Isso pode ser legítimo mas em processos críticos = suspeito
                elif global_flag and isinstance(global_flag, int) and global_flag != 0:
                    target_low = exe_name.lower()
                    if target_low in _CRITICAL_HIJACK_TARGETS:
                        items.append(_item(
                            label=f"[IFEO] GlobalFlag={global_flag} em {exe_name}",
                            detail=(f"GlobalFlag ativa modo de debug no processo — "
                                    f"em target crítico ({exe_name}) pode ser "
                                    f"preparação pra injeção via page heap."),
                            severity="medium", matched="ifeo-globalflag",
                        ))
            finally:
                winreg.CloseKey(sub)
    finally:
        winreg.CloseKey(root)

    return _result(name, desc, items)


# ============================ COM Hijack via HKCU ============================

_COM_KEY = r"Software\Classes\CLSID"

# CLSIDs frequentemente hijackados (loaded pelo Explorer, Shell, ou browsers).
# Sabotar QUALQUER um destes = DLL do cheat carregado sem admin.
_COMMONLY_HIJACKED_CLSIDS = {
    "{0006F03A-0000-0000-C000-000000000046}": "Outlook.Application",
    "{42aedc87-2188-41fd-b9a3-0c966feabec1}": "Shell UAC ShimContext",
    "{a3ccedf7-2de2-11d0-86f4-00a0c913f750}": "Point in URL Object",
    "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}": "IE Sync Manager",
    "{f414c260-6ac0-11cf-b6d1-00aa00bbbb58}": "JScript Language Authoring",
    # Add mais conforme aparecerem na wild
}

# Paths onde InprocServer32 legítimo pode viver (mesmo em HKCU).
# Nota: strings NÃO-raw pra ter apenas 1 backslash trailing (raw + \\ = 2 chars).
_LEGIT_COM_PATH_PREFIXES = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\",
    "%systemroot%\\",
    "%programfiles%\\",
)

# Paths de AppData de apps conhecidos (COM LocalServer32 / toast handlers).
# VS Code, Chromium-based IDEs, etc. registram LocalServer32 em user-path —
# isso NÃO é DLL hijack clássico.
_TRUSTED_APPDATA_PATTERNS = (
    "\\microsoft\\teams\\",
    "\\microsoft\\onedrive\\",
    "\\microsoft\\edge\\",
    "\\microsoft vs code\\",
    "\\microsoft\\vscode\\",
    "\\programs\\microsoft vs code\\",
    "\\programs\\cursor\\",
    "\\programs\\antigravity\\",
    "\\slack\\",
    "\\zoom\\",
    "\\discord\\",
    "\\spotify\\",
    "\\jetbrains\\",
    "\\google\\chrome\\",
    "\\mozilla firefox\\",
    "\\openclaw\\",
)

# Basenames de LocalServer32 comumente registrados por apps legítimos
# (toast activation, protocol handlers). InprocServer32 com estes nomes
# ainda é suspeito se em temp — o filtro só aplica a LocalServer32.
_LEGIT_LOCALSERVER_BASENAMES = (
    "code.exe", "code - insiders.exe", "codehelper.exe",
    "cursor.exe", "cursor helper.exe",
    "antigravity.exe", "devenv.exe",
    "slack.exe", "teams.exe", "ms-teams.exe",
    "discord.exe", "spotify.exe", "chrome.exe", "msedge.exe",
    "firefox.exe", "notepad++.exe",
    "openclaw.tray.winui.exe", "openclaw.exe",
)


def scan_com_user_hijack() -> dict:
    """
    Enumera HKCU\\Software\\Classes\\CLSID e flagga entradas com
    InprocServer32 fora de paths do sistema. Não requer admin — HKCU tem
    precedência sobre HKCR e pode ser escrito por qualquer processo user.
    """
    name = "COM Hijack (HKCU CLSID)"
    desc = ("Objetos COM registrados em HKCU (precedência sobre HKCR sem admin) "
            "com DLL em user-path — vetor clássico de hijack sem UAC.")

    if not HAS_WINREG:
        return _result(name, desc, [], error="winreg indisponível")

    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _COM_KEY)
    except OSError:
        return _result(name, desc, [])

    items = []
    try:
        i = 0
        while True:
            try:
                clsid = winreg.EnumKey(root, i)
                i += 1
            except OSError:
                break

            # Só analisa entradas que parecem CLSIDs de verdade
            if not (clsid.startswith("{") and clsid.endswith("}") and len(clsid) == 38):
                continue

            # Prefere InprocServer32 (DLL in-process = hijack clássico).
            # LocalServer32 = out-of-process (toast, protocol handlers) —
            # apps legítimos (VS Code, Discord…) registram isso em AppData.
            dll_path = None
            server_kind = None  # "inproc" | "local"
            for inproc_sub, kind in (
                ("InprocServer32", "inproc"),
                ("InProcServer32", "inproc"),
                ("LocalServer32", "local"),
            ):
                try:
                    inproc = winreg.OpenKey(root, f"{clsid}\\{inproc_sub}")
                    try:
                        val, _ = winreg.QueryValueEx(inproc, "")
                        if isinstance(val, str) and val.strip():
                            # LocalServer32 às vezes tem args: `app.exe" -ToastActivated`
                            raw = val.strip().strip('"')
                            # Pega o path do exe (antes de args)
                            dll_path = raw.split('"')[0].strip() if raw else raw
                            if not dll_path:
                                dll_path = raw.split()[0] if raw.split() else raw
                            server_kind = kind
                            # Inproc tem prioridade: se achou, para.
                            if kind == "inproc":
                                break
                            # Se só LocalServer, continua buscando Inproc
                            # (já vai sobrescrever se achar Inproc depois —
                            # ordem do loop coloca Inproc primeiro).
                            break
                    finally:
                        winreg.CloseKey(inproc)
                except OSError:
                    continue

            if not dll_path:
                continue

            dll_low = os.path.expandvars(dll_path).lower().replace("/", "\\")
            base_name = os.path.basename(dll_low.split(" -")[0].strip().strip('"'))

            # Whitelist: paths do sistema
            if any(dll_low.startswith(p) for p in _LEGIT_COM_PATH_PREFIXES):
                continue

            # Whitelist: AppData de apps conhecidos
            if any(pat in dll_low for pat in _TRUSTED_APPDATA_PATTERNS):
                continue

            # LocalServer32 de apps conhecidos (Code.exe toast etc.) = não flaggar
            if server_kind == "local" and base_name in _LEGIT_LOCALSERVER_BASENAMES:
                continue

            # Se o DLL/exe existe: MEDIUM (pode ser legítimo obscuro).
            # Se não existe: HIGH (hijack órfão).
            # LocalServer32 genérico (app desconhecido em user-path) = LOW
            # — muito ruído de IDEs/toasts; só sobe com keyword/CLSID crítico.
            dll_exists = False
            try:
                check_path = os.path.expandvars(dll_path.split(" -")[0].strip().strip('"'))
                dll_exists = os.path.isfile(check_path)
            except OSError:
                pass

            hijack_of = _COMMONLY_HIJACKED_CLSIDS.get(clsid.lower())
            if server_kind == "local" and not hijack_of:
                severity = "low"
            else:
                severity = "high" if not dll_exists else "medium"
            if hijack_of:
                severity = "critical"

            # Matched keyword no path do DLL
            kw, sev = matching.match_keyword(dll_path)
            matched = kw or "com-user-hijack"
            if kw:
                severity = "high"

            # LocalServer32 sem keyword e sem CLSID crítico e severity low:
            # ainda reporta como contexto (meta) pra não poluir veredito.
            meta = server_kind == "local" and not kw and not hijack_of

            items.append(_item(
                label=f"[COM] {clsid} → {os.path.basename(dll_path.split()[0] if dll_path else '')}",
                detail=(f"CLSID: {clsid}\n"
                        f"Server: {server_kind or '?'}\n"
                        f"Path: {dll_path}\n"
                        f"Existe: {dll_exists}\n"
                        + (f"Hijack de {hijack_of}\n" if hijack_of else "")
                        + ("LocalServer32 em user-path (toast/protocol handler) "
                           "— comum em IDEs; InprocServer32 seria mais grave.\n"
                           if server_kind == "local" else
                           "Registrado em HKCU (sem admin necessário). HKCU tem "
                           "precedência sobre HKCR = DLL do usuário substitui o "
                           "componente do sistema pra processos do próprio user.")),
                severity=severity, matched=matched, meta_only=meta,
            ))
    finally:
        winreg.CloseKey(root)

    return _result(name, desc, items)


ALL_HIJACK_SCANNERS = [
    scan_ifeo_hijack,
    scan_com_user_hijack,
]
