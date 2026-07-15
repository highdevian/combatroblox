"""
Scanner de regras do Windows Firewall — anti-bypass e C2 silencioso.

Cheaters criam regras de firewall pra:
  1) Permitir que o executor faça conexões de saída sem popup (outbound Allow)
  2) Bloquear telemetria do Roblox / anti-cheat (inbound/outbound Block de roblox.com)
  3) Garantir que o reader externo acesse o servidor de licença (KeyAuth, etc.)

Lemos via registro (HKLM\\...\\FirewallRules) — mais rápido que PowerShell e
não precisa de prompt de elevação pra enumerar. Cada valor é uma string no formato:
  v2.30|Action=Allow|Active=TRUE|Dir=Out|...App=C:\\Users\\...\\cheat.exe|...
"""

from .models import _result, _item
import os
import re

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

from . import matching
_FIREWALL_KEYS = [
    (r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
     r"\FirewallPolicy\FirewallRules", "Perfil ativo"),
    (r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
     r"\FirewallPolicy\StandardProfile\AuthorizedApplications\List", "Perfil padrão"),
]

# Caminhos que nunca são suspeitos (Windows, Program Files, etc.)
_LEGIT_APP_PREFIXES = (
    r"c:\windows\\",
    r"c:\program files\\",
    r"c:\program files (x86)\\",
    r"c:\programdata\microsoft\\",
    r"%systemroot%\\",
    r"%programfiles%\\",
)

# Basenames de apps legítimos que moram em AppData/Users e criam Allow
# outbound (Voicemod, Discord, Steam overlay, OBS…). Não são KeyAuth.
_LEGIT_APP_BASENAMES = frozenset({
    "voicemod.exe", "voicemodsteamwrapper.exe", "voicemoddesktop.exe",
    "discord.exe", "discordcanary.exe", "discordptb.exe",
    "steam.exe", "steamwebhelper.exe", "steamerrorreporter.exe",
    "spotify.exe", "obs64.exe", "obs32.exe", "obs.exe",
    "streamlabs obs.exe", "slobs.exe",
    "nvcontainer.exe", "nvidia share.exe", "nvidia web helper.exe",
    "nvidia geforce experience.exe",
    "epicgameslauncher.exe", "fortniteclient-win64-shipping.exe",
    "epicwebhelper.exe", "epicgameslauncher-mac-shipping.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "opera.exe", "operagx.exe", "vivaldi.exe",
    "slack.exe", "teams.exe", "ms-teams.exe", "zoom.exe",
    "code.exe", "cursor.exe", "devenv.exe",
    "code - insiders.exe", "windsurf.exe", "antigravity.exe",
    "wallpaperengine.exe", "rainmeter.exe",
    "overwolf.exe", "medal.exe", "geforcenow.exe",
    # Roblox (rodam de %LOCALAPPDATA%\Roblox\Versions\version-XXXX\)
    "robloxplayerbeta.exe", "robloxplayerlauncher.exe",
    "robloxstudiobeta.exe", "roblox.exe",
    "bloxstrap.exe",  # bootstrapper open-source legítimo
    # Riot / Battle.net / Origin / Ubisoft / Rockstar (rodam de user path)
    "riotclientservices.exe", "riotclientux.exe", "riotclientcrashhandler.exe",
    "valorant.exe", "valorant-win64-shipping.exe",
    "leagueclient.exe", "leagueclientux.exe",
    "battle.net.exe", "agent.exe",
    "origin.exe", "eadesktop.exe", "ealauncher.exe",
    "upc.exe", "ubisoftconnect.exe", "ubisoftgamelauncher.exe",
    "rockstargameslauncher.exe", "launcher.exe", "playgtav.exe",
    # Squirrel-based updaters (Electron apps)
    "update.exe", "squirrel.exe", "squirrelsetup.exe",
    # Comms / social
    "telegram.exe", "whatsapp.exe", "signal.exe",
    "github desktop.exe", "githubdesktop.exe",
    "notion.exe", "notion helper.exe",
    "dropbox.exe", "dropboxupdate.exe",
    # Devs & tools (às vezes rodam de user path)
    "python.exe", "pythonw.exe", "node.exe", "npm.exe",
    "docker desktop.exe", "docker.exe",
    "insomnia.exe", "postman.exe",
    # Anti-cheat / anti-spy legítimos
    "vgc.exe", "vgtray.exe",  # Vanguard
    "faceit.exe", "faceitclient.exe",
    # AV / EDR user-mode (raro em user path mas acontece)
    "malwarebytes.exe", "mbam.exe",
})

_RE_APP = re.compile(r"[Aa]pp=([^|]+)")
_RE_ACTION = re.compile(r"[Aa]ction=([^|]+)")
_RE_DIR = re.compile(r"[Dd]ir=([^|]+)")
_RE_ACTIVE = re.compile(r"[Aa]ctive=([^|]+)")
_RE_NAME = re.compile(r"[Nn]ame=([^|]+)")
_RE_RM = re.compile(r"[Rr]emisite=([^|]+)")

# Domínios e IPs do Roblox — bloquear estes no firewall = red flag forte
_ROBLOX_DOMAINS_IN_RULE = (
    "roblox", "rbx.com", "rbxcdn", "rbxstatic", "bloxstrap",
)


def _parse_fw_rule(value_name: str, raw: str) -> dict | None:
    """Parseia uma regra de firewall do registro e retorna campos relevantes ou None."""
    if not isinstance(raw, str):
        return None

    active_m = _RE_ACTIVE.search(raw)
    if active_m and active_m.group(1).upper() != "TRUE":
        return None

    app_m = _RE_APP.search(raw)
    app = app_m.group(1).strip() if app_m else ""
    app_expanded = os.path.expandvars(app).lower().replace("/", "\\")

    action_m = _RE_ACTION.search(raw)
    action = action_m.group(1).strip().upper() if action_m else ""

    dir_m = _RE_DIR.search(raw)
    direction = dir_m.group(1).strip().upper() if dir_m else ""

    name_m = _RE_NAME.search(raw)
    rule_name = name_m.group(1).strip() if name_m else value_name

    return {
        "app": app, "app_lower": app_expanded,
        "action": action, "direction": direction, "rule_name": rule_name,
        "raw": raw[:300],
    }


def scan_firewall_rules() -> dict:
    """
    Lê as regras do Windows Firewall diretamente do registro (HKLM).
    Flagga:
      • Regra Allow outbound pra exe em pasta de usuário (executor querendo sair pra
        KeyAuth / servidor de licença sem prompt de UAC/firewall)
      • Regra Block pra domínios do Roblox (bloqueio de telemetria / anti-cheat)
      • Regra com nome de executor conhecido
    Requer admin pra ler HKLM\\...\\FirewallPolicy\\FirewallRules.
    """
    name = "Regras do Firewall"
    desc = "Regras Allow/Block suspeitas no Windows Firewall (executores e Roblox)"

    if not HAS_WINREG:
        return _result(name, desc, [], error="winreg indisponível")

    items = []

    for key_path, _label in _FIREWALL_KEYS:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        except OSError:
            continue

        try:
            idx = 0
            while True:
                try:
                    val_name, raw, _ = winreg.EnumValue(key, idx)
                    idx += 1
                except OSError:
                    break

                rule = _parse_fw_rule(val_name, raw if isinstance(raw, str) else "")
                if not rule:
                    continue

                app = rule["app"]
                app_low = rule["app_lower"]
                action = rule["action"]
                direction = rule["direction"]
                rule_name = rule["rule_name"]

                # 1. Nome da regra ou app contém keyword de executor
                kw, sev = matching.match_keyword(rule_name) or matching.match_keyword(app)
                if not kw:
                    kw2, sev2 = matching.match_keyword(app)
                    if kw2:
                        kw, sev = kw2, sev2

                if kw:
                    items.append(_item(
                        label=f"[Firewall] {rule_name} ({action} {direction})",
                        detail=(f"Regra com nome de executor conhecido:\n"
                                f"App: {app}\nAção: {action} | Direção: {direction}\n"
                                f"Executores adicionam regras Allow pra garantir acesso "
                                f"ao servidor de licença (KeyAuth) sem ser bloqueados."),
                        severity=sev, matched=kw,
                    ))
                    continue

                # 2. App em pasta de usuário com Allow outbound
                if app and action == "ALLOW" and direction in ("OUT", ""):
                    if not any(app_low.startswith(p) for p in _LEGIT_APP_PREFIXES):
                        if any(s in app_low for s in (
                            "\\users\\", "\\temp\\", "\\appdata\\", "\\downloads\\"
                        )):
                            base = os.path.basename(app_low)
                            if base in _LEGIT_APP_BASENAMES:
                                continue
                            items.append(_item(
                                label=f"[Firewall] Allow outbound: {os.path.basename(app)}",
                                detail=(f"Regra Allow de saída pra executável em pasta de "
                                        f"usuário:\nApp: {app}\n"
                                        f"Executores criam esta regra pra acessar KeyAuth/"
                                        f"servidor de licença sem bloquear."),
                                severity="medium", matched="firewall-user-allow",
                            ))

                # 3. Regra bloqueando Roblox / anti-cheat
                if action == "BLOCK":
                    raw_low = rule["raw"].lower()
                    for dom in _ROBLOX_DOMAINS_IN_RULE:
                        if dom in raw_low or dom in app_low:
                            items.append(_item(
                                label=f"[Firewall] BLOCK Roblox: {rule_name}",
                                detail=(f"Regra de BLOQUEIO atingindo telemetria do Roblox:\n"
                                        f"Regra: {rule_name}\nApp/domain: {dom}\n"
                                        f"Bloquear roblox.com/rbxcdn no firewall = "
                                        f"silenciar telemetria ou anti-cheat do cliente."),
                                severity="high", matched="firewall-block-roblox",
                            ))
                            break
        finally:
            winreg.CloseKey(key)

    return _result(name, desc, items)


ALL_FIREWALL_SCANNERS = [
    scan_firewall_rules,
]
