"""
Streamproof / SetWindowDisplayAffinity — cheat oculto de screen capture.

O Windows tem uma API: SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE).
Quando aplicada a uma janela, ela some de:
  - Screenshots (Snipping Tool, Win+Shift+S)
  - OBS Studio, Discord Screen Share
  - PrintScreen
  - Ferramentas de acessibilidade

Winter Bypass, Solara e outros cheats de UI usam isso pra ficar INVISÍVEIS
durante screenshare — a janela do menu do cheat existe, tem título ("Winter
Bypass", "Solara"), consome memória — mas NÃO aparece na captura.

Detecção:
Iteramos janelas visíveis via EnumWindows, chamamos GetWindowDisplayAffinity
em cada. Se retorna WDA_EXCLUDEFROMCAPTURE (0x11) ou WDA_MONITOR (0x1) numa
janela cujo processo NÃO é DRM/Netflix/browser secure video = red flag.

Whitelist:
  - Netflix / streaming legítimos usam pra proteger conteúdo DRM
  - Alguns password managers usam
  - Nada disso deveria aparecer numa sessão de SS de Roblox

Requer: user context (as janelas são do session atual).
"""

from models import _result, _item
import ctypes
from ctypes import wintypes


try:
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _HAS_USER32 = True
except OSError:
    _HAS_USER32 = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# WDA constants
WDA_NONE = 0x00
WDA_MONITOR = 0x01
WDA_EXCLUDEFROMCAPTURE = 0x11

# Processos legítimos que podem legitimamente usar streamproof
_LEGIT_STREAMPROOF_PROCESSES = frozenset({
    # DRM / streaming apps
    "netflix.exe", "spotify.exe", "primevideo.exe", "hulu.exe",
    "disneyplus.exe", "youtubemusic.exe", "appletv.exe",
    # Browsers com secure video playback
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "opera.exe", "operagx.exe", "vivaldi.exe",
    # Password managers
    "1password.exe", "bitwarden.exe", "keepass.exe", "keepassxc.exe",
    "lastpass.exe", "dashlane.exe",
    # Meetings apps (proteção de compartilhamento)
    "teams.exe", "ms-teams.exe", "zoom.exe", "webex.exe", "slack.exe",
    "discord.exe", "discordcanary.exe", "discordptb.exe",
    "obs64.exe", "obs32.exe",  # OBS pode ter overlay
    "slobs.exe", "streamlabs obs.exe",
    # Windows components
    "explorer.exe", "shellexperiencehost.exe", "searchapp.exe",
    "startmenuexperiencehost.exe", "textinputhost.exe",
    "systemsettings.exe", "widgetservice.exe", "widgets.exe",
    "lockapp.exe", "logonui.exe", "credentialuibroker.exe",
    "sechealthui.exe",  # Windows Security UI
    # Xbox / Game Bar (Win11 sempre presente)
    "gamebar.exe", "gamebarft.exe", "gamebarpresencewriter.exe",
    "xboxpcapp.exe", "xboxpcappft.exe",
    # Copilot (Win11 24H2+)
    "copilot.exe", "microsoftcopilot.exe", "windowscopilot.exe",
    # NVIDIA overlays / GeForce Experience
    "nvidia share.exe", "nvcontainer.exe",
    "nvidia geforce experience.exe", "nvcp.exe",
    # AV / EDR proteções contra screen scraping
    "windefend.exe", "msmpeng.exe", "securityhealthservice.exe",
})


if _HAS_USER32:
    _EnumWindows = _user32.EnumWindows
    _EnumWindows.argtypes = [
        ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM),
        wintypes.LPARAM,
    ]
    _EnumWindows.restype = wintypes.BOOL

    _IsWindowVisible = _user32.IsWindowVisible
    _IsWindowVisible.argtypes = [wintypes.HWND]
    _IsWindowVisible.restype = wintypes.BOOL

    _GetWindowThreadProcessId = _user32.GetWindowThreadProcessId
    _GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    _GetWindowThreadProcessId.restype = wintypes.DWORD

    _GetWindowTextLengthW = _user32.GetWindowTextLengthW
    _GetWindowTextLengthW.argtypes = [wintypes.HWND]
    _GetWindowTextLengthW.restype = ctypes.c_int

    _GetWindowTextW = _user32.GetWindowTextW
    _GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    _GetWindowTextW.restype = ctypes.c_int

    _GetWindowDisplayAffinity = _user32.GetWindowDisplayAffinity
    _GetWindowDisplayAffinity.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    _GetWindowDisplayAffinity.restype = wintypes.BOOL


def _get_window_title(hwnd) -> str:
    length = _GetWindowTextLengthW(hwnd)
    if length <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    _GetWindowTextW(hwnd, buf, length + 1)
    return buf.value


def _get_process_name_from_hwnd(hwnd) -> tuple[int, str]:
    pid = wintypes.DWORD(0)
    _GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value == 0 or not HAS_PSUTIL:
        return pid.value, ""
    try:
        proc = psutil.Process(pid.value)
        return pid.value, (proc.name() or "").lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return pid.value, ""


def scan_streamproof_windows() -> dict:
    """
    Enumera janelas visíveis do usuário e verifica GetWindowDisplayAffinity.
    Janela com WDA_EXCLUDEFROMCAPTURE cujo processo NÃO é de streaming/DRM
    conhecido = quase certo cheat de UI usando streamproof (Winter, Solara).
    """
    name = "Streamproof (janelas ocultas de captura)"
    desc = ("Janelas usando SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) — "
            "cheats de UI (Winter, Solara) usam pra sumir de screenshare/OBS.")

    if not _HAS_USER32:
        return _result(name, desc, [], error="user32 indisponível (não-Windows?)")

    hits: list[tuple[int, str, str, int]] = []  # (hwnd, title, proc_name, pid)

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def _enum_proc(hwnd, _lparam):
        try:
            if not _IsWindowVisible(hwnd):
                return True
            affinity = wintypes.DWORD(0)
            ok = _GetWindowDisplayAffinity(hwnd, ctypes.byref(affinity))
            if not ok:
                return True
            if affinity.value not in (WDA_MONITOR, WDA_EXCLUDEFROMCAPTURE):
                return True
            title = _get_window_title(hwnd)
            pid, pname = _get_process_name_from_hwnd(hwnd)
            hits.append((int(hwnd), title, pname, pid))
        except Exception:
            pass
        return True

    try:
        _EnumWindows(_enum_proc, 0)
    except OSError as e:
        return _result(name, desc, [], error=f"EnumWindows falhou: {e}")

    items = []
    for hwnd, title, pname, pid in hits:
        # Whitelist: DRM, browser, meetings
        if pname in _LEGIT_STREAMPROOF_PROCESSES:
            continue
        # Janela sem título vinda de browser normalmente é DRM tab
        if not title and pname in {"chrome.exe", "msedge.exe"}:
            continue

        # Match keyword em title ou pname
        import matching
        kw, _sev = matching.match_keyword(title) or matching.match_keyword(pname)
        if not kw:
            kw2, _ = matching.match_keyword(pname)
            if kw2:
                kw = kw2

        matched = f"streamproof:{kw}" if kw else "streamproof-unknown"
        # Match de keyword = critical. Sem match mas streamproof em processo
        # não-legítimo = high (é forte anti-SS por si só).
        severity = "critical" if kw else "high"

        items.append(_item(
            label=f"[Streamproof] {title or '(sem título)'} ({pname or '?'})",
            detail=(f"HWND: {hex(hwnd)}\n"
                    f"PID: {pid}\n"
                    f"Processo: {pname or '(desconhecido)'}\n"
                    f"Título: {title or '(vazio)'}\n"
                    f"SetWindowDisplayAffinity ativo com WDA_EXCLUDEFROMCAPTURE. "
                    f"A janela existe, tem estado visível no OS, mas NÃO aparece "
                    f"em screenshots, OBS, ou screen share. Winter Bypass e "
                    f"Solara usam isso pra ficarem invisíveis na SS."),
            severity=severity, matched=matched,
        ))

    return _result(name, desc, items)


ALL_STREAMPROOF_SCANNERS = [
    scan_streamproof_windows,
]
