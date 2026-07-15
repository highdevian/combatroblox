"""
Windows Clipboard History — texto copiado/colado (não só digitado).

Diferente de scan_powershell_history (ConsoleHost_history = o que FOI
DIGITADO no PS): este pega o que o cheater COPIOU — URL do browser, one-liner
`iex (irm …)`, path de executor — inclusive antes de executar.

Fontes (sem admin, HKCU / perfil do user):
  1) Disco: %LocalAppData%\\Microsoft\\Windows\\Clipboard\\{HistoryData,Pinned}
     Pastas GUID com blobs binários; extrai strings UTF-16 LE e UTF-8.
  2) Live: conteúdo atual do clipboard (CF_UNICODETEXT) via Win32.

Nota: itens NÃO-pinned do histórico costumam morrer no reboot (só memória).
Pinned + residual em disco + clipboard atual ainda capturam o fluxo de SS
ao vivo (operador pede pra copiar/colar; cheater colou loader no chat).
"""

from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime

from .models import _result, _item, _fmt_ts

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

try:
    from . import win_tools
    HAS_WIN_TOOLS = True
except ImportError:
    HAS_WIN_TOOLS = False

# Reaproveita a mesma heurística de red-flag do histórico de PS/RunMRU
# (domínios, iex/irm, keyword com word-boundary, anti-signature-list).
from .command_history import _match_in_line, _is_signature_list


_CLIPBOARD_ROOT = os.path.join(
    "%LOCALAPPDATA%", "Microsoft", "Windows", "Clipboard"
)
_SUBDIRS = ("HistoryData", "Pinned")

# Limites de perf (ROADMAP: scanner < 3s)
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_TEXT_CHARS = 8192
_MAX_ITEMS = 40
_MIN_STRING_LEN = 8
_MAX_STRINGS_PER_FILE = 40
_MAX_DISK_ENTRIES = 250

# Hits fracos que no *clipboard* viram ruído (gente copia tutorial o tempo todo).
# No PS history fazem sentido (comando digitado); aqui exigimos contexto extra
# ou simplesmente ignoramos se forem o único sinal.
_WEAK_NETWORK_MATCHES = frozenset({"curl ", "wget "})

# Runs de texto legível em blobs
_UTF16_RUN = re.compile(
    rb"(?:[\x20-\x7e]\x00){%d,}" % _MIN_STRING_LEN
)
_UTF8_RUN = re.compile(
    rb"[\x20-\x7e]{%d,}" % _MIN_STRING_LEN
)


def _powershell() -> str:
    if HAS_WIN_TOOLS:
        return win_tools.powershell()
    return "powershell.exe"


def _clipboard_root() -> str:
    return os.path.expandvars(_CLIPBOARD_ROOT)


def _history_enabled() -> bool | None:
    """True/False se a chave existir; None se não der pra ler."""
    if not HAS_WINREG:
        return None
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Clipboard",
        ) as k:
            val, _ = winreg.QueryValueEx(k, "EnableClipboardHistory")
            return bool(int(val))
    except (OSError, ValueError, TypeError):
        return None


def _extract_strings(blob: bytes) -> list[str]:
    """Extrai runs de texto de um blob (UTF-16 LE e UTF-8 ASCII)."""
    found: list[str] = []
    seen: set[str] = set()

    def _add(s: str) -> None:
        s = (s or "").strip()
        if len(s) < _MIN_STRING_LEN:
            return
        # Normaliza whitespace pra dedup
        key = " ".join(s.split())
        if key.lower() in seen:
            return
        seen.add(key.lower())
        found.append(key[:_MAX_TEXT_CHARS])

    for m in _UTF16_RUN.finditer(blob):
        if len(found) >= _MAX_STRINGS_PER_FILE:
            break
        try:
            s = m.group(0).decode("utf-16-le", errors="ignore")
        except Exception:
            continue
        _add(s)

    for m in _UTF8_RUN.finditer(blob):
        if len(found) >= _MAX_STRINGS_PER_FILE:
            break
        try:
            s = m.group(0).decode("ascii", errors="ignore")
        except Exception:
            continue
        _add(s)

    return found


def _iter_disk_entries() -> list[tuple[str, str, float]]:
    """Lista (text, source_path, mtime) de arquivos em HistoryData/Pinned."""
    root = _clipboard_root()
    out: list[tuple[str, str, float]] = []
    if not os.path.isdir(root):
        return out

    for sub in _SUBDIRS:
        if len(out) >= _MAX_DISK_ENTRIES:
            break
        base = os.path.join(root, sub)
        if not os.path.isdir(base):
            continue
        for dirpath, _dirnames, filenames in os.walk(base):
            if len(out) >= _MAX_DISK_ENTRIES:
                break
            for fn in filenames:
                if len(out) >= _MAX_DISK_ENTRIES:
                    break
                path = os.path.join(dirpath, fn)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if st.st_size <= 0 or st.st_size > _MAX_FILE_BYTES:
                    continue
                try:
                    with open(path, "rb") as fh:
                        blob = fh.read(_MAX_FILE_BYTES)
                except OSError:
                    continue
                for text in _extract_strings(blob):
                    out.append((text, path, st.st_mtime))
                    if len(out) >= _MAX_DISK_ENTRIES:
                        break
    return out


def _read_clipboard_win32() -> str | None:
    """Lê CF_UNICODETEXT do clipboard atual. None se vazio/indisponível."""
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    CF_UNICODETEXT = 13

    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
    user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL

    if not user32.OpenClipboard(None):
        return None
    try:
        if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
            return None
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return None
        ptr = kernel32.GlobalLock(handle)
        if not ptr:
            return None
        try:
            text = ctypes.wstring_at(ptr)
        finally:
            kernel32.GlobalUnlock(handle)
        text = (text or "").strip()
        return text[:_MAX_TEXT_CHARS] if text else None
    except Exception:
        # Access violation / tipo errado / clipboard lock — nunca derruba o scan.
        return None
    finally:
        try:
            user32.CloseClipboard()
        except Exception:
            pass


def _read_clipboard_powershell() -> str | None:
    """Fallback: Get-Clipboard (só item atual)."""
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$t = Get-Clipboard -Raw -ErrorAction SilentlyContinue;"
        "if ($t) { Write-Output $t }"
    )
    try:
        result = subprocess.run(
            [_powershell(), "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (result.stdout or "").strip()
    return text[:_MAX_TEXT_CHARS] if text else None


def _read_current_clipboard() -> str | None:
    text = _read_clipboard_win32()
    if text:
        return text
    return _read_clipboard_powershell()


def _is_weak_clipboard_hit(matched: str, text: str) -> bool:
    """True = ruído típico de clipboard; ignorar.

    Clipboard é bem mais barulhento que PS history: dev copia tutorial de
    curl/wget, snippet .NET com DownloadString, etc. Exigimos contexto
    extra pra esses tokens fracos — domínio suspeito ou família download+exec.
    """
    m_raw = (matched or "").lower()
    # NÃO strip cego: matches do PS vêm com espaço final ("curl ", "iex ").
    # Mas "iex  + krnl.cat" (composto) é sempre forte.
    if "+" in m_raw:
        return False

    m = m_raw.strip()
    head = m.split()[0] if m else ""
    low = (text or "").lower()

    # curl/wget sozinhos (severity low) — tutorial Docker/Linux o tempo todo
    if head in ("curl", "wget") or m_raw in _WEAK_NETWORK_MATCHES:
        from . import matching
        from .database import SUSPICIOUS_DOMAINS
        if any(matching.domain_in_text(d, low) for d in SUSPICIOUS_DOMAINS):
            return False
        if any(x in low for x in (
            "iex", "irm ", "invoke-expression", "downloadstring",
            "invoke-webrequest", "iwr ",
        )):
            return False
        return True

    # "downloadstring" solto (ex.: `function DownloadString()` em docs .NET)
    if m == "downloadstring" or head == "downloadstring":
        if not any(x in low for x in (
            "http://", "https://", "webclient", "iex", "irm ",
            "invoke-", "net.webclient", "downloadfile",
        )):
            return True

    # Fragmentos de download/exec SEM URL = snippet incompleto copiado
    if head in (
        "invoke-webrequest", "iwr", "irm", "invoke-restmethod",
        "invoke-expression", "iex",
    ) or m_raw.rstrip() in (
        "invoke-webrequest", "iwr", "irm", "invoke-restmethod",
        "invoke-expression", "iex", "iex(",
    ):
        if "http://" not in low and "https://" not in low and "www." not in low:
            if not any(x in low for x in ("downloadstring", "webclient", "bitstransfer")):
                return True

    return False


def _classify(text: str) -> tuple[str | None, str | None]:
    """(matched, severity) ou (None, None)."""
    if not text or len(text.strip()) < 4:
        return None, None
    if _is_signature_list(text):
        return None, None
    # Meta do próprio Telador / docs
    low = text.lower()
    if any(t in low for t in (
        "telador", "combatroblox", "scan_clipboard", "changelog",
        "clipboard_history_scanner",
    )):
        return None, None
    matched, sev = _match_in_line(text)
    if matched and _is_weak_clipboard_hit(matched, text):
        return None, None
    return matched, sev


def scan_clipboard_history() -> dict:
    """
    Varre histórico em disco (HistoryData/Pinned) + clipboard atual.
    Flagga texto com executor keyword, domínio suspeito ou iex/irm/etc.
    """
    name = "Clipboard History"
    desc = ("Texto copiado/colado (histórico em disco + clipboard atual). "
            "Pega URL de loader e one-liner iex/irm que o PS history não vê.")

    items = []
    seen_text: set[str] = set()

    # --- 1) Disco ---
    disk_entries = _iter_disk_entries()
    for text, path, mtime in disk_entries:
        if len(items) >= _MAX_ITEMS:
            break
        key = " ".join(text.split()).lower()
        if key in seen_text:
            continue
        matched, sev = _classify(text)
        if not matched:
            continue
        seen_text.add(key)
        pinned = "\\pinned\\" in path.lower().replace("/", "\\")
        where = "Pinned" if pinned else "HistoryData"
        preview = text if len(text) <= 240 else text[:240] + "…"
        items.append(_item(
            label=f"[Clipboard/{where}] {matched}",
            detail=(
                f"Match: {matched}\n"
                f"Fonte: {path}\n"
                f"Preview: {preview}\n"
                f"Item {'PINADO (sobrevive reboot)' if pinned else 'histórico em disco'}. "
                f"Clipboard history pega o que foi COPIADO — diferente do "
                f"PowerShell history (só o que foi digitado no PS)."
            ),
            severity=sev or "medium",
            matched=f"clipboard:{matched}",
            timestamp=_fmt_ts(mtime),
        ))

    # --- 2) Live (clipboard atual) ---
    current = _read_current_clipboard()
    if current and len(items) < _MAX_ITEMS:
        key = " ".join(current.split()).lower()
        if key not in seen_text:
            matched, sev = _classify(current)
            if matched:
                seen_text.add(key)
                preview = current if len(current) <= 240 else current[:240] + "…"
                items.append(_item(
                    label=f"[Clipboard/atual] {matched}",
                    detail=(
                        f"Match: {matched}\n"
                        f"Fonte: clipboard atual (CF_UNICODETEXT)\n"
                        f"Preview: {preview}\n"
                        f"Conteúdo presente AGORA no clipboard do user — "
                        f"útil em SS ao vivo (acabou de copiar loader/URL)."
                    ),
                    severity=sev or "medium",
                    matched=f"clipboard-live:{matched}",
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ))

    # --- Meta: histórico desligado / pasta vazia (contexto, não veredito) ---
    enabled = _history_enabled()
    root = _clipboard_root()
    if enabled is False:
        items.append(_item(
            label="[Clipboard] Histórico desativado",
            detail=(
                "HKCU\\Software\\Microsoft\\Clipboard\\EnableClipboardHistory=0. "
                "Sem histórico persistente o scanner só vê o clipboard atual. "
                "Desligar o histórico também é técnica de OPSEC (anti-SS)."
            ),
            severity="low",
            matched="clipboard-history-off",
            meta_only=True,
        ))
    elif not os.path.isdir(root) and not items:
        # Sem pasta e sem hit live — ambiente sem feature / limpo
        pass

    return _result(name, desc, items)


ALL_CLIPBOARD_SCANNERS = [
    scan_clipboard_history,
]
