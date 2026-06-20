"""
Detecção de Alternate Data Streams (ADS) — anti-forense de ocultação.

O NTFS permite que um arquivo carregue streams nomeados OCULTOS:
`notas.txt:cheat.exe`. O conteúdo do stream nomeado é invisível pro Explorer,
pro `dir` e pra maioria das ferramentas (só aparece com `dir /r` ou a API de
streams). Um cheater pode esconder o executor num ADS e rodar de lá via LOLBin —
sem o `.exe` aparecer no disco como arquivo normal.

Lê via FindFirstStreamW/FindNextStreamW (API oficial) + lê o conteúdo do stream
(o `open("arquivo:stream")` do Windows funciona). Whitelista os ADS LEGÍTIMOS
(`Zone.Identifier` = mark-of-the-web que TODO download tem, SmartScreen, etc.) e
só flagga quando há sinal de EXECUTÁVEL escondido: conteúdo com header MZ, nome
de executor conhecido, ou extensão de executável no nome do stream. ADS comum de
app (sem sinal executável) não dispara — FP ~zero.
"""

from models import _result, _item
import os
import ctypes
from ctypes import wintypes

import matching

try:
    _k32 = ctypes.windll.kernel32
    _k32.FindFirstStreamW.restype = wintypes.HANDLE
    _k32.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int,
                                      ctypes.c_void_p, wintypes.DWORD]
    _k32.FindNextStreamW.restype = wintypes.BOOL
    _k32.FindNextStreamW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _k32.FindClose.argtypes = [wintypes.HANDLE]
    HAS_WIN = True
except (AttributeError, OSError):
    HAS_WIN = False

_INVALID_HANDLE = ctypes.c_void_p(-1).value


class WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [
        ("StreamSize", wintypes.LARGE_INTEGER),
        ("cStreamName", wintypes.WCHAR * (260 + 36)),
    ]


# ADS LEGÍTIMOS comuns — NÃO são ocultação de cheat. Comparados em lowercase.
_BENIGN_STREAMS = {
    "",                          # stream default (::$DATA)
    "zone.identifier",          # mark-of-the-web: TODO arquivo baixado tem
    "smartscreen",
    "encryptable",
    "favicon",
    "com.dropbox.attrs",
    "com.dropbox.attributes",
    "com.apple.quarantine",
    "ms-properties",
    "wof",                      # Windows Overlay Filter (compressão transparente)
    "afp_afpinfo", "afp_resource",
}

# Extensões num nome de ADS que gritam "executável escondido".
_EXEC_EXT = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
             ".com", ".lua", ".luau", ".jar", ".hta")

# Onde procurar — pastas graváveis pelo usuário onde cheat costuma cair.
_SCAN_DIRS = [
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Documents",
    r"%TEMP%",
    r"%APPDATA%",
    r"%LOCALAPPDATA%\Temp",
]
_MAX_DEPTH = 2
_MAX_FILES = 20000  # cap de perf


def _parse_stream_name(raw: str) -> str:
    """':Zone.Identifier:$DATA' -> 'Zone.Identifier'; '::$DATA' -> '' (default)."""
    parts = (raw or "").split(":")
    return parts[1] if len(parts) >= 2 else ""


def _classify_stream(stream_name: str, has_mz: bool):
    """Retorna (severity, matched) se o ADS esconde executável; senão None.
    Núcleo testável (sem Win32). Só flagga sinal de executável — anti-FP."""
    base = (stream_name or "").lower().strip().split(":")[0]
    if base in _BENIGN_STREAMS:
        return None

    # Nome de executor conhecido no nome do stream = cravado
    kw, _sev = matching.match_keyword(stream_name)
    if kw:
        return "high", f"ads-executor:{kw}"

    # Conteúdo executável (header MZ) escondido num stream
    if has_mz:
        return "high", "ads-executavel"

    # Extensão de executável no nome do stream
    if base.endswith(_EXEC_EXT):
        return "high", "ads-exec-nome"

    # ADS desconhecido SEM sinal executável = não flagga (evita FP de app)
    return None


def _list_streams(path: str):
    """Retorna [(stream_name, size)] dos ADS NOMEADOS (exclui o ::$DATA default).
    Isolado do resto pra ser mockável."""
    if not HAS_WIN:
        return []
    out = []
    fsd = WIN32_FIND_STREAM_DATA()
    try:
        h = _k32.FindFirstStreamW(path, 0, ctypes.byref(fsd), 0)
    except OSError:
        return out
    if not h or h == _INVALID_HANDLE:
        return out
    try:
        while True:
            name = _parse_stream_name(fsd.cStreamName)
            if name:  # named ADS (default ::$DATA vira '')
                try:
                    size = int(fsd.StreamSize)
                except (ValueError, OverflowError):
                    size = 0
                out.append((name, size))
            if not _k32.FindNextStreamW(h, ctypes.byref(fsd)):
                break
    finally:
        _k32.FindClose(h)
    return out


def _stream_has_mz(path: str, stream_name: str) -> bool:
    """Lê os 2 primeiros bytes do stream — open('arquivo:stream') do Windows."""
    try:
        with open(f"{path}:{stream_name}", "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


def scan_alternate_data_streams() -> dict:
    """Varre arquivos em pastas de usuário procurando ADS que escondem
    executável (conteúdo MZ, nome de executor, ou extensão de exe no stream)."""
    if not HAS_WIN:
        return _result("Alternate Data Streams (ADS)",
                       "Executável escondido em stream NTFS oculto", [],
                       error="API de streams indisponível (não-Windows)")

    items = []
    seen = set()
    files_scanned = 0
    for raw in _SCAN_DIRS:
        d = os.path.expandvars(raw)
        if not os.path.isdir(d):
            continue
        for dirpath, dirnames, filenames in os.walk(d):
            if dirpath[len(d):].count(os.sep) > _MAX_DEPTH:
                dirnames[:] = []
                continue
            for f in filenames:
                files_scanned += 1
                if files_scanned > _MAX_FILES:
                    dirnames[:] = []
                    break
                full = os.path.join(dirpath, f)
                try:
                    streams = _list_streams(full)
                except Exception:
                    continue
                for name, size in streams:
                    has_mz = _stream_has_mz(full, name) if size >= 2 else False
                    res = _classify_stream(name, has_mz)
                    if not res:
                        continue
                    sev, matched = res
                    key = (full.lower(), name.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    items.append(_item(
                        label=f"Stream oculto (ADS): {f}:{name}",
                        detail=f"{full}:{name}  ({size} bytes)\n"
                               f"Arquivo carrega um Alternate Data Stream NTFS oculto com "
                               f"sinal de executável. ADS é invisível no Explorer e no 'dir' "
                               f"— esconder um executável num stream é ocultação anti-forense; "
                               f"o cheat roda de lá sem aparecer como arquivo no disco.",
                        severity=sev, matched=matched,
                    ))

    return _result("Alternate Data Streams (ADS)",
                   "Executável escondido em stream NTFS oculto (anti-forense)", items)


ALL_ADS_SCANNERS = [
    scan_alternate_data_streams,
]
