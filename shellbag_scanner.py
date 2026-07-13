"""
Artefatos de navegação do Windows Shell — sobrevivem a cleaners populares.

  - ShellBags: HKCU\\...\\Shell\\BagMRU registra TODAS as pastas visitadas no
    Explorer (inclusive pastas já deletadas). Cheater que navegou até a pasta do
    executor e depois deletou? ShellBag continua lá. CCleaner não apaga por padrão.

  - AppCompatFlags: HKCU\\...\\AppCompatFlags\\Layers registra flags de
    compatibilidade em executáveis (RunAsAdmin, RunAsHighest…). Se o cheat está
    aqui, ele foi configurado explicitamente pelo usuário para rodar.
"""

from models import _result, _item
import os
import struct

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# Chaves ShellBag em ambos os hives (Win 8+ tem as duas localizações).
_SHELLBAG_ROOTS = [
    (r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU", "HKCU-Classic"),
    (r"Software\Microsoft\Windows\Shell\BagMRU", "HKCU-Modern"),
]

_APPCOMPAT_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"

# Máximo de subchaves a visitar na BagMRU (protege contra recursão infinita).
_MAX_BAGS = 2000


def _extract_strings_from_pidl(blob: bytes) -> list[str]:
    """
    Extrai strings de um blob PIDL (Shell Folder ID List).
    Estratégia resiliente: procura strings Unicode (UTF-16 LE) e ASCII com
    comprimento razoável, sem depender do parser PIDL completo.
    Falsos positivos de substring são filtrados pelo matching central depois.
    """
    found = []
    if not blob or len(blob) < 4:
        return found

    # UTF-16 LE: procura runs de (char, \x00) com len >= 4
    i = 0
    while i < len(blob) - 3:
        # Detecta início de possível string UTF-16 LE (printável no range 0x20-0x7e)
        if (0x20 <= blob[i] <= 0x7e) and blob[i + 1] == 0:
            start = i
            chars = []
            j = i
            while j < len(blob) - 1:
                c = blob[j]
                hi = blob[j + 1]
                if hi != 0 or c < 0x20 or c > 0x7e:
                    break
                chars.append(chr(c))
                j += 2
            if len(chars) >= 4:
                s = "".join(chars).strip()
                if s:
                    found.append(s)
                i = j
                continue
        i += 1

    return found


def _walk_bagmru(hive, key_path: str, depth: int = 0, visited: list = None) -> list[str]:
    """
    Percorre BagMRU recursivamente e extrai todas as strings de folder.
    Retorna lista de strings encontradas.
    """
    if visited is None:
        visited = []
    if len(visited) >= _MAX_BAGS:
        return []

    strings = []
    try:
        key = winreg.OpenKey(hive, key_path)
    except OSError:
        return strings

    try:
        # Lê todos os valores binários desta chave
        i = 0
        while True:
            try:
                name, data, typ = winreg.EnumValue(key, i)
                i += 1
            except OSError:
                break
            # Valores numéricos (MRUListEx, etc.) — pula
            if typ == winreg.REG_BINARY and isinstance(data, (bytes, bytearray)):
                for s in _extract_strings_from_pidl(bytes(data)):
                    strings.append(s)

        # Navega subchaves (cada uma é uma pasta filha)
        j = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, j)
                j += 1
            except OSError:
                break
            if len(visited) >= _MAX_BAGS:
                break
            visited.append(1)
            sub_path = f"{key_path}\\{subkey_name}"
            strings.extend(_walk_bagmru(hive, sub_path, depth + 1, visited))
    finally:
        winreg.CloseKey(key)

    return strings


def scan_shellbag() -> dict:
    """
    Lê as ShellBags do Windows (BagMRU). Registra TODAS as pastas visitadas
    no Explorer — mesmo que a pasta já tenha sido deletada depois. Cheater que
    navega pra pasta do executor e depois deleta ainda deixa rastro aqui.
    CCleaner não apaga ShellBags por padrão.
    Requer apenas acesso HKCU (sem admin).
    """
    name = "ShellBags (histórico de pastas)"
    desc = "Pastas navegadas no Explorer (persiste mesmo após deleção)"

    if not HAS_WINREG:
        return _result(name, desc, [], error="winreg indisponível")

    import matching

    all_strings: set[str] = set()
    for key_path, _label in _SHELLBAG_ROOTS:
        for s in _walk_bagmru(winreg.HKEY_CURRENT_USER, key_path):
            all_strings.add(s)

    if not all_strings:
        return _result(name, desc, [])

    items = []
    seen_kw: set[str] = set()
    for s in sorted(all_strings):
        kw, sev = matching.match_keyword(s)
        if not kw:
            continue
        dedup = (kw, s[:60])
        if dedup in seen_kw:
            continue
        seen_kw.add(dedup)
        items.append(_item(
            label=f"Pasta visitada: {s}",
            detail=(f"ShellBag: pasta '{s}' foi navegada no Explorer. "
                    f"O registro persiste mesmo após deleção da pasta e "
                    f"não é apagado por cleaners comuns."),
            severity=sev, matched=kw,
        ))

    return _result(name, desc, items)


# ============================ AppCompatFlags ============================

def scan_appcompat_flags() -> dict:
    """
    HKCU\\...\\AppCompatFlags\\Layers: flags de compatibilidade em executáveis.
    Quando um exe tem flags aqui, o usuário configurou manualmente (clique
    direito → Propriedades → Compatibilidade) ou um instalador gravou.
    Encontrar um executor conhecido aqui = confirmação de execução intencional.
    Requer apenas HKCU (sem admin).
    """
    name = "AppCompatFlags (modo de compatibilidade)"
    desc = "Executáveis com flags de compatibilidade configurados pelo usuário"

    if not HAS_WINREG:
        return _result(name, desc, [], error="winreg indisponível")

    import matching

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _APPCOMPAT_KEY)
    except OSError:
        return _result(name, desc, [])

    items = []
    try:
        i = 0
        while True:
            try:
                exe_path, flags, _ = winreg.EnumValue(key, i)
                i += 1
            except OSError:
                break
            if not isinstance(exe_path, str):
                continue

            # Checa o exe_path e também o basename
            basename = os.path.basename(exe_path)
            kw, sev = matching.match_keyword(exe_path) or matching.match_keyword(basename)
            if not kw:
                kw2, sev2 = matching.match_keyword(basename)
                if kw2:
                    kw, sev = kw2, sev2

            if not kw:
                continue

            items.append(_item(
                label=f"[AppCompat] {basename}",
                detail=(f"Path: {exe_path}\n"
                        f"Flags: {flags}\n"
                        f"Executável encontrado nas flags de compatibilidade do Windows. "
                        f"Indica que foi executado explicitamente (configura pelo usuário "
                        f"ou pelo próprio instalador do cheat)."),
                severity=sev, matched=kw,
            ))
    finally:
        winreg.CloseKey(key)

    return _result(name, desc, items)


ALL_SHELLBAG_SCANNERS = [
    scan_shellbag,
    scan_appcompat_flags,
]
