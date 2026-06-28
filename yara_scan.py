"""
Scan de assinatura BINÁRIA estilo YARA — pega o cheat pelo CONTEÚDO, não pelo nome.

O resto do Telador casa por nome/path/keyword (signatures.json) e varre SCRIPTS
(.lua/.luau/.txt) por API de exploit. O que faltava: olhar DENTRO dos binários
(.exe/.dll). Renomear o executor pra 'trabalho.exe' engana o match por nome — mas
não engana o conteúdo: se o binário carrega os SÍMBOLOS da API de exploit Luau
(getrawmetatable, hookmetamethod, newcclosure…), casa do mesmo jeito.

Regras no estilo YARA: cada regra é um conjunto de strings (ASCII/UTF-16) + uma
condição "N de N". Engine própria, sem dependência nativa — empacota no .exe igual
ao resto do projeto. (Hook p/ carregar .yar reais via yara-python fica pra v2.)

Anti-FP, três camadas:
  1. só varre pastas graváveis pelo usuário (Downloads/Desktop/Temp/Roblox) e só
     arquivos PE (header MZ), com caps de tamanho/quantidade;
  2. pula o PRÓPRIO telador.exe (ele embute essa mesma lista de símbolos);
  3. se o arquivo que casou está VALIDAMENTE ASSINADO, descarta — app legítimo
     que por acaso contém os símbolos (raríssimo) não vira veredito.

A regra-âncora (API de exploit Luau) é específica do ecossistema de executor de
Roblox — software legítimo praticamente nunca exporta essa superfície.
"""

from models import _result, _item
import os
import sys


# ============================ Engine ============================

def _wide(pattern: bytes) -> bytes:
    """Forma UTF-16LE (wide string do Windows) do padrão ASCII."""
    try:
        return pattern.decode("latin-1").encode("utf-16le")
    except Exception:
        return b""


def _count_matches(data: bytes, patterns: list[bytes]) -> int:
    """Quantos padrões DISTINTOS aparecem em `data` (ASCII ou UTF-16LE)."""
    n = 0
    for p in patterns:
        if not p:
            continue
        if p in data or (_wide(p) and _wide(p) in data):
            n += 1
    return n


def _match_rules(data: bytes, rules: list[dict]) -> list[dict]:
    """Núcleo puro (testável): regras cuja condição N-de-N é satisfeita."""
    hits = []
    for rule in rules:
        if _count_matches(data, rule["strings"]) >= rule["min_matches"]:
            hits.append(rule)
    return hits


# ============================ Regras ============================
# Strings em bytes ASCII. `min_matches` = quantas precisam bater (condição N-de-N).

BUILTIN_RULES: list[dict] = [
    {
        "name": "Executor Roblox (API de exploit Luau embutida)",
        "severity": "high",
        "matched": "yara:executor-luau-api",
        "why": "carrega os símbolos da API de exploit de Roblox (getrawmetatable, "
               "hookmetamethod, newcclosure, checkcaller…). Software legítimo não "
               "exporta essa superfície — é executor (ou a DLL injetora dele), "
               "mesmo com o arquivo renomeado.",
        "min_matches": 6,
        "strings": [
            b"getrawmetatable", b"hookmetamethod", b"hookfunction",
            b"newcclosure", b"checkcaller", b"iscclosure", b"islclosure",
            b"isexecutorclosure", b"getnamecallmethod", b"setreadonly",
            b"getgenv", b"getrenv", b"getsenv", b"getgc",
            b"getloadedmodules", b"getscripts", b"getconnections",
            b"setclipboard", b"is_synapse_function",
        ],
    },
    {
        "name": "Toolmarks de injetor / manual-mapper",
        "severity": "medium",
        "matched": "yara:injector-toolmarks",
        "why": "combina as APIs clássicas de injeção de código em outro processo "
               "(VirtualAllocEx + WriteProcessMemory + CreateRemoteThread…). "
               "Ferramenta legítima também usa, então isto sozinho é sinal, não "
               "prova — corrobora com outra fonte.",
        "min_matches": 5,
        "strings": [
            b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
            b"NtCreateThreadEx", b"RtlCreateUserThread", b"QueueUserAPC",
            b"LoadLibraryA", b"GetProcAddress", b"NtMapViewOfSection",
            b"SetThreadContext",
        ],
    },
]


# ============================ Alvos ============================

_SCAN_DIRS = [
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\Desktop",
    r"%TEMP%",
    r"%LOCALAPPDATA%\Temp",
    r"%LOCALAPPDATA%\Roblox",
]
_CANDIDATE_EXT = (".exe", ".dll", ".scr", ".node")
_MAX_DEPTH = 2
_MAX_FILES = 4000        # cap de quantidade
_MAX_READ = 64 * 1024 * 1024   # ignora binário gigante (instalador legítimo)


def _is_self(path: str) -> bool:
    """O próprio telador.exe embute a lista de símbolos — nunca se auto-flagga."""
    low = path.lower().replace("/", "\\")
    if "telador" in os.path.basename(low):
        return True
    try:
        own = os.path.realpath(sys.executable).lower()
        if own and os.path.realpath(path).lower() == own:
            return True
    except Exception:
        pass
    return False


def _read_bytes(path: str, cap: int) -> bytes:
    """Lê até `cap` bytes do arquivo; b'' em qualquer falha/grande demais."""
    try:
        if os.path.getsize(path) > cap:
            return b""
        with open(path, "rb") as fh:
            return fh.read(cap)
    except OSError:
        return b""


def _is_signed(path: str):
    """True/False/None — reusa o WinVerifyTrust do live_analysis (import tardio
    pra não criar dependência circular no import do módulo)."""
    try:
        import live_analysis
        return live_analysis._is_dll_signed(path)
    except Exception:
        return None


def _iter_candidate_files():
    """Caminhos de PE candidatos nas pastas de usuário, com caps de profundidade
    e quantidade. Isolado pra ser mockável nos testes."""
    seen = 0
    for raw in _SCAN_DIRS:
        d = os.path.expandvars(raw)
        if not os.path.isdir(d):
            continue
        for dirpath, dirnames, filenames in os.walk(d):
            if dirpath[len(d):].count(os.sep) > _MAX_DEPTH:
                dirnames[:] = []
                continue
            for f in filenames:
                if not f.lower().endswith(_CANDIDATE_EXT):
                    continue
                seen += 1
                if seen > _MAX_FILES:
                    return
                yield os.path.join(dirpath, f)


def scan_yara_binaries() -> dict:
    """Varre binários (.exe/.dll) em pastas de usuário casando regras de conteúdo
    estilo YARA — pega executor renomeado/repackado pelos símbolos embutidos."""
    name = "Assinatura binária (YARA)"
    desc = "Cheat detectado pelo CONTEÚDO do binário (símbolos de exploit/injeção)"

    items = []
    seen_paths = set()
    for path in _iter_candidate_files():
        if _is_self(path):
            continue
        data = _read_bytes(path, _MAX_READ)
        if len(data) < 2 or data[:2] != b"MZ":   # só PE
            continue
        hits = _match_rules(data, BUILTIN_RULES)
        if not hits:
            continue
        # App VALIDAMENTE assinado que casou = legítimo raríssimo -> descarta
        if _is_signed(path) is True:
            continue

        low = path.lower()
        if low in seen_paths:
            continue
        seen_paths.add(low)

        fname = os.path.basename(path)
        for rule in hits:
            items.append(_item(
                label=f"YARA: {fname} — {rule['name']}",
                detail=f"{path}\n"
                       f"O binário {rule['why']}",
                severity=rule["severity"],
                matched=rule["matched"],
            ))

    return _result(name, desc, items)


ALL_YARA_SCANNERS = [
    scan_yara_binaries,
]
