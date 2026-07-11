"""
Detecção de adulteração do Windows Defender — anti-bypass.

O método mais comum pra rodar cheat sem o Defender atrapalhar: mandar o próprio
Windows IGNORAR a pasta do executor (Exclusões do Defender), ou desligar a
proteção em tempo real. Exclusão de pasta de usuário / executor / extensão de
.exe é quase sempre "esconde meu cheat" — usuário comum nunca mexe nisso.

Lê via API oficial (Get-MpPreference / Get-MpComputerStatus por PowerShell). As
chaves do Defender no registro são bloqueadas pelo Tamper Protection mesmo com
admin (só SYSTEM lê), então a API é o caminho que de fato funciona em produção.
"""

from models import _result, _item
import os
import subprocess

import win_tools

import matching
from database import DEFENDER_EXCLUSION_DEV_PATHS


# Normalizado pra comparação case-insensitive com forward/back-slash uniforme.
# Os markers em DEFENDER_EXCLUSION_DEV_PATHS terminam em `\\` (raw string =
# DOIS backslashes), mas paths reais do Windows têm UM separador. `.rstrip("\\")`
# tira o trailing — `\jetbrains\\` vira `\jetbrains` e casa como substring.
_DEV_PATH_SUBS = [
    s.lower().replace("/", "\\").rstrip("\\") for s in DEFENDER_EXCLUSION_DEV_PATHS
]


def _is_dev_exclusion_path(value: str) -> bool:
    """Retorna True se o path é uma pasta conhecida de IDE / runtime."""
    low = value.lower().replace("/", "\\")
    return any(sub in low for sub in _DEV_PATH_SUBS)


# Marcadores de pasta de DESENVOLVIMENTO que NÃO estão na lista hard-coded.
# Lemos o conteúdo da pasta excluída: se ela tem `.git`, `package.json`,
# `pyproject.toml` etc na raiz, é repo de dev (exclusão por perf), não cheat.
# Cobre o caso `Desktop\<nome_qualquer_do_projeto>`.
_DEV_FOLDER_MARKERS = (
    ".git", "package.json", "node_modules", "pyproject.toml",
    "requirements.txt", "Cargo.toml", "go.mod", "pom.xml",
    "build.gradle", ".csproj", ".sln", "tsconfig.json", "Gemfile",
    ".venv", "venv", ".idea", ".vscode",
)


def _probe_dev_folder(original_path: str) -> bool:
    """Lê o conteúdo da pasta excluída e procura marcadores de projeto.
    Roda só pra paths que de fato existem; ignora erro silencioso (path pode
    ter sido movido/digitado errado pelo usuário). Cheater não cria .git só
    pra disfarçar."""
    if not original_path:
        return False
    try:
        if not os.path.isdir(original_path):
            return False
        entries = set(os.listdir(original_path))
    except OSError:
        return False
    low = {e.lower() for e in entries}
    for marker in _DEV_FOLDER_MARKERS:
        ml = marker.lower()
        # marcadores tipo ".csproj" / ".sln" são extensões — varre por sufixo
        if ml.startswith("."):
            if any(e.endswith(ml) for e in low) or ml in low:
                return True
        elif ml in low:
            return True
    return False


# Paths graváveis onde cheater costuma dropar (HIGH se excluir sem ser dev).
_USER_DROP_PATHS = ("\\downloads", "\\temp", "\\appdata", "\\users\\public",
                    "\\local\\temp", "\\local\\")
# Desktop/Documents/Roaming: devs excluem projeto por perf com frequência.
# Sem marcador de repo → MEDIUM (revisar), não HIGH (não crava sozinho).
_USER_PROJECT_PATHS = ("\\desktop", "\\documents", "\\roaming")

_KIND_LABEL = {"path": "pasta", "process": "processo", "extension": "extensão"}


def _classify_exclusion(value: str, kind: str):
    """Retorna (severity, matched) pra uma exclusão. Núcleo testável.
    kind: 'path' | 'process' | 'extension'."""
    v = (value or "").strip()
    low = v.lower().replace("/", "\\")

    # Nome de executor conhecido na exclusão = cravado
    kw, _sev = matching.match_keyword(v)
    if kw:
        return "high", f"exclusao-executor:{kw}"

    # Excluir extensão de executável inteira (.exe / *.exe) = esconder tudo
    if kind == "extension" and low.lstrip("*.") in ("exe", "dll", "scr", "bat"):
        return "high", f"exclusao-extensao:{low}"

    # Exclusão de pasta gravável pelo usuário (e não Program Files) = suspeito
    if kind == "path":
        # IDE/runtime conhecida (lista hard-coded) → baixo risco
        if _is_dev_exclusion_path(v):
            return "low", "exclusao-dev"
        in_drop = any(s in low for s in _USER_DROP_PATHS)
        in_project = any(s in low for s in _USER_PROJECT_PATHS)
        if (in_drop or in_project) and not low.startswith(
                ("c:\\program files", "c:\\programdata")):
            # Probe do conteúdo: pasta com marcadores de projeto (.git, package.json…)
            # → repo de dev no Desktop/Documents, exclusão por perf, não cheat.
            if _probe_dev_folder(v):
                return "low", "exclusao-dev"
            # Downloads/Temp/AppData sem marcador = HIGH (drop clássico de cheat).
            # Desktop/Documents sem marcador = MEDIUM (muitas vezes portfolio/projeto).
            if in_drop:
                return "high", "exclusao-pasta-usuario"
            return "medium", "exclusao-pasta-usuario"

    # Processo excluído fora de Program Files / Windows
    if kind == "process" and low and not low.startswith(
            ("c:\\program files", "c:\\windows")):
        return "medium", "exclusao-processo"

    # Resto (ex.: pasta de jogo em Program Files) = contexto
    return "low", "exclusao"


def _query_defender():
    """Consulta Get-MpPreference / Get-MpComputerStatus via PowerShell.
    Retorna dict {path, process, extension, realtime_disabled} ou None se falhar.
    Isolado pra ser testável (os testes mockam isto)."""
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$p=Get-MpPreference;"
        "Write-Output ('PATH:' + ($p.ExclusionPath -join ';;'));"
        "Write-Output ('PROC:' + ($p.ExclusionProcess -join ';;'));"
        "Write-Output ('EXT:' + ($p.ExclusionExtension -join ';;'));"
        "Write-Output ('RTP:' + ((Get-MpComputerStatus).RealTimeProtectionEnabled))"
    )
    try:
        r = subprocess.run(
            [win_tools.powershell(), "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None

    data = {"path": [], "process": [], "extension": [], "realtime_disabled": False}
    got_any = False
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("PATH:"):
            got_any = True
            data["path"] = [x for x in line[5:].split(";;") if x]
        elif line.startswith("PROC:"):
            data["process"] = [x for x in line[5:].split(";;") if x]
        elif line.startswith("EXT:"):
            data["extension"] = [x for x in line[4:].split(";;") if x]
        elif line.startswith("RTP:"):
            data["realtime_disabled"] = line[4:].strip().lower() == "false"

    # Sem admin, o Get-MpPreference devolve "N/A: Must be an administrator to
    # view exclusions" no lugar do valor — não é exclusão, é falta de acesso.
    # Trata como inconclusivo (None) em vez de virar FP.
    for kind in ("path", "process", "extension"):
        if any("must be an administrator" in x.lower() for x in data[kind]):
            return None

    return data if got_any else None


def scan_defender_tampering() -> dict:
    """Exclusões do Windows Defender + proteção em tempo real desligada.
    Exclusão de pasta de usuário / executor / extensão de exe = anti-bypass forte."""
    info = _query_defender()
    if info is None:
        return _result(
            "Adulteração do Windows Defender",
            "Exclusões do Defender e proteção desligada (anti-bypass)",
            [], error="não deu pra consultar o Defender (sem PowerShell/Get-MpPreference ou sem admin)")

    items = []
    for kind in ("path", "process", "extension"):
        for v in info[kind]:
            sev, matched = _classify_exclusion(v, kind)
            if matched == "exclusao-dev":
                # Exclusão legítima de ambiente de dev — contexto, não anti-bypass
                detail = (f"{v}\nExclusão de pasta de IDE / runtime / projeto de "
                          f"desenvolvimento. JetBrains, VS Code, .git, node_modules "
                          f"e afins têm exclusão documentada por performance — não é "
                          f"o padrão clássico de anti-bypass de cheat. Listado só "
                          f"como contexto.")
            else:
                detail = (f"{v}\nO Windows Defender foi mandado IGNORAR esta "
                          f"{_KIND_LABEL[kind]}. Excluir pasta de usuário, executor "
                          f"ou extensão de .exe é o jeito clássico de rodar cheat sem "
                          f"o Defender pegar. Usuário comum não mexe em exclusão do "
                          f"antivírus.")
            items.append(_item(
                label=f"Exclusão do Defender ({_KIND_LABEL[kind]}): {v}",
                detail=detail,
                severity=sev, matched=matched,
            ))

    if info["realtime_disabled"]:
        items.append(_item(
            label="Proteção em tempo real do Defender DESLIGADA",
            detail="A proteção em tempo real do Windows Defender está desativada. Pode ser "
                   "anti-bypass (desligou pra rodar o cheat) ou um antivírus de terceiro "
                   "legítimo. Cruze com o resto: desligado + exclusão de executor = forte.",
            severity="medium", matched="defender-realtime-off",
        ))

    return _result("Adulteração do Windows Defender",
                   "Exclusões do Defender e proteção desligada (anti-bypass)", items)


ALL_DEFENDER_SCANNERS = [
    scan_defender_tampering,
]
