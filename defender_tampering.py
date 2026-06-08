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

import subprocess

import matching


def _result(name, description, items, error=None):
    if error:
        status, summary = "error", f"Erro: {error}"
    elif items:
        status, summary = "suspicious", f"{len(items)} item(s) suspeito(s)"
    else:
        status, summary = "clean", "Nenhum vestígio encontrado"
    return {"name": name, "description": description, "status": status,
            "items": items, "summary": summary, "error": error}


def _item(label, detail, severity, matched, timestamp=""):
    return {"label": label, "detail": detail, "severity": severity,
            "matched": matched, "timestamp": timestamp}


# Pastas graváveis pelo usuário — exclusão aqui = escondendo algo.
_USER_WRITABLE = ("\\downloads", "\\temp", "\\appdata", "\\users\\public",
                  "\\desktop", "\\roaming", "\\local\\")

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
        if any(s in low for s in _USER_WRITABLE) and not low.startswith(
                ("c:\\program files", "c:\\programdata")):
            return "high", "exclusao-pasta-usuario"

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
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
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
            items.append(_item(
                label=f"Exclusão do Defender ({_KIND_LABEL[kind]}): {v}",
                detail=f"{v}\nO Windows Defender foi mandado IGNORAR esta {_KIND_LABEL[kind]}. "
                       f"Excluir pasta de usuário, executor ou extensão de .exe é o jeito "
                       f"clássico de rodar cheat sem o Defender pegar. Usuário comum não mexe "
                       f"em exclusão do antivírus.",
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
