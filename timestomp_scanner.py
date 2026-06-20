"""
Detecção de anomalias de timestamp de arquivo — anti-forense (time-stomping).

Time-stomping = adulterar as datas (criado/modificado) de um arquivo pra ele
parecer antigo ou cair FORA da janela de tempo da SS. O método forense definitivo
compara $STANDARD_INFORMATION vs $FILE_NAME no MFT — mas isso é confundido por
rename legítimo (renomear já deixa $SI < $FN) e exige parse raw do MFT. Aqui
ficamos nos sinais que são GENUINAMENTE FP-SAFE:

  1. Data NO FUTURO (criado/modificado > agora + tolerância) — nenhum processo
     legítimo cria arquivo com data futura; corrobora relógio adulterado.
  2. Arquivo com NOME DE EXECUTOR conhecido cuja CRIAÇÃO está absurdamente no
     passado (backdated, antes do Roblox existir). Gated atrás do match de
     executor → 0 FP em arquivo limpo (arquivo limpo não casa o nome).

Só olha arquivos executáveis/script em pastas de usuário (bounded, relevante).
Usa os.stat (precisão a nível de dia basta pra estes sinais; sem ctypes frágil).
Severidade MEDIUM — corroboração no Confidence Engine, não crava sozinho.
"""

from models import _result, _item
import os
from datetime import datetime, timedelta

import matching


# Extensões que interessam (executável / script).
_EXEC_EXT = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
             ".com", ".lua", ".luau", ".jar", ".hta")

_SCAN_DIRS = [
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Documents",
    r"%TEMP%",
    r"%APPDATA%",
    r"%LOCALAPPDATA%\Temp",
]
_MAX_DEPTH = 2
_MAX_FILES = 20000

# Tolerância de skew pra "futuro" (1 dia) — evita FP de fuso/relógio levemente
# adiantado. Só data MUITO no futuro dispara.
_FUTURE_TOLERANCE = timedelta(days=1)

# Piso de "backdate": executor com criação antes disto é fake (o Roblox e a cena
# de executores são bem posteriores; nada legítimo com nome de cheat é de 2005).
_BACKDATE_FLOOR = datetime(2006, 1, 1)


def _classify_times(created, modified, now, is_executor):
    """Retorna (severity, matched, motivo) ou None. Núcleo testável (sem I/O).

    `created`/`modified`: datetime ou None. `is_executor`: o nome casou um
    executor conhecido (gate anti-FP pro backdate)."""
    future = now + _FUTURE_TOLERANCE

    # 1. Data no futuro — FP-safe (nenhum processo legítimo faz isso)
    if created and created > future:
        return "medium", "timestamp-futuro", f"data de criação no futuro ({created:%Y-%m-%d %H:%M})"
    if modified and modified > future:
        return "medium", "timestamp-futuro", f"data de modificação no futuro ({modified:%Y-%m-%d %H:%M})"

    # 2. Executor backdated (gated atrás do match de executor → 0 FP em limpo)
    if is_executor and created and created < _BACKDATE_FLOOR:
        return ("medium", "timestamp-backdated",
                f"arquivo de executor com criação backdated ({created:%Y-%m-%d}) — "
                f"anterior à existência da cena de cheats")

    return None


def _file_times(path):
    """(created, modified) como datetime via os.stat, ou (None, None) em erro.
    No Windows, st_ctime é a data de CRIAÇÃO."""
    try:
        st = os.stat(path)
    except OSError:
        return None, None
    try:
        created = datetime.fromtimestamp(getattr(st, "st_birthtime", st.st_ctime))
    except (ValueError, OSError, OverflowError):
        created = None
    try:
        modified = datetime.fromtimestamp(st.st_mtime)
    except (ValueError, OSError, OverflowError):
        modified = None
    return created, modified


def scan_timestomp() -> dict:
    """Anomalias de timestamp em arquivos executáveis/script de pastas de usuário."""
    items = []
    seen = set()
    now = datetime.now()
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
                low = f.lower()
                is_executor = bool(matching.match_keyword(f)[0])
                # Só olha exe/script OU nome de executor — bounded e relevante
                if not low.endswith(_EXEC_EXT) and not is_executor:
                    continue

                files_scanned += 1
                if files_scanned > _MAX_FILES:
                    dirnames[:] = []
                    break

                full = os.path.join(dirpath, f)
                if full.lower() in seen:
                    continue
                seen.add(full.lower())

                created, modified = _file_times(full)
                res = _classify_times(created, modified, now, is_executor)
                if not res:
                    continue
                sev, matched, motivo = res
                items.append(_item(
                    label=f"Timestamp adulterado: {f}",
                    detail=f"{full}\n{motivo}.\nTime-stomping é anti-forense: muda a data do "
                           f"arquivo pra ele parecer antigo ou cair fora da janela de tempo da "
                           f"SS. Cruze com o relógio do sistema e os artefatos de execução.",
                    severity=sev, matched=matched,
                ))

    return _result("Anomalia de timestamp (time-stomping)",
                   "Datas de arquivo adulteradas (futuro / executor backdated)", items)


ALL_TIMESTOMP_SCANNERS = [
    scan_timestomp,
]
