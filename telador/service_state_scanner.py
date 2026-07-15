"""
Serviços forenses críticos parados — bypass que stoppa anti-forense.

Os "Windows modificados" (AtlasOS, ReviOS, Ghost Spectre, Lite Gamer) param
esses serviços de propósito pra cegar a forense:
  - eventlog       NADA mais entra em nenhum Event Log enquanto está parado
  - DPS            alimenta Program Compatibility Assistant (pcaclient)
  - Diagtrack      Connected User Experiences and Telemetry
  - pcasvc         Program Compatibility Assistant
  - cdpusersvc*    Connected Devices Platform User Service (suffix por user)

eventlog parado = HIGH sozinho (catastrófico). 3+ outros parados juntos =
HIGH (bypass deliberado de múltiplos). 1-2 isolados = MEDIUM (debloater
de gamer pode parar Diagtrack+DPS sem ser cheat — não inflar pra HIGH).

NÃO incluímos:
  - SysMain — já coberto por `extra_forensics.scan_prefetch_sysmain_disabled`
    (via Start Type=Disabled no registry; duplicaria aqui).
  - sgrmbroker — trigger-start em Win11; frequentemente Stopped em PC saudável,
    geraria FP estrutural.
  - Defender RTP — coberto por `defender_tampering.py`.
"""

from .models import _result, _item

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# (nome_servico_lower, label_humano)
CRITICAL_FORENSIC_SERVICES = [
    ("eventlog",   "Windows Event Log"),
    ("dps",        "Diagnostic Policy Service"),
    ("diagtrack",  "Connected User Experiences and Telemetry"),
    ("pcasvc",     "Program Compatibility Assistant"),
]

# cdpusersvc tem suffix por sessão (cdpusersvc_12abc) — casa por prefixo.
# Tratamento especial: só conta como "parado" se TODAS as instâncias estão
# parando (Win10/11 normalmente roda 1-2 — basta uma rodar pra status ser ok).
CDPUSER_PREFIX = "cdpusersvc"
CDPUSER_LABEL = "Connected Devices Platform User Service"


def _label_for(name_key: str) -> str:
    for k, label in CRITICAL_FORENSIC_SERVICES:
        if k == name_key:
            return label
    if name_key == CDPUSER_PREFIX:
        return CDPUSER_LABEL
    return name_key


def _list_stopped_services():
    """{name_key: status_lower} dos serviços críticos NÃO-running. None se
    psutil indisponível / sem acesso ao SCM.

    cdpusersvc: coletado em dois passes pra evitar bug ordem-dependente —
    só conta como stopped se NENHUMA instância está running."""
    if not HAS_PSUTIL:
        return None
    try:
        services = list(psutil.win_service_iter())
    except (AttributeError, OSError):
        return None

    critical_set = {k for k, _ in CRITICAL_FORENSIC_SERVICES}
    stopped = {}
    cdpu_running_count = 0
    cdpu_stopped_status = None

    for svc in services:
        try:
            name_low = svc.name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
        try:
            status = svc.status().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue

        if name_low in critical_set:
            if status != "running":
                stopped[name_low] = status
        elif name_low.startswith(CDPUSER_PREFIX):
            if status == "running":
                cdpu_running_count += 1
            else:
                # guarda 1 status pra reportar caso TODAS estejam paradas
                cdpu_stopped_status = cdpu_stopped_status or status

    # cdpusersvc só vira "stopped" se nenhuma instância está rodando E
    # pelo menos uma instância parada foi observada (PC normal tem 1+ instâncias;
    # nenhuma observada = ausente, não conta).
    if cdpu_running_count == 0 and cdpu_stopped_status is not None:
        stopped[CDPUSER_PREFIX] = cdpu_stopped_status

    return stopped


def _classify(stopped: dict) -> list:
    """Itens a partir do dict de serviços parados.

    eventlog parado vira HIGH com label próprio (impacto único: cega TODO log).
    3+ outros parados juntos = HIGH "multi" (bypass deliberado de muitos).
    1-2 outros = MEDIUM (debloater scripts de gamer comumente param 1-2)."""
    if not stopped:
        return []
    items = []

    if "eventlog" in stopped:
        items.append(_item(
            label=f"Windows Event Log PARADO (status: {stopped['eventlog']})",
            detail="O serviço EventLog não está rodando. Enquanto ele está parado, "
                   "NADA novo entra em nenhum Event Log do Windows — apagar "
                   "evidência fica grátis e o scan_event_log_gap pode parecer "
                   "limpo. Bypass clássico de SS faz isto deliberadamente.",
            severity="high", matched="service-stopped:eventlog",
        ))

    others = {k: v for k, v in stopped.items() if k != "eventlog"}
    if not others:
        return items

    labels = [f"{_label_for(k)} ({k}, {v})" for k, v in sorted(others.items())]

    if len(others) >= 3:
        items.append(_item(
            label=f"{len(labels)} serviços forenses críticos parados",
            detail="Parados: " + "; ".join(labels) + ". "
                   "Combinação típica de Windows modificado (AtlasOS/ReviOS/Ghost "
                   "Spectre/Lite Gamer) que cega a forense de propósito. DPS "
                   "alimenta o PCA; Diagtrack alimenta telemetry; pcasvc registra "
                   "compatibility data. Três ou mais parados juntos = bypass "
                   "deliberado, raro em PC normal mesmo com debloater.",
            severity="high", matched="service-stopped:multi",
        ))
        return items

    if len(others) == 2:
        items.append(_item(
            label=f"2 serviços forenses parados: {', '.join(sorted(others))}",
            detail="Parados: " + "; ".join(labels) + ". "
                   "Pode ser script de debloat de gamer (Diagtrack+DPS é combo "
                   "comum em tweaks), mas vale o contexto — bypasses param os "
                   "mesmos serviços de propósito.",
            severity="medium", matched="service-stopped:pair",
        ))
        return items

    only = next(iter(others))
    items.append(_item(
        label=f"Serviço forense parado: {_label_for(only)}",
        detail=f"O serviço {only} ({_label_for(only)}) está {others[only]}. "
               f"Pode ser tweak de gamer pra latência, mas vários bypasses param "
               f"este de propósito — vale o contexto.",
        severity="medium", matched=f"service-stopped:{only}",
    ))
    return items


def scan_critical_services() -> dict:
    """Checa serviços forenses críticos do Windows. eventlog parado = HIGH;
    3+ parados juntos = HIGH (Win modificado / bypass); 1-2 = MEDIUM."""
    name = "Serviços forenses críticos parados"
    desc = "EventLog/DPS/Diagtrack/pcasvc/cdpusersvc parados (Win modificado / bypass)"
    if not HAS_PSUTIL:
        return _result(name, desc, [], error="psutil indisponível")
    stopped = _list_stopped_services()
    if stopped is None:
        return _result(name, desc, [],
                       error="sem acesso a Service Control Manager")
    return _result(name, desc, _classify(stopped))


ALL_SERVICE_STATE_SCANNERS = [
    scan_critical_services,
]
