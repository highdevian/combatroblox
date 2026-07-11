"""
Filtro de falso-positivos.

Pós-processa os findings dos scanners aplicando:
  - Detecção de ambiente de dev (Cheat Engine + VS instalado != cheater)
  - Time decay (hit antigo importa menos)
  - Whitelist de paths conhecidos (.git, node_modules, Steam, etc.)
  - Smart browser context (visita vs download)
  - Confidence score numérico
  - Veredict ponderado

Cada item ganha campos:
  - original_severity: severidade antes do filtro
  - fp_reason: motivo do downgrade (ou None se manteve)
  - confidence: 0-100 (quão confiante estamos que é cheat)
"""

import os
from datetime import datetime, timedelta


# ============================ Dev environment detection ============================

DEV_INDICATORS = [
    # IDEs / editors
    r"%PROGRAMFILES%\Microsoft Visual Studio",
    r"%PROGRAMFILES(X86)%\Microsoft Visual Studio",
    r"%PROGRAMFILES%\JetBrains",
    r"%PROGRAMFILES(X86)%\JetBrains",
    r"%LOCALAPPDATA%\Programs\Microsoft VS Code",
    r"%LOCALAPPDATA%\Programs\Cursor",
    r"%LOCALAPPDATA%\JetBrains",
    r"%USERPROFILE%\.vscode",
    r"%USERPROFILE%\.cursor",
    r"%USERPROFILE%\.idea",
    r"%LOCALAPPDATA%\Programs\Windsurf",
    r"%APPDATA%\Code",

    # Runtimes / SDKs
    r"%PROGRAMFILES%\Python311",
    r"%PROGRAMFILES%\Python312",
    r"%PROGRAMFILES%\Python313",
    r"%PROGRAMFILES%\Python314",
    r"%LOCALAPPDATA%\Programs\Python",
    r"%PROGRAMFILES%\nodejs",
    r"%PROGRAMFILES%\dotnet",
    r"%PROGRAMFILES%\Git",
    r"%PROGRAMFILES(X86)%\Git",
    r"%PROGRAMFILES%\Docker",
    r"%PROGRAMFILES%\CMake",
    r"%PROGRAMFILES%\LLVM",
    r"%PROGRAMFILES%\Go",
    r"%USERPROFILE%\.rustup",
    r"%USERPROFILE%\.cargo",

    # Source folders (Microsoft convention + comuns)
    r"%USERPROFILE%\source\repos",
    r"%USERPROFILE%\Documents\Visual Studio 2019",
    r"%USERPROFILE%\Documents\Visual Studio 2022",
    r"%USERPROFILE%\dev",
    r"%USERPROFILE%\Developer",
    r"%USERPROFILE%\Projects",
    r"%USERPROFILE%\github",
]


_dev_cache = None


def detect_dev_environment() -> dict:
    """
    Retorna {'is_dev': bool, 'evidence': [paths]}.
    Cache resultado pra não recalcular a cada item.
    """
    global _dev_cache
    if _dev_cache is not None:
        return _dev_cache

    evidence = []
    for raw in DEV_INDICATORS:
        path = os.path.expandvars(raw)
        if os.path.isdir(path):
            evidence.append(path)

    _dev_cache = {
        "is_dev": len(evidence) >= 2,  # 2+ indicators = provavelmente dev
        "evidence": evidence,
    }
    return _dev_cache


# ============================ Whitelist de paths ============================

# Substrings que, se aparecem no path, indicam que é seguro
WHITELIST_PATH_SUBSTRINGS = [
    r"\.git\\",
    r"\.git/",
    r"\node_modules\\",
    r"\node_modules/",
    r"\.venv\\",
    r"\venv\\",
    r"\.cache\\",
    r"\__pycache__\\",
    r"\.idea\\",
    r"\.vscode\\",
    r"\steamapps\common\\",
    r"\epic games\\",
    r"\rockstar games\\",
    r"\battle.net\\",
    r"\riot games\\",
    r"\microsoft visual studio\\",
    r"\jetbrains\\",
    r"\windows\system32\\",
    r"\windows\syswow64\\",
    r"\windows\winsxs\\",
    r"\nvidia corporation\\",
    r"\amd\\drivers\\",
    r"\intel\\graphics\\",
    r"\windows defender\\",
    r"\microsoft\edgewebview\\",
    r"\microsoft sdks\\",
    r"\windows kits\\",
    # Cloud sync e apps comuns (não são cheats)
    r"\onedrive\\",
    r"\google\chrome\\",
    r"\google drive\\",
    r"\dropbox\\",
    r"\microsoft\edge\\",
    r"\mozilla firefox\\",
    r"\mozilla\\firefox\\",
]


def is_whitelisted_path(path: str) -> tuple[bool, str | None]:
    import os
    """
    Retorna (True, motivo) se o 'path' for de uma ferramenta legítima
    como Visual Studio, JetBrains, Roblox nativo, etc.
    Do contrário, (False, None).
    """
    if not path or len(path) < 3:
        return False, None

    # Normaliza
    norm_path = os.path.normpath(path).lower()
    parts = norm_path.split(os.sep)

    for sub in WHITELIST_PATH_SUBSTRINGS:
        norm_sub = os.path.normpath(sub).lower().strip(os.sep)
        if norm_path == norm_sub or norm_path.startswith(norm_sub + os.sep) or norm_sub in parts:
            return True, f"whitelisted path substring: {sub}"
    return False, None


def _path_candidates_for_item(item: dict) -> list[str]:
    """Extrai textos com chance real de conter o path do artefato."""
    candidates = []
    label = (item.get("label") or "").strip()
    detail = (item.get("detail") or "").strip()

    if detail:
        first_line = detail.splitlines()[0].strip()
        if first_line:
            candidates.append(first_line)

    if ": " in label:
        suffix = label.split(": ", 1)[1].strip()
        if suffix:
            candidates.append(suffix)

    blob = f"{label} {detail}".strip()
    if blob:
        candidates.append(blob)

    seen = set()
    ordered = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


# ============================ Time decay ============================

# Ordem da mais fraca pra mais forte. `critical` foi adicionado pra cobrir
# evidências de altíssima confiança (hash conhecido de executor, driver BYOVD
# carregado, etc). _downgrade nunca tira de critical em 1 nível — ele vira
# high. Quem quiser eliminar tem que mandar levels=2+ explicitamente.
SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _downgrade(severity: str, levels: int = 1) -> str:
    if severity not in SEVERITY_ORDER:
        return severity
    idx = SEVERITY_ORDER.index(severity)
    new_idx = max(0, idx - levels)
    return SEVERITY_ORDER[new_idx]


def _parse_timestamp(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    # Formatos típicos do projeto: "2024-05-26 18:42:00"
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d")
    except ValueError:
        pass
    return None


def apply_time_decay(severity: str, ts_str: str, corroboration: int = 1) -> tuple[str, str | None]:
    """
    Retorna (nova_severidade, motivo).

    Decay base por idade:
      < 30 dias  : sem decay
      30-90 dias : -1 nível
      90+ dias   : -2 níveis (efetivamente vai pra "low")

    Corroboração multi-fonte RESISTE ao decay. O decay existe pra proteger de
    UM artefato velho isolado (pista fraca que ficou pra trás). Mas o MESMO
    alvo visto em várias fontes independentes é evidência forte não importa a
    idade — 5 fontes batendo em Solara há 4 meses ainda é cheater. Então:
      corroboração >= 3 fontes : não decai (idade irrelevante)
      corroboração == 2 fontes : atenua um nível
      corroboração <= 1 fonte  : decay cheio (o caso que o filtro protege)
    """
    ts = _parse_timestamp(ts_str)
    if ts is None:
        return severity, None

    age = datetime.now() - ts
    if age < timedelta(days=30):
        return severity, None

    # 3+ fontes corroborando o mesmo alvo: idade não enfraquece.
    if corroboration >= 3:
        return severity, None

    levels = 1 if age < timedelta(days=90) else 2
    if corroboration == 2:
        levels -= 1                      # 2 fontes seguram um nível de decay
    if levels <= 0:
        return severity, None

    new_sev = _downgrade(severity, levels)
    if new_sev != severity:
        extra = f", atenuado por {corroboration} fontes" if corroboration == 2 else ""
        return new_sev, f"hit antigo ({age.days}d) — rebaixado de {severity} pra {new_sev}{extra}"
    return severity, None


# ============================ Smart context filters ============================

# Domínios "forum/pesquisa" — visita só = baixa confiança
LOW_INTENT_DOMAINS = {
    "v3rmillion.net", "v3rm.net", "elitepvpers.com", "unknowncheats.me",
    "guidedhacking.com", "lanik.us", "mpgh.net",
    "rscripts.net", "scriptblox.com", "robloxscripts.com",
}


def adjust_browser_finding(item: dict) -> tuple[dict, str | None]:
    """
    Se finding é browser history:
      - DOWNLOAD: mantém severity
      - Só visita a forum (low-intent domain): rebaixa
    """
    label = (item.get("label") or "")
    matched = (item.get("matched") or "").lower()
    detail = (item.get("detail") or "").lower()

    # Não é browser? skip
    if not label.startswith("[Chrome") and not label.startswith("[Edge") and \
       not label.startswith("[Brave") and not label.startswith("[Opera"):
        return item, None

    # Foi DOWNLOAD? mantém
    if "DOWNLOAD:" in label or "download" in detail[:100]:
        return item, None

    # Só visita a forum/research site? rebaixa
    for dom in LOW_INTENT_DOMAINS:
        if dom in matched or dom in detail:
            new_sev = _downgrade(item.get("severity", "low"), 1)
            if new_sev != item.get("severity"):
                reason = f"só visita a forum ({dom}) — não houve download"
                return item, reason

    return item, None


# ============================ Dev environment downgrade ============================

# matched values que indicam pasta de usuário genérica excluída do Defender
_DEFENDER_USER_FOLDER_MATCHED = {"exclusao-pasta-usuario", "exclusao-processo"}


# Keywords que são suspeitas em geral, mas comum em PC de dev
DEV_AMBIGUOUS_KEYWORDS = {
    "cheat engine", "cheatengine", "cheatengine-x86_64.exe", "cheatengine-i386.exe",
    "process hacker", "processhacker.exe", "system informer", "systeminformer.exe",
    "ida.exe", "ida64.exe", "ghidra.exe", "dnspy.exe",
    "x32dbg.exe", "x64dbg.exe", "ollydbg.exe", "windbg.exe",
    "scylla.exe", "pe-bear.exe", "die.exe",
    "dll injector", "codex",
    # Macro tools (dual-use): rebaixa em dev; em cheater continua MEDIUM
    "tinytask", "tinytask.exe",
    "autoclicker", "auto clicker", "op auto clicker",
}

# Em PC de DEV (Telador do supervisor), esconde TOTALmente — não polui o
# report do próprio dono. Em PC de suspeito (não-dev) o match continua.
# Cheater com TinyTask SEM IDE/JetBrains/etc ainda leva MEDIUM em 4 fontes.
DEV_SUPPRESS_KEYWORDS = {
    "tinytask", "tinytask.exe",
}


def _matched_is_suppressed(matched: str, suppress: set) -> bool:
    m = (matched or "").lower().strip()
    if not m:
        return False
    if m in suppress:
        return True
    # "tinytask" casa "tinytask-1.77-installer" via token
    for tok in suppress:
        if tok and tok in m:
            return True
    return False


def adjust_for_dev_env(item: dict, is_dev: bool) -> tuple[dict, str | None]:
    """Em PC de dev, ferramentas como Cheat Engine são LOW (uso legítimo)."""
    if not is_dev:
        return item, None

    matched = (item.get("matched") or "").lower()

    if matched not in DEV_AMBIGUOUS_KEYWORDS:
        # Exclusão genérica de pasta de usuário: dev costuma excluir projeto do Desktop
        # por performance → rebaixa HIGH → MEDIUM (ainda vale revisar, mas não é prova)
        if matched in _DEFENDER_USER_FOLDER_MATCHED:
            new_sev = _downgrade(item.get("severity", "low"), 1)
            if new_sev != item.get("severity"):
                return item, "PC de dev — pasta de usuário excluída do Defender pode ser otimização de performance"
        return item, None

    new_sev = _downgrade(item.get("severity", "low"), 2)
    if new_sev != item.get("severity"):
        return item, "PC de dev (VS/JetBrains/etc detectados) — ferramenta tem uso legítimo"

    return item, None


# ============================ Confidence score ============================

# Pesos por severidade. `critical` é deliberadamente maior que 2× `high` —
# evidência crítica (hash conhecido, BYOVD ativo) deve sozinha disparar
# veredicto positivo mesmo sem cross-correlation com outras fontes.
SEVERITY_WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1}


def compute_confidence(item: dict) -> int:
    """
    Score 0-100. Considera:
      - Severidade
      - Tem timestamp recente?
      - Whitelisted? (confidence cai)
      - Rebaixado por FP filter? (confidence cai)
    """
    sev = item.get("severity", "low")
    # base: low=10, medium=40, high=100, critical=100 (capado)
    base = min(100, SEVERITY_WEIGHT.get(sev, 0) * 10)

    # Timestamp recente boosta um pouco
    ts = _parse_timestamp(item.get("timestamp", ""))
    if ts is not None:
        age = datetime.now() - ts
        if age < timedelta(days=7):
            base = min(100, int(base * 1.2))
        elif age > timedelta(days=180):
            base = int(base * 0.5)

    # Foi rebaixado? confidence cai
    if item.get("fp_reason"):
        base = int(base * 0.6)

    return max(0, min(100, base))


# ============================ Main post-processor ============================

def _corroboration_by_item(findings: list) -> dict:
    """Mapa id(item) -> nº de FONTES distintas que corroboram o MESMO alvo.

    Reusa o clustering completo do Confidence Engine (evidence.build_clusters),
    que já funde variantes no mesmo alvo (path->executor, aliases): assim
    'solara', 'solara.exe', 'usn:solara' e o path do .exe contam como fontes do
    MESMO Solara. Sem isso a corroboração ficaria fragmentada e o decay ainda
    colapsaria o veredito de um cheater óbvio."""
    try:
        import evidence
        clusters = evidence.build_clusters(evidence.findings_to_evidences(findings))
    except Exception:
        return {}
    out = {}
    for c in clusters:
        n = c.n_sources
        for ev in c.evidences:
            out[id(ev.raw)] = n          # ev.raw É o dict do item original
    return out


def post_process_findings(findings: list) -> tuple[list, dict]:
    """
    Aplica todos os filtros de FP em todos os items.
    Retorna (findings_processados, stats_dict).

    Adiciona em cada item:
      - original_severity (se foi rebaixado)
      - fp_reason (motivo do rebaixamento, se houve)
      - confidence (0-100)
    """
    dev = detect_dev_environment()
    # Corroboração por alvo (nº de fontes) ANTES de decair — decide se um hit
    # antigo resiste ao time-decay por estar corroborado em várias fontes.
    corrob = _corroboration_by_item(findings)
    stats = {
        "is_dev_env": dev["is_dev"],
        "dev_evidence": dev["evidence"],
        "items_downgraded": 0,
        "items_whitelisted": 0,
        "total_items_in": sum(len(f["items"]) for f in findings),
    }

    for finding in findings:
        new_items = []
        for item in finding["items"]:
            original_sev = item.get("severity", "low")
            reasons = []

            # 1. Whitelist por path — checa label (o caminho real) e detail
            for candidate in _path_candidates_for_item(item):
                wl, wl_reason = is_whitelisted_path(candidate)
                if wl:
                    stats["items_whitelisted"] += 1
                    # Skip totalmente — não adiciona ao output
                    break
            else:
                wl = False
            if wl:
                continue

            # 1b. Em PC de dev: some dual-use do dono (TinyTask etc.) — não
            # polui report. Em suspeito sem ambiente de dev, continua.
            if dev["is_dev"] and _matched_is_suppressed(
                    item.get("matched") or "", DEV_SUPPRESS_KEYWORDS):
                stats["items_whitelisted"] += 1
                continue

            # 2. Browser smart context
            _, browser_reason = adjust_browser_finding(item)
            if browser_reason:
                item["severity"] = _downgrade(item["severity"], 1)
                reasons.append(browser_reason)

            # 3. Dev environment
            _, dev_reason = adjust_for_dev_env(item, dev["is_dev"])
            if dev_reason:
                item["severity"] = _downgrade(item["severity"], 2)
                reasons.append(dev_reason)

            # 4. Time decay — NÃO se aplica à costura de operador: ali o
            # timestamp é a hora da PARTIDA (quando o swap ocorreu), não a idade
            # de um artefato no disco. Evidência de um evento passado não perde
            # força com o tempo — auditar uma série antiga tem que manter o peso.
            if not (item.get("matched") or "").lower().startswith("seam-"):
                n_src = corrob.get(id(item), 1)
                new_sev, decay_reason = apply_time_decay(
                    item["severity"], item.get("timestamp", ""), corroboration=n_src)
                if decay_reason:
                    item["severity"] = new_sev
                    reasons.append(decay_reason)

            # Anotar
            if item["severity"] != original_sev:
                item["original_severity"] = original_sev
                item["fp_reason"] = " | ".join(reasons)
                stats["items_downgraded"] += 1

            # Confidence
            item["confidence"] = compute_confidence(item)

            new_items.append(item)

        finding["items"] = new_items
        # Re-status: se ficou sem items, é "clean"
        # Não reescrever status="error": checagem que crashou/cegou NÃO é "clean".
        if finding.get("status") == "error":
            finding["items"] = new_items
            if not finding.get("summary"):
                finding["summary"] = f"Erro: {finding.get('error') or 'checagem falhou'}"
        elif not new_items:
            finding["status"] = "clean"
            finding["summary"] = "Nenhum hit após filtro de FP"
        else:
            finding["status"] = "suspicious"
            finding["summary"] = f"{len(new_items)} item(s) suspeito(s)"

    stats["total_items_out"] = sum(
        len([i for i in f["items"] if not i.get("meta_only")]) for f in findings
    )
    stats["n_error_scanners"] = sum(1 for f in findings if f.get("status") == "error")
    return findings, stats


# ============================ Verdict ponderado ============================

def compute_verdict(findings: list) -> dict:
    """
    Score ponderado em vez de só contar HIGH.
    Cada hit pontua baseado em severidade + confidence + recência.
    """
    total_score = 0
    crit_count = high_count = med_count = low_count = 0
    most_recent_hit = None
    highest_confidence = 0

    for f in findings:
        for item in f["items"]:
            # Itens meta_only são contexto (ex: cabeçalho "[PROCESSO] Roblox
            # rodando") — não são hits. Não devem somar score nem contagem.
            if item.get("meta_only"):
                continue
            sev = item.get("severity", "low")
            conf = item.get("confidence", 50)
            weight = SEVERITY_WEIGHT.get(sev, 0)
            total_score += weight * (conf / 100)

            if sev == "critical":
                crit_count += 1
            elif sev == "high":
                high_count += 1
            elif sev == "medium":
                med_count += 1
            else:
                low_count += 1

            highest_confidence = max(highest_confidence, conf)

            ts = _parse_timestamp(item.get("timestamp", ""))
            if ts and (most_recent_hit is None or ts > most_recent_hit):
                most_recent_hit = ts

    # Veredict baseado no score
    # Conta quantas FONTES diferentes deram hit — 1 fonte só raramente é
    # evidência de cheat. Cross-correlation > pontuação isolada.
    sources_with_hits = sum(1 for f in findings if f.get("items"))

    # Critical hits são prova forense forte (hash conhecido, BYOVD ativo, etc).
    # 1 crítico já confirma. 2+ críticos cravam mesmo sem outras fontes.
    # Cores em oklch = paleta do relatório HTML (forensic dark lab). O terminal
    # usa ANSI próprio; este campo `color` é só pro HTML.
    if crit_count >= 2 or (crit_count >= 1 and sources_with_hits >= 2):
        verdict, color = "CHEATER CONFIRMADO", "oklch(0.62 0.21 28)"
    elif crit_count >= 1:
        verdict, color = "ALTAMENTE SUSPEITO", "oklch(0.62 0.21 28)"
    elif total_score >= 50 and sources_with_hits >= 3:
        verdict, color = "CHEATER CONFIRMADO", "oklch(0.62 0.21 28)"
    elif total_score >= 25 and sources_with_hits >= 2:
        verdict, color = "ALTAMENTE SUSPEITO", "oklch(0.62 0.21 28)"
    elif total_score >= 12 and sources_with_hits >= 2:
        verdict, color = "SUSPEITO (REVISAR)", "oklch(0.72 0.14 28)"
    elif total_score >= 4:
        verdict, color = "POSSÍVEIS PISTAS", "oklch(0.78 0.02 240)"
    else:
        verdict, color = "LIMPO", "oklch(0.72 0.14 160)"

    # Contagem de scanners com erro (fontes cegas) — o caller pode promover
    # LIMPO → INCONCLUSIVO via coverage.apply_coverage_to_verdict.
    n_error_scanners = sum(1 for f in findings if f.get("status") == "error")
    sources_with_errors = [
        f.get("name", "?") for f in findings if f.get("status") == "error"
    ]

    return {
        "verdict": verdict,
        "color": color,
        "score": round(total_score, 1),
        "critical": crit_count,
        "high": high_count,
        "medium": med_count,
        "low": low_count,
        "highest_confidence": highest_confidence,
        "most_recent_hit": most_recent_hit.strftime("%Y-%m-%d %H:%M:%S") if most_recent_hit else None,
        "sources_with_hits": sources_with_hits,
        "n_error_scanners": n_error_scanners,
        "sources_with_errors": sources_with_errors,
        "inconclusive": False,
    }
