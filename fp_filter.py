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
import re
from datetime import datetime, timedelta


# ============================ Dev environment detection ============================

DEV_INDICATORS = [
    # IDEs / editors
    r"%PROGRAMFILES%\Microsoft Visual Studio",
    r"%PROGRAMFILES(X86)%\Microsoft Visual Studio",
    r"%PROGRAMFILES%\JetBrains",
    r"%PROGRAMFILES(X86)%\JetBrains",
    r"%LOCALAPPDATA%\Programs\Microsoft VS Code",
    r"%LOCALAPPDATA%\JetBrains",
    r"%USERPROFILE%\.vscode",
    r"%USERPROFILE%\.cursor",
    r"%USERPROFILE%\.idea",

    # Runtimes / SDKs
    r"%PROGRAMFILES%\Python311",
    r"%PROGRAMFILES%\Python312",
    r"%PROGRAMFILES%\Python313",
    r"%PROGRAMFILES%\nodejs",
    r"%PROGRAMFILES%\dotnet",
    r"%PROGRAMFILES%\Git",
    r"%PROGRAMFILES(X86)%\Git",
    r"%PROGRAMFILES%\Docker",

    # Source folders (Microsoft convention)
    r"%USERPROFILE%\source\repos",
    r"%USERPROFILE%\Documents\Visual Studio 2019",
    r"%USERPROFILE%\Documents\Visual Studio 2022",
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
    """Retorna (True, motivo) se path está em whitelist."""
    if not path:
        return False, None
    lower = path.lower().replace("/", "\\")
    for sub in WHITELIST_PATH_SUBSTRINGS:
        sub_normalized = sub.replace("/", "\\").lower()
        if sub_normalized in lower:
            return True, f"path-whitelisted ({sub_normalized.strip(chr(92))})"
    return False, None


# ============================ Time decay ============================

SEVERITY_ORDER = ["low", "medium", "high"]


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


def apply_time_decay(severity: str, ts_str: str) -> tuple[str, str | None]:
    """
    Retorna (nova_severidade, motivo).
    Decay:
      < 30 dias  : sem decay
      30-90 dias : -1 nível
      90+ dias   : -2 níveis (efetivamente vai pra "low")
    """
    ts = _parse_timestamp(ts_str)
    if ts is None:
        return severity, None

    age = datetime.now() - ts
    if age < timedelta(days=30):
        return severity, None
    if age < timedelta(days=90):
        new_sev = _downgrade(severity, 1)
        if new_sev != severity:
            return new_sev, f"hit antigo ({age.days}d) — rebaixado de {severity} pra {new_sev}"
        return severity, None

    # Muito antigo (> 90 dias)
    new_sev = _downgrade(severity, 2)
    if new_sev != severity:
        return new_sev, f"hit antigo ({age.days}d) — rebaixado de {severity} pra {new_sev}"
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

# Keywords que são suspeitas em geral, mas comum em PC de dev
DEV_AMBIGUOUS_KEYWORDS = {
    "cheat engine", "cheatengine", "cheatengine-x86_64.exe", "cheatengine-i386.exe",
    "process hacker", "processhacker.exe", "system informer", "systeminformer.exe",
    "ida.exe", "ida64.exe", "ghidra.exe", "dnspy.exe",
    "x32dbg.exe", "x64dbg.exe", "ollydbg.exe", "windbg.exe",
    "scylla.exe", "pe-bear.exe", "die.exe",
    "dll injector",
}


def adjust_for_dev_env(item: dict, is_dev: bool) -> tuple[dict, str | None]:
    """Em PC de dev, ferramentas como Cheat Engine são LOW (uso legítimo)."""
    if not is_dev:
        return item, None

    matched = (item.get("matched") or "").lower()
    if matched not in DEV_AMBIGUOUS_KEYWORDS:
        return item, None

    new_sev = _downgrade(item.get("severity", "low"), 2)
    if new_sev != item.get("severity"):
        return item, "PC de dev (VS/JetBrains/etc detectados) — ferramenta tem uso legítimo"

    return item, None


# ============================ Confidence score ============================

SEVERITY_WEIGHT = {"high": 10, "medium": 4, "low": 1}


def compute_confidence(item: dict) -> int:
    """
    Score 0-100. Considera:
      - Severidade
      - Tem timestamp recente?
      - Whitelisted? (confidence cai)
      - Rebaixado por FP filter? (confidence cai)
    """
    sev = item.get("severity", "low")
    base = SEVERITY_WEIGHT.get(sev, 0) * 10  # 10/40/100

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
            wl, wl_reason = is_whitelisted_path(
                item.get("label", "") + " " + item.get("detail", "")
            )
            if wl:
                stats["items_whitelisted"] += 1
                # Skip totalmente — não adiciona ao output
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

            # 4. Time decay
            new_sev, decay_reason = apply_time_decay(item["severity"], item.get("timestamp", ""))
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
        if not new_items:
            finding["status"] = "clean"
            finding["summary"] = "Nenhum hit após filtro de FP"

    stats["total_items_out"] = sum(len(f["items"]) for f in findings)
    return findings, stats


# ============================ Verdict ponderado ============================

def compute_verdict(findings: list) -> dict:
    """
    Score ponderado em vez de só contar HIGH.
    Cada hit pontua baseado em severidade + confidence + recência.
    """
    total_score = 0
    high_count = med_count = low_count = 0
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

            if sev == "high":
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

    if total_score >= 50 and sources_with_hits >= 3:
        verdict, color = "CHEATER CONFIRMADO", "#ff4d4f"
    elif total_score >= 25 and sources_with_hits >= 2:
        verdict, color = "ALTAMENTE SUSPEITO", "#ff4d4f"
    elif total_score >= 12 and sources_with_hits >= 2:
        verdict, color = "SUSPEITO (REVISAR)", "#ffb020"
    elif total_score >= 4:
        verdict, color = "POSSÍVEIS PISTAS", "#ffe066"
    else:
        verdict, color = "LIMPO", "#3fbf7f"

    return {
        "verdict": verdict,
        "color": color,
        "score": round(total_score, 1),
        "high": high_count,
        "medium": med_count,
        "low": low_count,
        "highest_confidence": highest_confidence,
        "most_recent_hit": most_recent_hit.strftime("%Y-%m-%d %H:%M:%S") if most_recent_hit else None,
    }
