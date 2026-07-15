"""
Cobertura do scan: quais checagens rodaram, falharam, ou foram puladas.

Um veredito LIMPO com fontes cegas é INCONCLUSIVO — esta module materializa
isso pra console, HTML e Markdown.
"""

from __future__ import annotations

from typing import Any


# Fontes "fortes" — cegar estas com erro duro justifica INCONCLUSIVO.
# NÃO usar substring genérica "event" (casava "PCA AppCompat Events").
STRONG_SOURCES_HINTS = (
    "prefetch", "amcache", "bam",
    "defender: detecção", "defender events", "defender mplog",
    "recycle", "lixeira",
    "usn", "usn journal",
    "windows events", "winevent", "event log de execução",
    "critical services", "service state",
)

# Erros "soft": opcional ausente / canal vazio / base vazia — NÃO cegam
# forensics e NÃO devem promover LIMPO → INCONCLUSIVO.
_SOFT_ERROR_HINTS = (
    "não está instalado",
    "nao esta instalado",
    "não detectado",
    "nao detectado",
    "base de hashes vazia",
    "não encontrado",
    "nao encontrado",
    "psutil não instalado",
    "psutil nao instalado",
    # Canais secundários: vazios ou inacessíveis ≠ cegueira forense
    "ou vazio",
    "canal pca inacessível",
    "task scheduler log inacessível",
    "log inacessível (requer admin)",
    "inacessível (requer admin) ou vazio",
)


def _is_strong_source(name: str = "", error: str = "") -> bool:
    """True se o scanner (ou a mensagem de erro) e fonte forense forte.

    Usado pra NUNCA classificar Amcache/Prefetch/BAM/etc como soft-skip
    so porque a mensagem contem "nao encontrado".
    """
    blob = f"{name or ''} {error or ''}".lower()
    return any(h in blob for h in STRONG_SOURCES_HINTS)


def _is_soft_error(error: str, scanner_name: str = "") -> bool:
    """Soft = opcional ausente / canal vazio. Nunca soft se fonte forte."""
    if _is_strong_source(scanner_name, error):
        return False
    e = (error or "").lower()
    return any(h in e for h in _SOFT_ERROR_HINTS)


def build_coverage(
    findings: list[dict],
    *,
    is_admin: bool = True,
    quick: bool = False,
    skipped_groups: list[str] | None = None,
    only: list[str] | None = None,
    sig_version: str | None = None,
    sig_path: str | None = None,
) -> dict[str, Any]:
    """Agrega cobertura a partir dos findings e flags de execução."""
    skipped_groups = list(skipped_groups or [])
    errored = []          # erros duros (cegam fonte real)
    soft_errored = []     # opcional ausente (G HUB etc.) — não força INCONCLUSIVO
    clean = []
    suspicious = []

    for f in findings:
        status = f.get("status", "clean")
        name = f.get("name", "?")
        err = f.get("error") or ""
        entry = {
            "name": name,
            "status": status,
            "error": err,
            "n_items": len([i for i in f.get("items", []) if not i.get("meta_only")]),
        }
        if status == "error":
            if _is_soft_error(err, name):
                soft_errored.append(entry)
            else:
                errored.append(entry)
        elif status == "suspicious" or entry["n_items"] > 0:
            suspicious.append(entry)
        else:
            clean.append(entry)

    strong_errored = [
        e for e in errored
        if any(h in e["name"].lower() for h in STRONG_SOURCES_HINTS)
    ]

    incomplete_reasons: list[str] = []
    if not is_admin:
        incomplete_reasons.append(
            "Scan sem administrador — Prefetch, Amcache, BAM e Defender "
            "costumam falhar ou ficar incompletos."
        )
    if quick:
        incomplete_reasons.append(
            "Modo --quick: apenas scanners base; forensics/live/persistence "
            "não rodaram."
        )
    if only:
        incomplete_reasons.append(
            f"Modo --only limitado a: {', '.join(only)}."
        )
    for g in skipped_groups:
        incomplete_reasons.append(f"Grupo desligado: {g}.")
    # Só erros DUROS reduzem cobertura / forçam INCONCLUSIVO.
    # Soft (mouse software não instalado, base de hashes vazia) é skip.
    if errored:
        incomplete_reasons.append(
            f"{len(errored)} checagem(ns) com erro real "
            f"(cobertura reduzida)."
        )
    if strong_errored and is_admin:
        incomplete_reasons.append(
            "Fontes fortes com erro: "
            + ", ".join(e["name"] for e in strong_errored[:6])
            + ("…" if len(strong_errored) > 6 else "")
            + "."
        )

    incomplete = bool(incomplete_reasons)
    # "cego para forensics fortes" — sem admin OU erros em fontes fortes
    blind_strong = (not is_admin) or bool(strong_errored)

    return {
        "is_admin": is_admin,
        "quick": quick,
        "only": only or [],
        "skipped_groups": skipped_groups,
        "total_scanners": len(findings),
        # soft_errored conta como "ok" pro n_ok (skip de opcional)
        "n_ok": len(clean) + len(suspicious) + len(soft_errored),
        "n_suspicious": len(suspicious),
        "n_clean": len(clean),
        "n_error": len(errored),
        "n_soft_skip": len(soft_errored),
        "errored": errored,
        "soft_errored": soft_errored,
        "strong_errored": strong_errored,
        "incomplete": incomplete,
        "blind_strong": blind_strong,
        "reasons": incomplete_reasons,
        "sig_version": sig_version,
        "sig_path": sig_path,
    }


def coverage_forces_inconclusive(coverage: dict, verdict_label: str) -> bool:
    """True se um LIMPO deve virar INCONCLUSIVO pela cobertura.

    Só força quando a cobertura está realmente cega em fonte forte
    (sem admin, --quick/--only, ou erro duro em Prefetch/Amcache/BAM…).
    Erro em scanner secundário (PCA vazio, Task Execlog) NÃO invalida LIMPO.
    """
    if not coverage:
        return False
    if verdict_label != "LIMPO":
        return False
    # Cegueira real em forensics fortes
    if coverage.get("blind_strong"):
        return True
    # Modos limitados de execução
    if not coverage.get("is_admin"):
        return True
    if coverage.get("quick") or coverage.get("only"):
        return True
    if coverage.get("skipped_groups"):
        return True
    # Erros duros em fontes FORTES (já em strong_errored → blind_strong)
    # Erros duros em fontes fracas: incomplete pode ser True pro painel,
    # mas NÃO promove LIMPO → INCONCLUSIVO.
    return False


def apply_coverage_to_verdict(verdict: dict, coverage: dict | None) -> dict:
    """Mutável-cópia: ajusta veredito LIMPO → INCONCLUSIVO se cobertura falha."""
    if not coverage or not verdict:
        return verdict
    out = dict(verdict)
    out["coverage"] = coverage
    if coverage_forces_inconclusive(coverage, out.get("verdict", "")):
        out["verdict"] = "INCONCLUSIVO"
        out["color"] = "oklch(0.78 0.12 85)"
        out["inconclusive"] = True
        out["inconclusive_reason"] = "; ".join(coverage.get("reasons") or [])
    else:
        out["inconclusive"] = False
    return out
