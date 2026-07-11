"""
Cobertura do scan: quais checagens rodaram, falharam, ou foram puladas.

Um veredito LIMPO com fontes cegas é INCONCLUSIVO — esta module materializa
isso pra console, HTML e Markdown.
"""

from __future__ import annotations

from typing import Any


# Fontes "fortes" que tipicamente exigem admin / SysMain / Event Log
STRONG_SOURCES_HINTS = (
    "prefetch", "amcache", "bam", "defender", "recycle", "lixeira",
    "usn", "winevent", "event", "service",
)


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
    errored = []
    clean = []
    suspicious = []

    for f in findings:
        status = f.get("status", "clean")
        name = f.get("name", "?")
        entry = {
            "name": name,
            "status": status,
            "error": f.get("error") or "",
            "n_items": len([i for i in f.get("items", []) if not i.get("meta_only")]),
        }
        if status == "error":
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
    if errored:
        incomplete_reasons.append(
            f"{len(errored)} checagem(ns) retornaram erro "
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
        "n_ok": len(clean) + len(suspicious),
        "n_suspicious": len(suspicious),
        "n_clean": len(clean),
        "n_error": len(errored),
        "errored": errored,
        "strong_errored": strong_errored,
        "incomplete": incomplete,
        "blind_strong": blind_strong,
        "reasons": incomplete_reasons,
        "sig_version": sig_version,
        "sig_path": sig_path,
    }


def coverage_forces_inconclusive(coverage: dict, verdict_label: str) -> bool:
    """True se um LIMPO deve virar INCONCLUSIVO pela cobertura."""
    if not coverage:
        return False
    if verdict_label != "LIMPO":
        return False
    return bool(coverage.get("incomplete") or coverage.get("blind_strong"))


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
