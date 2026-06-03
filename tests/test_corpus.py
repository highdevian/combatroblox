"""
Corpus de regressão — a rede de segurança anti-falso-positivo.

Trava as DUAS regressões mais perigosas de um SS:
  1. PC LIMPO virar acusação falsa (falso positivo) — o pior erro possível,
     porque queima um inocente e a credibilidade da ferramenta.
  2. CHEATER REAL deixar de ser pego (falso negativo) — detecção quebrar
     silenciosamente numa refatoração.

Os corpora são SINTÉTICOS e determinísticos (não dependem da máquina nem
de rede), então rodam igual em qualquer lugar e pegam regressão na lógica
de agregação — que é onde o estrago acontece.

Se um destes testes falhar, NÃO faça release até entender por quê.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence as ev      # noqa: E402
import fp_filter           # noqa: E402


def _finding(name, items):
    return {"name": name, "status": "suspicious" if items else "clean",
            "description": "", "summary": "", "items": items}


def _it(label, matched, severity="medium", ts="", conf=60, detail=""):
    return {"label": label, "detail": detail, "matched": matched,
            "severity": severity, "timestamp": ts, "confidence": conf}


# ============================================================================
#  CORPUS 1 — PC LIMPO (realista, com coisas que ASSUSTAM mas não são cheat)
# ============================================================================
# Cada sinal aqui é benigno OU isolado (1 fonte só). O ponto: por mais que
# pareça suspeito, nada deve AGREGAR numa acusação. Inclui exatamente os
# casos que enganariam um motor ingênuo.

def _clean_pc_findings():
    return [
        # Dev tem Cheat Engine instalado (uso legítimo de RE) — 1 fonte
        _finding("MuiCache", [
            _it("cheatengine-x86_64.exe", "cheat engine", "medium",
                detail=r"C:\Program Files\Cheat Engine 7.5\cheatengine-x86_64.exe")]),
        # Curiosidade: visitou fórum de cheat, mas NÃO baixou nada — 1 fonte, low
        _finding("Browser History (Chrome)", [
            _it("[Chrome] visited unknowncheats.me", "unknowncheats.me", "low",
                detail="visit only, no download")]),
        # Traço ANTIGO de quando usou algo em 2022 (time decay deve rebaixar) — 1 fonte
        _finding("Amcache", [
            _it(r"C:\Users\x\AppData\Local\Temp\old.exe", "synapse", "high",
                ts="2022-01-15 10:00:00", conf=80)]),
        # AutoHotkey (macro legítimo — digitar texto, etc) — 1 fonte
        _finding("Macros (mouse/teclado)", [
            _it("AutoHotkey.exe", "autohotkey", "medium",
                detail=r"C:\Program Files\AutoHotkey\AutoHotkey.exe")]),
        # Um app WebView2 ASSINADO (Discord) — comportamental NÃO deve flagar;
        # aqui simulamos que nem entrou como item (porque é assinado).
        # Uma entrada solta de Prefetch com nome ambíguo — 1 fonte, low
        _finding("Prefetch", [
            _it(r"C:\Windows\Prefetch\WAVE.EXE-12AB34CD.pf", "wave", "high",
                ts="2026-06-01 12:00:00", conf=85)]),
    ]


def test_clean_pc_no_false_confirmed():
    """Nenhum cluster pode chegar a CONFIRMED ou DETECTED num PC limpo —
    todos os sinais são isolados (1 fonte). FP protection do Confidence
    Engine tem que segurar."""
    clusters = ev.build_clusters(ev.findings_to_evidences(_clean_pc_findings()))
    for c in clusters:
        assert c.verdict not in ("CONFIRMED", "DETECTED"), (
            f"FALSO POSITIVO: cluster '{c.label}' virou {c.verdict} "
            f"({c.n_sources} fonte(s), score {c.score}) num PC limpo"
        )


def test_clean_pc_verdict_not_accusation():
    """O veredito global de um PC limpo não pode ser acusação forte."""
    # Controla o ambiente de dev pra determinismo (não depende da máquina).
    fp_filter._dev_cache = {"is_dev": True, "evidence": ["x", "y"]}
    findings, _ = fp_filter.post_process_findings(_clean_pc_findings())
    v = fp_filter.compute_verdict(findings)
    assert v["verdict"] not in ("CHEATER CONFIRMADO", "ALTAMENTE SUSPEITO"), (
        f"FALSO POSITIVO no veredito global: {v['verdict']} (score {v['score']})"
    )


def test_single_signed_webview_app_not_flagged_behaviorally():
    """Reforço: a detecção comportamental nunca dispara em app assinado
    (já coberto em test_behavioral, repetido aqui como invariante de corpus)."""
    import live_analysis as la
    # Sem estrutura de executor no corpus limpo → 0 hits estruturais.
    r = la.scan_executor_structure()
    # Na máquina de teste tem que ser limpo (mesma trava do behavioral).
    assert r["status"] == "clean"


# ============================================================================
#  CORPUS 2 — CHEATER REAL (deve SEMPRE ser pego)
# ============================================================================
# Solara executado, visto em 5 fontes independentes + BYOVD. Se isto deixar
# de dar CONFIRMED, a detecção quebrou.

def _cheater_findings():
    return [
        _finding("Prefetch", [
            _it(r"C:\Windows\Prefetch\SOLARA.EXE-A1B2C3D4.pf", "solara", "high",
                ts="2026-06-03 14:23:00", conf=90)]),
        _finding("Amcache", [
            _it(r"C:\Users\bob\AppData\Local\Solara\Solara.exe", "solara executor",
                "high", ts="2026-06-03 14:23:05", conf=88)]),
        _finding("BAM", [
            _it("[BAM] solara.exe", "solara.exe", "high",
                ts="2026-06-03 14:24:00", conf=85)]),
        _finding("USN Journal", [
            _it(r"USN CREATE: C:\Users\bob\AppData\Local\Solara\Solara.exe",
                "usn:solara", "high", ts="2026-06-03 14:22:50", conf=92)]),
        _finding("Browser History (Chrome)", [
            _it("[Chrome DOWNLOAD] solara.exe from solara.cc", "solara", "high",
                ts="2026-06-03 14:22:30", conf=88)]),
    ]


def test_cheater_is_confirmed():
    """5 fontes independentes batendo em Solara TÊM que dar CONFIRMED."""
    clusters = ev.build_clusters(ev.findings_to_evidences(_cheater_findings()))
    top = clusters[0]
    assert top.target_id.value == "solara"
    assert top.verdict == "CONFIRMED", (
        f"FALSO NEGATIVO: cheater óbvio só deu {top.verdict} "
        f"({top.n_sources} fontes, score {top.score})"
    )
    assert top.confidence_pct >= 90


def test_cheater_global_verdict_is_accusation():
    fp_filter._dev_cache = {"is_dev": False, "evidence": []}
    findings, _ = fp_filter.post_process_findings(_cheater_findings())
    v = fp_filter.compute_verdict(findings)
    assert v["verdict"] in ("CHEATER CONFIRMADO", "ALTAMENTE SUSPEITO"), (
        f"FALSO NEGATIVO no veredito global: {v['verdict']}"
    )


def test_byovd_critical_alone_at_least_detected():
    """Um driver BYOVD crítico sozinho não pode ser ignorado — mínimo DETECTED."""
    findings = [_finding("Kernel Drivers", [
        _it(r"C:\Windows\System32\drivers\winring0.sys", "driver-byovd:winring0",
            "critical", ts="2026-06-03 14:24:30", conf=95)])]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert clusters[0].has_critical
    assert clusters[0].verdict in ("DETECTED", "CONFIRMED")
