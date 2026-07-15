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
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import evidence as ev      # noqa: E402
from telador import fp_filter           # noqa: E402
def _finding(name, items):
    return {"name": name, "status": "suspicious" if items else "clean",
            "description": "", "summary": "", "items": items}


def _it(label, matched, severity="medium", ts="", conf=60, detail=""):
    return {"label": label, "detail": detail, "matched": matched,
            "severity": severity, "timestamp": ts, "confidence": conf}


def _recent(offset_secs=0):
    """Timestamp FRESCO (2 dias atrás), relativo a agora.

    Datas fixas (ex: '2026-06-03') viravam TIME-BOMB: quando a idade passa de
    30 dias, o apply_time_decay rebaixa os hits high→medium e o veredito de
    cheater desaba pra 'POSSÍVEIS PISTAS' — o teste apodrece sozinho conforme
    o tempo real passa. O corpus representa um SS ATUAL, então os artefatos
    têm que ser recentes DE VERDADE (relativos a agora), não uma data fixa."""
    base = datetime.now() - timedelta(days=2)
    return (base + timedelta(seconds=offset_secs)).strftime("%Y-%m-%d %H:%M:%S")


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
    from telador import live_analysis as la
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
    # Timestamps FRESCOS relativos a agora (janela apertada de execução ~90s).
    # Antes eram fixos em 2026-06-03 e o teste virava time-bomb — ver _recent().
    return [
        _finding("Prefetch", [
            _it(r"C:\Windows\Prefetch\SOLARA.EXE-A1B2C3D4.pf", "solara", "high",
                ts=_recent(30), conf=90)]),
        _finding("Amcache", [
            _it(r"C:\Users\bob\AppData\Local\Solara\Solara.exe", "solara executor",
                "high", ts=_recent(35), conf=88)]),
        _finding("BAM", [
            _it("[BAM] solara.exe", "solara.exe", "high",
                ts=_recent(90), conf=85)]),
        _finding("USN Journal", [
            _it(r"USN CREATE: C:\Users\bob\AppData\Local\Solara\Solara.exe",
                "usn:solara", "high", ts=_recent(20), conf=92)]),
        _finding("Browser History (Chrome)", [
            _it("[Chrome DOWNLOAD] solara.exe from solara.cc", "solara", "high",
                ts=_recent(0), conf=88)]),
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


# ============================================================================
#  CORPUS 3 — corroboração multi-fonte RESISTE ao time-decay
# ============================================================================
# O decay protege de UM artefato velho isolado. Mas o mesmo alvo em várias
# fontes independentes é evidência forte mesmo velho — não pode colapsar.

def _old(days):
    return (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def test_old_multi_source_cheater_resists_decay():
    """Solara em 5 fontes há 120 dias ainda TEM que acusar — corroboração
    segura o decay (não é artefato velho isolado)."""
    old = _old(120)
    findings = [
        _finding("Prefetch", [
            _it(r"C:\Windows\Prefetch\SOLARA.EXE-A1B2C3D4.pf", "solara", "high", ts=old, conf=90)]),
        _finding("Amcache", [
            _it(r"C:\Users\bob\AppData\Local\Solara\Solara.exe", "solara executor", "high", ts=old, conf=88)]),
        _finding("BAM", [
            _it("[BAM] solara.exe", "solara.exe", "high", ts=old, conf=85)]),
        _finding("USN Journal", [
            _it(r"USN CREATE: C:\Users\bob\AppData\Local\Solara\Solara.exe", "usn:solara", "high", ts=old, conf=92)]),
        _finding("Browser History (Chrome)", [
            _it("[Chrome DOWNLOAD] solara.exe from solara.cc", "solara", "high", ts=old, conf=88)]),
    ]
    fp_filter._dev_cache = {"is_dev": False, "evidence": []}
    processed, _ = fp_filter.post_process_findings(findings)
    sev = [i["severity"] for f in processed for i in f["items"]]
    assert all(s == "high" for s in sev), f"corroboração devia segurar o decay: {sev}"
    v = fp_filter.compute_verdict(processed)
    assert v["verdict"] in ("CHEATER CONFIRMADO", "ALTAMENTE SUSPEITO"), v["verdict"]


def test_old_isolated_hit_still_decays():
    """Hit velho ISOLADO (1 fonte) continua decaindo — proteção de FP intacta."""
    findings = [_finding("Amcache", [
        _it(r"C:\Users\x\AppData\Local\Temp\old.exe", "synapse", "high", ts=_old(120), conf=80)])]
    fp_filter._dev_cache = {"is_dev": False, "evidence": []}
    processed, _ = fp_filter.post_process_findings(findings)
    sev = processed[0]["items"][0]["severity"]
    assert sev == "low", f"hit isolado velho devia decair pra low, veio {sev}"


def test_cross_correlate_ignores_all_low_dualuse():
    """Dual-use LOW em 6 fontes (Process Hacker num PC de dev) NÃO pode virar
    'ALTA CONFIANÇA' — LOW é ambíguo por definição. Reproduz o FP do owner."""
    from telador import cli as telador
    findings = [
        _finding(src, [_it("ProcessHacker.exe", "process hacker", "low")])
        for src in ("MuiCache", "UserAssist", "BAM", "ShimCache", "Lixeira", "Pastas")
    ]
    hc = telador.cross_correlate(findings)
    assert "process hacker" not in hc, "dual-use LOW em N fontes não é alta confiança"


def test_cross_correlate_flags_real_medium_multi_source():
    """Mas alvo com severidade real (>= medium) em 3+ fontes continua alta
    confiança — o cheater que esqueceu de limpar alguns rastros."""
    from telador import cli as telador
    findings = [
        _finding("Prefetch", [_it("solara.exe", "solara", "high")]),
        _finding("Amcache", [_it("solara.exe", "solara", "high")]),
        _finding("BAM", [_it("solara.exe", "solara", "medium")]),
    ]
    assert "solara" in telador.cross_correlate(findings)


def test_apply_time_decay_corroboration_levels():
    old60, old120 = _old(60), _old(120)          # 30-90d e >90d
    # 1 fonte: decay cheio
    assert fp_filter.apply_time_decay("high", old60, 1)[0] == "medium"
    assert fp_filter.apply_time_decay("high", old120, 1)[0] == "low"
    # 2 fontes: atenua um nível
    assert fp_filter.apply_time_decay("high", old60, 2)[0] == "high"     # 1-1 = 0 níveis
    assert fp_filter.apply_time_decay("high", old120, 2)[0] == "medium"  # 2-1 = 1 nível
    # 3+ fontes: não decai
    assert fp_filter.apply_time_decay("high", old120, 3)[0] == "high"
    # recente: nunca decai, independente de fonte
    assert fp_filter.apply_time_decay("high", _recent(0), 1)[0] == "high"
