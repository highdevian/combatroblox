"""
Testes do Confidence Engine (evidence.py).

Foco em garantir:
  - target_id resolve corretamente (sha256 > path > executor canon > raw)
  - Aliases canonizam variantes ("solara.exe" → "solara")
  - Clusters mergeiam path:* em executor:* quando aplicável
  - Verdict respeita FP protection (1 fonte só nunca confirma sem critical)
  - Score com diminishing returns + bônus de diversidade
"""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence as ev  # noqa: E402


# ============================== Helpers ==============================

def _item(label="", matched="", severity="high", timestamp="", confidence=80, pe_info=None):
    it = {
        "label": label,
        "detail": "",
        "matched": matched,
        "severity": severity,
        "timestamp": timestamp,
        "confidence": confidence,
    }
    if pe_info:
        it["pe_info"] = pe_info
    return it


def _finding(name, items):
    return {"name": name, "items": items, "status": "suspicious", "description": "", "summary": ""}


# ============================== Aliases ==============================

def test_canonicalize_strips_common_suffixes():
    assert ev._canonicalize_executor_name("solara.exe") == "solara"
    assert ev._canonicalize_executor_name("Solara Executor") == "solara"
    assert ev._canonicalize_executor_name("Wave.cx") == "wave"
    assert ev._canonicalize_executor_name("xeno hub") == "xeno"
    assert ev._canonicalize_executor_name("krnl.dll") == "krnl"


def test_canonicalize_preserves_protected_names():
    # 'arceus x' não pode virar 'arceus' (pokémon)
    assert ev._canonicalize_executor_name("arceus x") == "arceus x"
    assert ev._canonicalize_executor_name("oxygen u") == "oxygen u"
    assert ev._canonicalize_executor_name("trigon evo") == "trigon evo"


def test_resolve_alias_unifies_variants():
    """Todas estas variantes devem resolver para o mesmo ID canônico."""
    canon = ev.resolve_alias("solara")
    assert canon == "solara"
    assert ev.resolve_alias("Solara.exe") == "solara"
    assert ev.resolve_alias("SOLARA EXECUTOR") == "solara"
    assert ev.resolve_alias("solara hub") == "solara"


def test_resolve_alias_returns_none_for_unknown():
    assert ev.resolve_alias("randomgame.exe") is None
    assert ev.resolve_alias("") is None


def test_top5_executors_canonicalize_consistently():
    """Solara, Xeno, Wave, Velocity, Ronix — TODAS as variantes devem
    convergir pro mesmo ID canônico. Sem isso a unificação por cluster
    falha e o supervisor vê fragmentação."""
    ev.invalidate_aliases()
    cases = {
        "solara":   ["solara", "Solara.exe", "Solara Executor", "solara hub", "solara.cc", "solaraexec", "solaralauncher"],
        "xeno":     ["xeno.exe", "xeno executor", "xeno hub", "xeno.now", "xeno.lat", "xeno.gg", "xeno.cc"],
        "wave":     ["wave executor", "wave.exe", "wave.cx", "wave hub", "wave.gg", "waveexec"],
        "velocity": ["velocity executor", "velocity.exe", "velocity hub", "velocity.cx", "velocity.gg", "velocityexec"],
        "ronix":    ["ronix", "ronix.exe", "ronix executor", "ronix hub", "ronix.cc", "ronix.gg", "ronixexec"],
    }
    for canon, variants in cases.items():
        for v in variants:
            got = ev.resolve_alias(v)
            assert got == canon, f"{v!r} → {got!r} (esperado {canon!r})"


# ============================== target_id ==============================

def test_target_id_prefers_sha256():
    it = _item(
        label="C:\\Users\\bob\\Downloads\\anything.exe",
        matched="some-other-match",
        pe_info={"sha256": "a" * 64, "path": "C:\\Users\\bob\\Downloads\\anything.exe"},
    )
    tid, label, kind = ev.compute_target_id(it)
    assert tid.scheme == "sha256"
    assert tid.value == "a" * 64


def test_target_id_falls_back_to_path():
    it = _item(label=r"C:\Users\bob\AppData\Local\Solara\Solara.exe", matched="solara")
    tid, label, kind = ev.compute_target_id(it)
    assert tid.scheme == "path"
    assert "solara" in tid.value.lower()
    assert tid.value == tid.value.lower()  # normalizado


def test_target_id_falls_back_to_executor_canon():
    it = _item(label="[BAM] solara.exe rodou", matched="solara.exe")
    tid, label, kind = ev.compute_target_id(it)
    assert tid.scheme == "executor"
    assert tid.value == "solara"


def test_target_id_byovd_classified_correctly():
    it = _item(label="kernel driver carregado", matched="driver-byovd:winring0", severity="critical")
    tid, label, kind = ev.compute_target_id(it)
    assert kind == "byovd"


def test_target_id_normalizes_nt_paths():
    it = _item(label=r"\??\C:\Windows\System32\drivers\winring0.sys", matched="x")
    tid, _, _ = ev.compute_target_id(it)
    assert tid.scheme == "path"
    assert tid.value.startswith("c:\\")  # \??\ foi removido


# ============================== Adapter ==============================

def test_adapter_source_slug_mapping():
    """Adapter deve mapear nomes de scanner pra slugs conhecidos."""
    cases = [
        ("Prefetch", "prefetch"),
        ("Amcache (InventoryApplicationFile)", "amcache"),
        ("BAM — Background Activity Monitor", "bam"),
        ("USN Journal", "usn_journal"),
        ("Kernel Drivers", "kernel_drivers"),
        ("Roblox Logs", "roblox_logs"),
        ("Browser History (Chrome)", "browser_history"),
    ]
    for name, expected in cases:
        assert ev._source_slug_from_name(name) == expected, f"{name} → expected {expected}"


def test_adapter_skips_meta_only():
    findings = [_finding("Prefetch", [
        {"label": "[INFO] header", "meta_only": True, "severity": "low", "matched": "x"},
        _item(label="real hit", matched="solara"),
    ])]
    evs = ev.findings_to_evidences(findings)
    assert len(evs) == 1
    assert evs[0].raw["label"] == "real hit"


# ============================== Clustering ==============================

def test_cluster_merges_path_into_executor():
    """O mesmo Solara aparece como path em Prefetch e executor canon em BAM.
    Deve virar 1 cluster só."""
    findings = [
        _finding("Prefetch", [_item(label=r"C:\Windows\Prefetch\SOLARA.EXE-A1B2C3D4.pf", matched="solara")]),
        _finding("BAM", [_item(label="[BAM] solara.exe", matched="solara.exe")]),
        _finding("Amcache", [_item(label=r"C:\Users\bob\AppData\Local\Solara\Solara.exe", matched="solara executor")]),
    ]
    evs = ev.findings_to_evidences(findings)
    clusters = ev.build_clusters(evs)
    assert len(clusters) == 1
    c = clusters[0]
    assert c.n_sources == 3
    assert c.target_id.scheme == "executor"
    assert c.target_id.value == "solara"
    assert c.label == "Solara"


def test_cluster_verdict_confirmed_needs_multiple_sources():
    """Verdict CONFIRMED exige ≥2 fontes E score ≥40 (sem critical),
    ou ≥3 fontes E score ≥40. 1 fonte com 5 hits nunca confirma."""
    # 5 hits high da mesma fonte (Prefetch)
    findings = [_finding("Prefetch", [
        _item(label="hit1", matched=f"solara"),
        _item(label="hit2", matched="solara.exe"),
        _item(label="hit3", matched="krnl"),
        _item(label="hit4", matched="krnl.exe"),
        _item(label="hit5", matched="xeno.exe"),
    ])]
    evs = ev.findings_to_evidences(findings)
    clusters = ev.build_clusters(evs)
    # Cada hit é executor diferente → vários clusters de 1 fonte só
    for c in clusters:
        assert c.verdict in ("WEAK", "SUSPECT"), \
            f"Cluster {c.label} com 1 fonte virou {c.verdict} (deveria ser cap em SUSPECT)"


def test_cluster_single_source_capped_at_suspect():
    """1 hit high em 1 fonte → no máximo SUSPECT."""
    findings = [_finding("Amcache", [_item(matched="solara", severity="high", confidence=90)])]
    evs = ev.findings_to_evidences(findings)
    clusters = ev.build_clusters(evs)
    assert len(clusters) == 1
    assert clusters[0].verdict in ("WEAK", "SUSPECT")


def test_cluster_critical_alone_is_detected():
    """1 critical isolado vira DETECTED (não confirma sozinho, mas é forte)."""
    findings = [_finding("Kernel Drivers", [
        _item(label=r"\??\C:\Windows\System32\drivers\winring0.sys",
              matched="driver-byovd:winring0", severity="critical")
    ])]
    evs = ev.findings_to_evidences(findings)
    clusters = ev.build_clusters(evs)
    assert len(clusters) == 1
    c = clusters[0]
    assert c.has_critical
    assert c.verdict == "DETECTED"
    assert c.confidence_pct >= 80


def test_cluster_critical_plus_2nd_source_confirms():
    """1 critical + 1 outra fonte qualquer = CONFIRMED."""
    findings = [
        _finding("Kernel Drivers", [_item(matched="driver-byovd:winring0", severity="critical", label=r"C:\drivers\winring0.sys")]),
        _finding("USN Journal", [_item(matched="usn:winring0", severity="high", label=r"C:\drivers\winring0.sys")]),
    ]
    evs = ev.findings_to_evidences(findings)
    clusters = ev.build_clusters(evs)
    # winring0 deve formar 1 cluster (mesmo path)
    top = clusters[0]
    assert top.has_critical
    assert top.n_sources == 2
    assert top.verdict == "CONFIRMED"


def test_cluster_confirms_with_multi_source_high():
    """5 fontes batendo no Solara, todas 'high', sem critical = CONFIRMED."""
    findings = [
        _finding("Prefetch", [_item(label=r"C:\Windows\Prefetch\SOLARA.EXE-AAAA1111.pf", matched="solara")]),
        _finding("Amcache", [_item(label=r"C:\Users\bob\Solara\Solara.exe", matched="solara executor")]),
        _finding("BAM", [_item(label="[BAM] solara.exe", matched="solara.exe")]),
        _finding("USN Journal", [_item(label=r"USN: C:\Users\bob\Solara\Solara.exe", matched="usn:solara")]),
        _finding("Browser History (Chrome)", [_item(label="[Chrome DOWNLOAD] solara from solara.cc", matched="solara")]),
    ]
    evs = ev.findings_to_evidences(findings)
    clusters = ev.build_clusters(evs)
    assert len(clusters) == 1
    c = clusters[0]
    assert c.target_id.value == "solara"
    assert c.n_sources == 5
    assert c.verdict == "CONFIRMED"
    assert c.confidence_pct >= 90


def test_cluster_score_diminishing_returns_within_source():
    """5 hits da mesma fonte valem menos que 5 hits de 5 fontes diferentes."""
    findings_same = [_finding("Prefetch", [
        _item(label=f"hit{i}", matched="solara") for i in range(5)
    ])]
    findings_diff = [
        _finding("Prefetch", [_item(label=r"C:\Windows\Prefetch\SOLARA.EXE-AAAA1111.pf", matched="solara")]),
        _finding("Amcache", [_item(label=r"C:\Users\bob\Solara\Solara.exe", matched="solara")]),
        _finding("BAM", [_item(label="[BAM] solara.exe", matched="solara")]),
        _finding("USN Journal", [_item(label=r"USN: solara", matched="solara")]),
        _finding("Roblox Logs", [_item(label="exit", matched="solara")]),
    ]
    evs_same = ev.findings_to_evidences(findings_same)
    evs_diff = ev.findings_to_evidences(findings_diff)
    c_same = ev.build_clusters(evs_same)[0]
    c_diff = ev.build_clusters(evs_diff)[0]
    assert c_diff.score > c_same.score, \
        f"5 fontes ({c_diff.score}) deveria valer mais que 5 hits 1 fonte ({c_same.score})"


def test_cluster_label_preserves_executor_canonical():
    """Cluster executor:solara deve ter label 'Solara', não basename
    aleatório como 'solara.exe-aaaa1111.pf'."""
    findings = [
        _finding("Prefetch", [_item(label=r"C:\Windows\Prefetch\SOLARA.EXE-A1B2C3D4.pf", matched="solara")]),
        _finding("BAM", [_item(label="[BAM] solara.exe", matched="solara.exe")]),
    ]
    evs = ev.findings_to_evidences(findings)
    clusters = ev.build_clusters(evs)
    assert clusters[0].label == "Solara"


def test_cluster_ordering_confirmed_first():
    findings = [
        # 1 fraco
        _finding("Roblox Logs", [_item(matched="weak", severity="low")]),
        # 1 critical → DETECTED (1 fonte)
        _finding("Kernel Drivers", [_item(matched="driver-byovd:winring0", severity="critical", label=r"C:\drivers\winring0.sys")]),
        # CONFIRMED (multi-source solara)
        _finding("Prefetch", [_item(label=r"C:\Windows\Prefetch\SOLARA.EXE-X.pf", matched="solara")]),
        _finding("Amcache", [_item(label=r"C:\Users\bob\Solara\Solara.exe", matched="solara")]),
        _finding("BAM", [_item(label="[BAM] solara.exe", matched="solara.exe")]),
    ]
    evs = ev.findings_to_evidences(findings)
    clusters = ev.build_clusters(evs)
    verdicts = [c.verdict for c in clusters]
    assert verdicts[0] == "CONFIRMED"  # solara
    assert "WEAK" in verdicts[-1] or "SUSPECT" in verdicts[-1] or verdicts[-1] == "WEAK"


# ============================== Cluster.score sanity ==============================

def test_cluster_score_zero_when_empty():
    c = ev.Cluster(target_id=ev.TargetId("raw", "x"), label="x", kind="executor")
    assert c.score == 0.0
    assert c.verdict == "WEAK"


def test_cluster_first_last_seen_extract_timestamps():
    e1 = ev.Evidence(source="prefetch", source_weight=0.9, severity="high",
                    target_id=ev.TargetId("executor", "solara"), target_label="Solara",
                    target_kind="executor", confidence=80,
                    timestamp=datetime(2026, 6, 3, 14, 23, 0), raw={})
    e2 = ev.Evidence(source="bam", source_weight=0.9, severity="high",
                    target_id=ev.TargetId("executor", "solara"), target_label="Solara",
                    target_kind="executor", confidence=80,
                    timestamp=datetime(2026, 6, 3, 14, 25, 0), raw={})
    c = ev.Cluster(target_id=ev.TargetId("executor", "solara"), label="Solara",
                   kind="executor", evidences=[e1, e2])
    assert c.first_seen == datetime(2026, 6, 3, 14, 23, 0)
    assert c.last_seen == datetime(2026, 6, 3, 14, 25, 0)


# ============================== FP protection (PC limpo) ==============================

def test_clean_pc_no_clusters():
    """PC limpo (sem matches) — não deve gerar cluster nenhum."""
    findings = [_finding("Prefetch", [])]
    evs = ev.findings_to_evidences(findings)
    clusters = ev.build_clusters(evs)
    assert clusters == []


def test_isolated_low_match_stays_weak():
    """1 hit low/medium isolado em 1 fonte = WEAK (não vira SUSPECT)."""
    findings = [_finding("Amcache", [_item(matched="rscripts", severity="low")])]
    evs = ev.findings_to_evidences(findings)
    clusters = ev.build_clusters(evs)
    assert clusters[0].verdict == "WEAK"


# ============================== Regression: critical no score ==============================

def test_regression_critical_severity_contributes_to_score():
    """REGRESSÃO: scan_kernel_drivers e futuros podem emitir critical.
    Antes do fix: SEVERITY_WEIGHT não tinha 'critical' → peso 0 → score zero.
    Depois do fix: critical pesa 25 → score forte mesmo com 1 evidência."""
    from fp_filter import compute_verdict, SEVERITY_WEIGHT, SEVERITY_ORDER

    assert "critical" in SEVERITY_WEIGHT, "critical foi removido de SEVERITY_WEIGHT"
    assert SEVERITY_WEIGHT["critical"] >= SEVERITY_WEIGHT["high"], \
        "critical deveria pesar pelo menos tanto quanto high"
    assert "critical" in SEVERITY_ORDER, "critical foi removido de SEVERITY_ORDER"

    # 1 evidência critical isolada deve gerar score > 0 e verdict não-LIMPO
    findings = [{
        "name": "Kernel Drivers",
        "status": "suspicious",
        "items": [{
            "label": r"C:\Windows\System32\drivers\winring0.sys",
            "matched": "driver-byovd:winring0",
            "severity": "critical",
            "confidence": 95,
            "timestamp": "",
        }],
        "summary": "",
        "description": "",
    }]
    v = compute_verdict(findings)
    assert v["score"] > 0, f"critical não contribuiu ao score: {v}"
    assert v.get("critical", 0) == 1, "contagem de critical não está em verdict"
    assert v["verdict"] != "LIMPO", f"1 evidência critical não saiu de LIMPO: {v}"


def test_regression_two_criticals_confirm_immediately():
    """2+ críticos cravam veredito sem cross-correlation."""
    from fp_filter import compute_verdict
    findings = [{
        "name": "Kernel Drivers",
        "status": "suspicious",
        "items": [
            {"label": "win0", "matched": "driver-byovd:winring0", "severity": "critical", "confidence": 95},
            {"label": "rwd", "matched": "driver-byovd:rwdrv",     "severity": "critical", "confidence": 95},
        ],
        "summary": "", "description": "",
    }]
    v = compute_verdict(findings)
    assert v["verdict"] == "CHEATER CONFIRMADO", f"2 críticos deveriam confirmar: {v}"


def test_summarize_clusters_counts_correctly():
    findings = [
        _finding("Prefetch", [_item(label=r"C:\Windows\Prefetch\SOLARA.EXE-X.pf", matched="solara")]),
        _finding("Amcache", [_item(label=r"C:\Users\bob\Solara\Solara.exe", matched="solara")]),
        _finding("BAM", [_item(label="[BAM] solara.exe", matched="solara.exe")]),
        _finding("Roblox Logs", [_item(matched="exit-anomaly", severity="low")]),
    ]
    evs = ev.findings_to_evidences(findings)
    clusters = ev.build_clusters(evs)
    summary = ev.summarize_clusters(clusters)
    assert summary["n_confirmed"] >= 1
    assert summary["top_cluster"].target_id.value == "solara"
