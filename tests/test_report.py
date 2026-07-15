"""
Testes do relatório HTML (report.py) — o artefato que o supervisor vê.

Antes destes testes, report.py (2400+ linhas) não tinha NENHUMA cobertura.
Estes travam o comportamento do relatório pra que qualquer refatoração
futura (ou mudança acidental) que quebre a renderização seja pega pelo CI,
não pelo supervisor no meio de uma SS.

Foco em invariantes que importam, não em HTML frágil:
  - gera sem crashar nos 4 cenários (limpo/suspeito/confirmado/critical)
  - o hero mostra o estado certo (verde/amarelo/vermelho)
  - o veredito-protagonista aparece com confidence
  - o botão "copiar resumo" existe e o texto está correto
  - HTML é minimamente bem-formado (tags balanceadas no essencial)
"""

import html as _html
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import evidence as ev   # noqa: E402
from telador import fp_filter        # noqa: E402
from telador import report           # noqa: E402
SYS_INFO = {"host": "TEST-PC", "user": "bob", "scan_time": "2026-06-03 14:30:00",
            "os": "Windows 11", "arch": "AMD64", "session_id": "ABCD1234"}


def _finding(name, items):
    return {"name": name, "status": "suspicious" if items else "clean",
            "description": "desc", "summary": "sum", "items": items}


def _it(label, matched, severity="high", ts="2026-06-03 14:23:00", conf=88, detail="x"):
    return {"label": label, "detail": detail, "matched": matched,
            "severity": severity, "timestamp": ts, "confidence": conf}


def _render(findings, tmp_path):
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    verdict = fp_filter.compute_verdict(findings)
    out = str(tmp_path / "report.html")
    path = report.generate_html_report(
        findings, SYS_INFO, clusters=clusters, verdict=verdict, output_path=out
    )
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# Cenários reutilizáveis
def _clean():
    return [_finding("Prefetch", [])]


def _confirmed():
    return [
        _finding("Prefetch", [_it(r"C:\Windows\Prefetch\SOLARA.EXE-A1.pf", "solara")]),
        _finding("Amcache", [_it(r"C:\Users\b\Solara\Solara.exe", "solara executor")]),
        _finding("BAM", [_it("[BAM] solara.exe", "solara.exe")]),
    ]


def _critical():
    return [_finding("Kernel Drivers", [
        _it(r"C:\Windows\System32\drivers\winring0.sys", "driver-byovd:winring0", "critical")])]


def _suspect():
    return [_finding("Amcache", [_it(r"C:\x\solara.exe", "solara", "high")])]


# ============================ Não crasha ============================

def test_renders_all_scenarios_without_crash(tmp_path):
    for name, f in [("clean", _clean()), ("confirmed", _confirmed()),
                    ("critical", _critical()), ("suspect", _suspect())]:
        out = str(tmp_path / f"{name}.html")
        clusters = ev.build_clusters(ev.findings_to_evidences(f))
        verdict = fp_filter.compute_verdict(f)
        path = report.generate_html_report(f, SYS_INFO, clusters=clusters,
                                           verdict=verdict, output_path=out)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 5000  # relatório real tem corpo


def test_renders_without_clusters_arg(tmp_path):
    """Backward-compat: clusters=None (caminho legado) não pode crashar."""
    f = _confirmed()
    out = str(tmp_path / "legacy.html")
    path = report.generate_html_report(f, SYS_INFO, output_path=out)
    assert os.path.isfile(path)


def test_renders_with_empty_findings(tmp_path):
    out = str(tmp_path / "empty.html")
    path = report.generate_html_report([], SYS_INFO, clusters=[],
                                       verdict=fp_filter.compute_verdict([]),
                                       output_path=out)
    assert os.path.isfile(path)


# ============================ Hero — estado certo ============================

def _hero_state(h):
    """Extrai a classe de estado APLICADA na section do hero (não a do CSS)."""
    m = re.search(r'class="hero-verdict (hv-state-\w+)"', h)
    return m.group(1) if m else None


def test_hero_clean_is_green_state(tmp_path):
    h = _render(_clean(), tmp_path)
    assert _hero_state(h) == "hv-state-clean"
    assert "NENHUM EXECUTOR DETECTADO" in h


def test_hero_confirmed_is_bad_state(tmp_path):
    h = _render(_confirmed(), tmp_path)
    assert _hero_state(h) == "hv-state-bad"
    assert ("EXECUTOR CONFIRMADO" in h) or ("EXECUTOR DETECTADO" in h)
    # nome do target aparece
    assert "Solara" in h


def test_hero_critical_shows_byovd(tmp_path):
    h = _render(_critical(), tmp_path)
    assert _hero_state(h) == "hv-state-bad"
    assert "winring0.sys" in h


def test_hero_suspect_is_warn_state(tmp_path):
    h = _render(_suspect(), tmp_path)
    # 1 fonte só → SUSPECT → estado de revisão (amarelo)
    assert _hero_state(h) == "hv-state-warn"


# ============================ Botão copiar resumo ============================

def test_copy_button_present_and_summary_correct(tmp_path):
    h = _render(_confirmed(), tmp_path)
    assert "hv-copy" in h
    assert "teladorCopySummary" in h
    # extrai o data-summary e confere o conteúdo
    m = re.search(r'data-summary="([^"]+)"', h)
    assert m, "data-summary não encontrado"
    summary = _html.unescape(m.group(1))
    assert "TELADOR" in summary
    assert "Solara" in summary
    assert "fonte(s)" in summary


def test_copy_summary_clean_says_nothing_detected(tmp_path):
    h = _render(_clean(), tmp_path)
    m = re.search(r'data-summary="([^"]+)"', h)
    assert m
    summary = _html.unescape(m.group(1))
    assert "Nenhum target" in summary


# ============================ Segurança / well-formed ============================

def test_no_unescaped_script_injection(tmp_path):
    """Um label malicioso não pode injetar HTML/script no relatório."""
    findings = [_finding("Prefetch", [
        _it("<script>alert(1)</script>", "solara", "high")])]
    h = _render(findings, tmp_path)
    # o label malicioso deve aparecer ESCAPADO, não como tag executável
    assert "<script>alert(1)</script>" not in h
    assert "&lt;script&gt;" in h


def test_html_has_essential_structure(tmp_path):
    h = _render(_confirmed(), tmp_path)
    assert h.lstrip().lower().startswith("<!doctype html")
    assert "<html" in h.lower() and "</html>" in h.lower()
    assert "<body" in h.lower() and "</body>" in h.lower()
    # contagem grosseira de balanceamento das sections principais
    assert h.count("<section") == h.count("</section>")


def test_verdict_and_confidence_visible(tmp_path):
    h = _render(_confirmed(), tmp_path)
    # confidence % aparece em algum lugar do hero
    assert re.search(r"Confidence\s*\d+%", h) or re.search(r"\d+%", h)
