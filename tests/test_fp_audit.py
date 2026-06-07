"""
Regressão de FALSOS POSITIVOS por colisão de marca/produto.

Auditoria encontrou keywords de palavra-única que colidiam com marcas
legítimas — flagando software/conteúdo inocente como executor (HIGH!):
  - "synapse"  → Razer Synapse (software de mouse, milhões de PCs)
  - "ronix"    → Ronix (marca de wakeboard)
  - "valex"    → Valex (marca de cabos)

Corrigido removendo a palavra solta e mantendo variantes específicas
(.exe / "x executor" / domínios). Estes testes garantem que:
  1. As colisões NÃO disparam mais.
  2. Os executores REAIS continuam detectados pelas variantes.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matching  # noqa: E402


def setup_module(_):
    matching.invalidate()


# Termos LEGÍTIMOS que colidiam — não podem casar
BRAND_COLLISIONS = [
    "razer synapse",
    "razersynapse.exe",
    "RazerSynapse.exe-A1B2C3D4.pf",
    "C:\\Program Files\\Razer\\Synapse3\\RazerSynapse.exe",
    "ronix wakeboard 2024",
    "ronix bindings",
    "ronix wake",
    "valex cables",
    "valex electronics",
]


def test_brand_collisions_do_not_false_positive():
    for t in BRAND_COLLISIONS:
        kw, sev = matching.match_keyword(t)
        assert kw is None, f"FALSO POSITIVO de marca: {t!r} casou com {kw!r} ({sev})"


# Executores REAIS que precisam continuar sendo detectados (via variantes)
EXECUTOR_VARIANTS = [
    ("synapse x", "synapse x"),
    ("synapsex", "synapsex"),
    ("SYNAPSE.EXE-A1B2C3D4.pf", "synapse.exe"),   # Prefetch-style
    ("synapse.exe", "synapse.exe"),
    ("ronix executor", "ronix executor"),
    ("RONIX.EXE-5678.pf", "ronix.exe"),
    ("ronix.cc", "ronix.cc"),
    ("valex executor", "valex executor"),
    ("VALEX.EXE-1234.pf", "valex.exe"),
]


def test_executors_still_detected_via_variants():
    for text, expected in EXECUTOR_VARIANTS:
        kw, sev = matching.match_keyword(text)
        assert kw == expected, f"{text!r} -> {kw!r} (esperado {expected!r}) — perdeu cobertura"
        assert sev == "high"


# ----- Domínio: substring de domínio maior NÃO pode casar -----

def test_domain_boundary_no_substring_fp():
    """wave.gg não pode casar soundwave.gg etc. (era FP de substring)."""
    cases_no = [
        ("wave.gg", "soundwave.gg/music"),
        ("wave.cc", "heatwave.cc"),
        ("wave.dev", "mywave.dev"),
        ("sense.gg", "nonsense.gg"),
        ("coral.gg", "mycoral.gg"),
    ]
    for dom, text in cases_no:
        assert not matching.domain_in_text(dom, text), \
            f"FP de domínio: {dom!r} casou {text!r}"


def test_domain_boundary_real_domains_match():
    """Domínio real e subdomínio legítimo DEVEM casar."""
    cases_yes = [
        ("wave.gg", "wave.gg"),
        ("wave.gg", "https://wave.gg/download"),
        ("wave.gg", "data.wave.gg"),        # subdomínio real
        ("solara.cc", "baixou de solara.cc hoje"),
        ("xeno.now", "sub.xeno.now"),
    ]
    for dom, text in cases_yes:
        assert matching.domain_in_text(dom, text), \
            f"perdeu match de domínio: {dom!r} em {text!r}"


# ----- word_in_text: fronteira de palavra para listas de substring -----

def test_word_in_text_boundary():
    assert matching.word_in_text("wipe", "wipe.exe")
    assert matching.word_in_text("shred", "shred.exe")
    assert not matching.word_in_text("wipe", "swipe.exe")     # era FP
    assert not matching.word_in_text("shred", "shredder pics")  # era FP


# ----- command_history não pode bypassar o matching central -----

def test_command_history_uses_central_matching():
    """command_history fazia substring de EXECUTOR_KEYWORDS/SUSPICIOUS_DOMAINS,
    bypassando word-boundary. Agora usa o matching central — sem FP."""
    import command_history as ch
    # FPs que o substring causava:
    assert ch._match_in_line("cd C:/solarapanel/docs")[0] is None
    assert ch._match_in_line("visited soundwave.gg yesterday")[0] is None
    # detecção real preservada:
    assert ch._match_in_line("run solara.exe")[0] is not None
    kw, sev = ch._match_in_line("iex(downloadstring https://solara.cc/x)")
    assert kw is not None and sev == "high"
