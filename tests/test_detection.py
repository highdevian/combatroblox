"""
Testes de detecção e anti-falso-positivo.

Trava as correções da auditoria: garante que executores reais continuam
sendo pegos E que software/jogos legítimos não disparam flag.

Rodar:  python -m pytest tests/ -q
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from matching import match_keyword  # noqa: E402


# --------------------------- Executores reais devem casar ---------------------------

REAL_EXECUTORS = [
    r"c:\users\x\downloads\krnl.exe",
    "wave executor",
    "Synapse X",
    "fluxus",
    "scriptware.dll",
    r"d:\tools\vegax.exe",
    "jjsploit",
    "wearedevs.net",
    "kdmapper",
    "xeno executor",
    "cryptic exec",
    "solara",
    "hydrogen-m",
]


def test_real_executors_match():
    for t in REAL_EXECUTORS:
        kw, sev = match_keyword(t)
        assert kw is not None, f"deveria casar executor real: {t!r}"


# --------------------------- Legítimos NÃO devem casar ---------------------------

LEGIT = [
    r"c:\program files\cryptic studios\game.exe",   # Star Trek Online / Neverwinter
    r"d:\games\xenoblade\save.dat",                  # série Xeno
    r"c:\nihon falcom\ys viii\ys8.exe",              # Nihon Falcom
    "argonauts legendary tales",                      # 'argon' não é substring solto
    "trigonometria_aula.pdf",                         # 'trigon'
    "scriptwarehouse inventory",                      # 'scriptware'
    r"c:\windows\system32\notepad.exe",
    r"c:\program files\google\chrome\chrome.exe",
    "calamari recipe.txt",                            # comida
    "",
]


def test_legit_not_flagged():
    for t in LEGIT:
        kw, sev = match_keyword(t)
        assert kw is None, f"FALSO POSITIVO: {t!r} casou {kw!r}"


def test_none_safe():
    assert match_keyword(None) == (None, None)
    assert match_keyword("") == (None, None)


# --------------------------- Database sanity ---------------------------

def test_removed_substring_keywords_absent():
    """Keywords soltas perigosas não podem voltar."""
    for k in ("xeno", "cryptic", "empyrean", "calamari", "nihon"):
        assert k not in database.EXECUTOR_KEYWORDS, f"{k} (solto) reintroduzido — FP!"


def test_specific_variants_present():
    """Variantes específicas que substituem os soltos devem existir."""
    for k in ("xeno executor", "cryptic exec", "calamari executor"):
        assert k in database.EXECUTOR_KEYWORDS, f"variante {k} sumiu"


def test_hyperv_macs_removed():
    """MACs Hyper-V não podem voltar (FP com WSL2/Docker/Sandbox)."""
    for mac in ("00:15:5D", "00:03:FF"):
        assert mac not in database.VM_MAC_PREFIXES, f"{mac} Hyper-V reintroduzido — FP!"


def test_generic_process_names_removed():
    """Process names genéricos que pegavam software legítimo."""
    for p in ("electron.exe", "sentinel.exe", "ninja.exe", "swift.exe", "apex.exe"):
        assert p not in database.EXECUTOR_PROCESS_NAMES, f"{p} reintroduzido — FP!"


def test_native_roblox_apis_not_high():
    """APIs nativas do Roblox não podem ser HIGH (usadas em jogos legítimos)."""
    for api in ("firetouchinterest", "fireclickdetector", "fireproximityprompt"):
        assert database.SCRIPT_RED_FLAGS.get(api) != "high", f"{api} não pode ser HIGH"


# --------------------------- Verdict ignora meta_only ---------------------------

def test_verdict_ignores_meta_only():
    import fp_filter
    findings = [{
        "name": "DLL Injection (Roblox)", "status": "clean",
        "items": [{
            "label": "[PROCESSO] PID 1 — RobloxPlayerBeta.exe",
            "detail": "ctx", "severity": "low", "matched": "roblox-running",
            "timestamp": "", "confidence": 50, "meta_only": True,
        }],
    }]
    v = fp_filter.compute_verdict(findings)
    assert v["score"] == 0, f"meta_only somou score: {v['score']}"
    assert v["low"] == 0, "meta_only contou como LOW"
    assert v["verdict"] == "LIMPO"


# --------------------------- Prova de SS ao vivo (#1) ---------------------------

def test_session_render_with_code():
    import report
    info = {"session_id": "A1B2C3D4", "session_code": "SUP-9988", "scan_time": "2026-05-30 12:00:00"}
    html = report._render_session(info, "deadbeef" * 8)
    assert "SUP-9988" in html and "A1B2C3D4" in html
    assert "código informado" in html  # estado verificado


def test_session_render_without_code_warns():
    import report
    info = {"session_id": "A1B2C3D4", "session_code": "", "scan_time": "x"}
    html = report._render_session(info, "")
    assert "NÃO verificada" in html  # avisa que faltou código


def test_session_not_shown_in_sysinfo_table():
    import report
    info = {"host": "pc", "session_id": "X", "session_code": "Y"}
    sys_html = report._render_system(info)
    # session_* têm card próprio, não devem poluir a tabela de sistema
    assert "session_id" not in sys_html and "session_code" not in sys_html


# --------------------------- Overlay / ESP externo (#4) ---------------------------

def test_overlay_scanner_runs():
    import live_analysis
    r = live_analysis.scan_overlay_windows()
    assert r["status"] in ("clean", "suspicious", "error")
    assert "name" in r and "items" in r


def test_overlay_whitelist_covers_common_apps():
    import live_analysis
    for app in ("discord.exe", "steam.exe", "obs64.exe", "nvcontainer.exe", "explorer.exe"):
        assert app in live_analysis.OVERLAY_WHITELIST, f"{app} deveria estar na whitelist de overlay"


# --------------------------- Assinaturas externas (signatures.json) ---------------------------

def test_external_signatures_merge(tmp_path):
    import json, database
    p = tmp_path / "signatures.json"
    p.write_text(json.dumps({
        "executor_keywords": {"zzznovoexec": "high", "ignorar_sev": "banana"},
        "executor_process_names": {"zzznovoexec.exe": "medium"},
        "naosei_secao": {"x": "high"},
    }), encoding="utf-8")

    added, err = database.load_external_signatures(str(p))
    try:
        assert err is None
        assert added == 2, f"esperava 2 mescladas, veio {added}"  # severidade inválida ignorada
        assert database.EXECUTOR_KEYWORDS.get("zzznovoexec") == "high"
        assert database.EXECUTOR_PROCESS_NAMES.get("zzznovoexec.exe") == "medium"
        assert "ignorar_sev" not in database.EXECUTOR_KEYWORDS
    finally:
        database.EXECUTOR_KEYWORDS.pop("zzznovoexec", None)
        database.EXECUTOR_PROCESS_NAMES.pop("zzznovoexec.exe", None)


def test_external_signatures_missing_is_safe(tmp_path):
    import database
    added, err = database.load_external_signatures(str(tmp_path / "naoexiste.json"))
    assert added == 0 and err is None


def test_external_signatures_invalid_json_degrades(tmp_path):
    import database
    p = tmp_path / "signatures.json"
    p.write_text("{ isto nao e json valido ", encoding="utf-8")
    added, err = database.load_external_signatures(str(p))
    assert added == 0 and err is not None  # avisa mas não quebra


# --------------------------- Forense extra (Tier 1) ---------------------------

def test_extra_forensic_scanners_run():
    """Cada scanner novo retorna o contrato esperado, sem crashar."""
    import extra_forensics
    for fn in extra_forensics.ALL_EXTRA_FORENSIC_SCANNERS:
        r = fn()
        assert isinstance(r, dict), f"{fn.__name__} não retornou dict"
        assert r.get("status") in ("clean", "suspicious", "error"), f"{fn.__name__} status inválido"
        assert "items" in r and isinstance(r["items"], list)
        assert "name" in r


def test_extra_forensics_registered():
    """Os scanners do Tier 1 estão na lista."""
    import extra_forensics
    names = {fn.__name__ for fn in extra_forensics.ALL_EXTRA_FORENSIC_SCANNERS}
    assert names == {"scan_shimcache", "scan_srum", "scan_script_hashes",
                     "scan_anti_forensics", "scan_usn_journal",
                     "scan_prefetch_disabled", "scan_event_log_gap",
                     "scan_shadow_copy_wipe", "scan_powershell_history_cleared",
                     "scan_kernel_drivers"}


# ============= scan_prefetch_disabled =============

def test_prefetch_disabled_both_off_is_high(monkeypatch):
    """EnablePrefetcher=0 + SysMain.Start=4 = high (bypass deliberado)."""
    import extra_forensics as ef
    def fake_read(_h, key, _v):
        if "PrefetchParameters" in key:
            return 0
        if "SysMain" in key:
            return 4
        return None
    monkeypatch.setattr(ef, "_read_dword", fake_read)
    r = ef.scan_prefetch_disabled()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    assert r["items"][0]["severity"] == "high"
    assert "ao mesmo tempo" in r["items"][0]["label"]


def test_prefetch_disabled_only_one_is_medium(monkeypatch):
    """Só Prefetch=0 (ou só SysMain=4) é média — comum em guias antigas de SSD."""
    import extra_forensics as ef
    def fake_read(_h, key, _v):
        if "PrefetchParameters" in key:
            return 0
        if "SysMain" in key:
            return 2  # automatic
        return None
    monkeypatch.setattr(ef, "_read_dword", fake_read)
    r = ef.scan_prefetch_disabled()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "medium"
    assert "Prefetch desativado" in r["items"][0]["label"]


def test_prefetch_default_win11_is_clean(monkeypatch):
    """EnablePrefetcher=3 + SysMain.Start=2: padrão Win11, zero achado."""
    import extra_forensics as ef
    def fake_read(_h, key, _v):
        if "PrefetchParameters" in key:
            return 3
        if "SysMain" in key:
            return 2
        return None
    monkeypatch.setattr(ef, "_read_dword", fake_read)
    r = ef.scan_prefetch_disabled()
    assert r["status"] == "clean"
    assert r["items"] == []


def test_prefetch_partial_value_1_is_clean(monkeypatch):
    """EnablePrefetcher=1 (só apps) também é legítimo — não dispara."""
    import extra_forensics as ef
    def fake_read(_h, key, _v):
        return 1 if "PrefetchParameters" in key else 2
    monkeypatch.setattr(ef, "_read_dword", fake_read)
    r = ef.scan_prefetch_disabled()
    assert r["status"] == "clean"


# ============= scan_event_log_gap =============

def test_event_log_gap_fresh_pc_is_clean(monkeypatch):
    """PC fresh (Prefetch<80) NÃO dispara mesmo com log curto — anti-FP crítico."""
    import extra_forensics as ef
    monkeypatch.setattr(ef, "_count_dir", lambda *a, **kw: 30)  # PC fresh
    monkeypatch.setattr(ef, "_oldest_event_age_hours", lambda log: 2.0)  # log curto
    r = ef.scan_event_log_gap()
    assert r["status"] == "clean", "PC fresh nunca deve disparar gap"


def test_event_log_gap_historic_pc_short_log_flags(monkeypatch):
    """PC com Prefetch volumoso + log < 6h = gap suspeito (média)."""
    import extra_forensics as ef
    monkeypatch.setattr(ef, "_count_dir", lambda *a, **kw: 150)  # PC histórico
    def fake_age(log):
        return 1.5 if log == "System" else 50.0  # System foi limpo, App ok
    monkeypatch.setattr(ef, "_oldest_event_age_hours", fake_age)
    r = ef.scan_event_log_gap()
    assert r["status"] == "suspicious"
    assert any("System" in it["label"] and it["severity"] == "medium"
               for it in r["items"])


def test_event_log_gap_long_history_is_clean(monkeypatch):
    """PC histórico com logs longos (>6h): nada a flagar."""
    import extra_forensics as ef
    monkeypatch.setattr(ef, "_count_dir", lambda *a, **kw: 150)
    monkeypatch.setattr(ef, "_oldest_event_age_hours", lambda log: 720.0)  # 30 dias
    r = ef.scan_event_log_gap()
    assert r["status"] == "clean"


# ============= scan_shadow_copy_wipe =============

def test_shadow_copy_single_event_is_clean(monkeypatch):
    """1 evento 8224 isolado = limpeza automática do Windows, NÃO dispara
    (esse é o estado normal — FP no PC do dev se disparasse)."""
    import extra_forensics as ef
    fake_out = b"""Event[0]
  Date: 2026-06-02T14:48:49.000Z
  Event ID: 8224
"""
    class FakeProc:
        returncode = 0
        stdout = fake_out
    monkeypatch.setattr(ef.subprocess, "run", lambda *a, **kw: FakeProc())
    r = ef.scan_shadow_copy_wipe()
    assert r["status"] == "clean"


def test_shadow_copy_burst_flags(monkeypatch):
    """4 eventos 8224 em <60s = vssadmin delete shadows /all (média)."""
    import extra_forensics as ef
    fake_out = b"""Event[0]
  Date: 2026-06-01T10:00:30.000Z
  Event ID: 8224
Event[1]
  Date: 2026-06-01T10:00:20.000Z
  Event ID: 8224
Event[2]
  Date: 2026-06-01T10:00:10.000Z
  Event ID: 8224
Event[3]
  Date: 2026-06-01T10:00:00.000Z
  Event ID: 8224
"""
    class FakeProc:
        returncode = 0
        stdout = fake_out
    monkeypatch.setattr(ef.subprocess, "run", lambda *a, **kw: FakeProc())
    r = ef.scan_shadow_copy_wipe()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "medium"
    assert "4 shadow copies apagadas em 30s" in r["items"][0]["label"]


# ============= scan_kernel_drivers =============

def test_driver_path_normalization():
    """Resolve \\SystemRoot\\ e \\??\\ pra path real."""
    import extra_forensics as ef
    assert ef._normalize_driver_path(r"\SystemRoot\System32\drivers\foo.sys").lower() \
        == r"c:\windows\system32\drivers\foo.sys"
    # ImagePath quoteado com argumentos é comum em userspace services; aqui o
    # foco é só o caminho do arquivo, então o teste cobre o caso limpo.
    assert ef._normalize_driver_path(r"\??\C:\tmp\evil.sys").lower() \
        == r"c:\tmp\evil.sys"


def test_driver_whitelist_covers_system32_root():
    """cdd.dll em System32 raiz é whitelistado (não disparou bug do FP)."""
    import extra_forensics as ef
    assert ef._is_driver_path_whitelisted(r"c:\windows\system32\cdd.dll")
    assert ef._is_driver_path_whitelisted(r"c:\windows\system32\drivers\tcpip.sys")
    assert ef._is_driver_path_whitelisted(r"c:\windows\system32\driverstore\filerepository\foo\bar.sys")
    # Fora da whitelist
    assert not ef._is_driver_path_whitelisted(r"c:\users\bob\desktop\rwdrv.sys")
    assert not ef._is_driver_path_whitelisted(r"c:\programdata\suspect\bar.sys")


def test_driver_user_path_token():
    """Pasta de usuário é flagada."""
    import extra_forensics as ef
    assert ef._has_user_path_token(r"c:\users\bob\appdata\local\temp\foo.sys")
    assert ef._has_user_path_token(r"c:\users\bob\downloads\rwdrv.sys")
    assert ef._has_user_path_token(r"c:\users\bob\desktop\evil.sys")
    assert not ef._has_user_path_token(r"c:\windows\system32\drivers\tcpip.sys")
    assert not ef._has_user_path_token(r"c:\programdata\amd\amdrm.sys")


def test_scan_kernel_drivers_flags_byovd_name(monkeypatch):
    """Driver com nome conhecido de BYOVD vira high mesmo se path parece OK."""
    import extra_forensics as ef
    # Simula registry retornando um driver "rwdrv" plantado em path normal
    monkeypatch.setattr(ef, "_enumerate_kernel_drivers",
                        lambda: iter([("rwdrv", r"C:\Windows\System32\drivers\rwdrv.sys")]))
    r = ef.scan_kernel_drivers()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "high"
    assert "byovd" in r["items"][0]["matched"]


def test_scan_kernel_drivers_flags_user_path(monkeypatch):
    """Driver fora da whitelist em path de usuário = high."""
    import extra_forensics as ef
    monkeypatch.setattr(ef, "_enumerate_kernel_drivers",
                        lambda: iter([("evilthing", r"C:\Users\bob\Desktop\evil.sys")]))
    r = ef.scan_kernel_drivers()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "high"
    assert "userpath" in r["items"][0]["matched"]


def test_scan_kernel_drivers_unsigned_flag(monkeypatch):
    """Driver fora da whitelist, em path COMUM (não user folder), sem assinatura = high.
    Usa path mockado em C:\\ProgramData (path neutro: não-system, não-user)."""
    import extra_forensics as ef
    fake_path = r"C:\ProgramData\custom\driver.sys"
    monkeypatch.setattr(ef, "_enumerate_kernel_drivers",
                        lambda: iter([("custom", fake_path)]))
    monkeypatch.setattr(ef.os.path, "isfile",
                        lambda p: p.lower() == fake_path.lower())
    monkeypatch.setattr(ef, "_check_driver_signed", lambda p: False)
    r = ef.scan_kernel_drivers()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "high"
    assert "unsigned" in r["items"][0]["matched"]


def test_scan_kernel_drivers_signed_is_clean(monkeypatch):
    """Driver fora da whitelist, mas ASSINADO = não dispara (FP control)."""
    import extra_forensics as ef
    fake_path = r"C:\ProgramData\custom\driver.sys"
    monkeypatch.setattr(ef, "_enumerate_kernel_drivers",
                        lambda: iter([("custom", fake_path)]))
    monkeypatch.setattr(ef.os.path, "isfile",
                        lambda p: p.lower() == fake_path.lower())
    monkeypatch.setattr(ef, "_check_driver_signed", lambda p: True)
    r = ef.scan_kernel_drivers()
    assert r["status"] == "clean"


def test_scan_kernel_drivers_orphan_is_low(monkeypatch):
    """Driver registrado mas arquivo sumiu (CPU-Z, HWInfo) = low (FP comum)."""
    import extra_forensics as ef
    monkeypatch.setattr(ef, "_enumerate_kernel_drivers",
                        lambda: iter([("cpuz162", r"C:\inexistente\foo.sys")]))
    r = ef.scan_kernel_drivers()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "low"
    assert "orphan" in r["items"][0]["matched"]


def test_scan_kernel_drivers_signing_check_failure_is_silent(monkeypatch):
    """_check_driver_signed retornando None (não conseguiu checar) NÃO dispara
    high — protege contra FP em sistema com WinVerifyTrust quebrado."""
    import extra_forensics as ef
    fake_path = r"C:\ProgramData\custom\driver.sys"
    monkeypatch.setattr(ef, "_enumerate_kernel_drivers",
                        lambda: iter([("custom", fake_path)]))
    monkeypatch.setattr(ef.os.path, "isfile",
                        lambda p: p.lower() == fake_path.lower())
    monkeypatch.setattr(ef, "_check_driver_signed", lambda p: None)
    r = ef.scan_kernel_drivers()
    assert r["status"] == "clean"


# ============= --high-only filter =============

def test_filter_items_for_display_off_keeps_everything():
    """Sem --high-only, lista intocada."""
    import telador
    items = [{"severity": "low"}, {"severity": "medium"}, {"severity": "high"}]
    assert telador._filter_items_for_display(items, False) == items


def test_filter_items_for_display_on_keeps_only_high_and_critical():
    """Com --high-only, só passam high e critical. Items originais preservados."""
    import telador
    items = [
        {"severity": "low", "label": "A"},
        {"severity": "medium", "label": "B"},
        {"severity": "high", "label": "C"},
        {"severity": "critical", "label": "D"},
        {"severity": "low", "label": "E"},
    ]
    out = telador._filter_items_for_display(items, True)
    assert [it["label"] for it in out] == ["C", "D"]
    # Lista original não foi mutada
    assert len(items) == 5


def test_filter_items_for_display_missing_severity_defaults_to_low():
    """Item sem campo 'severity' é tratado como low (não passa no --high-only)."""
    import telador
    items = [{"label": "X"}]
    assert telador._filter_items_for_display(items, True) == []


# ============= scan_powershell_history_cleared =============

def _patch_psreadline(monkeypatch, tmp_path, content_bytes, pf_count):
    """Aponta o scanner pra um arquivo temporário e fixa o Prefetch."""
    import extra_forensics as ef
    f = tmp_path / "ConsoleHost_history.txt"
    if content_bytes is not None:
        f.write_bytes(content_bytes)
    monkeypatch.setattr(ef, "PSREADLINE_HISTORY", str(f))
    monkeypatch.setattr(ef, "_count_dir", lambda *a, **kw: pf_count)
    return f


def test_ps_history_zero_bytes_is_high(monkeypatch, tmp_path):
    """Arquivo existe mas tem 0 bytes = alguém esvaziou (high)."""
    import extra_forensics as ef
    _patch_psreadline(monkeypatch, tmp_path, b"", pf_count=150)
    r = ef.scan_powershell_history_cleared()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "high"
    assert "zerado" in r["items"][0]["label"]


def test_ps_history_near_empty_on_historic_pc_is_medium(monkeypatch, tmp_path):
    """< 50 bytes + PC histórico = média (limpeza recente seguida de uso mínimo)."""
    import extra_forensics as ef
    _patch_psreadline(monkeypatch, tmp_path, b"ls\ncd\n", pf_count=150)
    r = ef.scan_powershell_history_cleared()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "medium"


def test_ps_history_near_empty_on_fresh_pc_is_clean(monkeypatch, tmp_path):
    """< 50 bytes em PC fresh (Prefetch < 80) NÃO dispara — anti-FP."""
    import extra_forensics as ef
    _patch_psreadline(monkeypatch, tmp_path, b"ls\ncd\n", pf_count=30)
    r = ef.scan_powershell_history_cleared()
    assert r["status"] == "clean"


def test_ps_history_normal_size_is_clean(monkeypatch, tmp_path):
    """Arquivo com tamanho normal (>= 50 bytes) não dispara."""
    import extra_forensics as ef
    _patch_psreadline(monkeypatch, tmp_path, b"x" * 1000, pf_count=150)
    r = ef.scan_powershell_history_cleared()
    assert r["status"] == "clean"


def test_ps_history_missing_on_historic_pc_is_low(monkeypatch, tmp_path):
    """Arquivo ausente + PC histórico = low (FP possível: usuário de CMD/bash)."""
    import extra_forensics as ef
    _patch_psreadline(monkeypatch, tmp_path, None, pf_count=150)
    r = ef.scan_powershell_history_cleared()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "low"
    assert "não existe" in r["items"][0]["label"]


def test_ps_history_missing_on_fresh_pc_is_clean(monkeypatch, tmp_path):
    """Arquivo ausente em PC fresh = normal (clean)."""
    import extra_forensics as ef
    _patch_psreadline(monkeypatch, tmp_path, None, pf_count=20)
    r = ef.scan_powershell_history_cleared()
    assert r["status"] == "clean"


def test_shadow_copy_spread_over_days_is_clean(monkeypatch):
    """3 eventos 8224 mas espalhados em dias = automático, sem flag."""
    import extra_forensics as ef
    fake_out = b"""Event[0]
  Date: 2026-06-02T14:48:49.000Z
  Event ID: 8224
Event[1]
  Date: 2026-05-28T08:00:00.000Z
  Event ID: 8224
Event[2]
  Date: 2026-05-15T12:00:00.000Z
  Event ID: 8224
"""
    class FakeProc:
        returncode = 0
        stdout = fake_out
    monkeypatch.setattr(ef.subprocess, "run", lambda *a, **kw: FakeProc())
    r = ef.scan_shadow_copy_wipe()
    assert r["status"] == "clean"


def test_usn_reason_bits_language_independent():
    """O motivo do USN é lido pelos bits do código hex, não pelo rótulo (PT-BR
    traduz 'Reason'). Cada bit estrutural mapeia pra severidade certa."""
    import extra_forensics as ef
    assert ef._usn_classify(ef._usn_reason_from_line("x 0x80000200: excluir")) == ("excluído", "high")
    assert ef._usn_classify(ef._usn_reason_from_line("x 0x00000100: criar")) == ("criado", "medium")
    assert ef._usn_classify(ef._usn_reason_from_line("x 0x00001000: rename")) == ("renomeado", "high")
    assert ef._usn_classify(ef._usn_reason_from_line("x 0x00002000: rename")) == ("renomeado", "high")
    # Motivo ilegível (0) não vira "baixa" silenciosa: o nome está no journal,
    # então é média "atividade" — não perde o achado se o CSV vier diferente.
    assert ef._usn_classify(0) == ("atividade no journal", "medium")


def test_usn_parse_line_flags_deleted_executor():
    """Linha do readjournal com exec EXCLUÍDO vira item high; arquivo comum é ignorado."""
    import extra_forensics as ef
    # nome de executor conhecido + bit de delete -> high
    it = ef._usn_parse_line("5028431440,krnl.exe,0x80000200,2024-12-02 14:03:11")
    assert it is not None
    assert it["severity"] == "high"
    assert it["matched"].startswith("usn:")
    assert "excluído" in it["label"]
    assert it["timestamp"] == "2024-12-02 14:03:11"
    # processo legítimo do Windows não casa a base -> None (sem falso positivo)
    assert ef._usn_parse_line("123,chrome.exe,0x00000200,...") is None
    # extensão fora do alvo (.txt) não vira item
    assert ef._usn_parse_line("123,notas.txt,0x00000200,...") is None


def test_usn_reason_ignores_hex_inside_filename():
    """FP: um hex dentro do nome (0x200.krnl.exe) não pode injetar o bit de
    DELETE. O motivo real (0x100 = criado) é lido sem o trecho do nome.
    (Sem a excisão, o 0x200 do nome seria lido como 'excluído'.)"""
    import extra_forensics as ef
    it = ef._usn_parse_line("100,0x200.krnl.exe,0x00000100,...")
    assert it is not None
    assert "criado" in it["label"]   # não "excluído"
    assert it["severity"] == "medium"


def test_usn_degraded_format_still_flags():
    """Se o motivo vier em texto (não 0x hex), o exec ainda é sinalizado como
    média 'atividade' — robustez contra formato de CSV diferente do esperado."""
    import extra_forensics as ef
    it = ef._usn_parse_line("5028431440,krnl.exe,FILE_DELETE|CLOSE")
    assert it is not None
    assert it["severity"] == "medium"
    assert "atividade no journal" in it["label"]


def test_script_hash_match_logic(tmp_path, monkeypatch):
    """Plantando um hash conhecido, um arquivo com aquele conteúdo é pego."""
    import extra_forensics, hashlib
    conteudo = b"-- script qualquer renomeado\nlocal x = 1\n" * 5
    sha1 = hashlib.sha1(conteudo).hexdigest()
    f = tmp_path / "anotacoes.lua"
    f.write_bytes(conteudo)

    monkeypatch.setattr(extra_forensics, "KNOWN_SCRIPT_HASHES", {sha1: "Hub Fictício vX"})
    monkeypatch.setattr(extra_forensics, "SCRIPT_HASH_PATHS", [str(tmp_path)])

    r = extra_forensics.scan_script_hashes()
    assert r["status"] == "suspicious"
    assert any("Hub Fictício vX" in it["label"] for it in r["items"])


# --------------------------- Parser de PE (pe_analysis) ---------------------------

def _build_minimal_pe(path, machine=0x8664, sections=(".text",), timestamp=1700000000):
    """Monta um PE mínimo, mas estruturalmente válido, em disco."""
    import struct
    pe_off = 0x80
    buf = bytearray(b"\x00" * pe_off)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, pe_off)         # e_lfanew -> offset do PE
    buf += b"PE\x00\x00"                               # assinatura
    # COFF: machine, num_sections, timestamp, ptr_symtab, num_symbols, opt_size, chars
    buf += struct.pack("<HHIIIHH", machine, len(sections), timestamp, 0, 0, 0, 0)
    for name in sections:                              # section headers (40 bytes cada)
        nm = name.encode("latin-1")[:8].ljust(8, b"\x00")
        buf += nm + b"\x00" * 32
    with open(path, "wb") as fh:
        fh.write(bytes(buf))
    return str(path)


def test_parse_pe_x64_basic(tmp_path):
    import pe_analysis
    p = _build_minimal_pe(tmp_path / "fake.exe", machine=0x8664, sections=(".text", ".data"))
    pe = pe_analysis.parse_pe_header(p)
    assert pe["is_pe"] is True
    assert pe["machine"] == "x64"
    assert ".text" in pe["sections"] and ".data" in pe["sections"]
    assert pe["is_packed"] is False
    assert pe["compile_timestamp"]  # timestamp válido foi parseado


def test_parse_pe_x86(tmp_path):
    import pe_analysis
    p = _build_minimal_pe(tmp_path / "x86.exe", machine=0x14C)
    assert pe_analysis.parse_pe_header(p)["machine"] == "x86"


def test_parse_pe_detects_packer(tmp_path):
    import pe_analysis
    p = _build_minimal_pe(tmp_path / "packed.exe", sections=(".vmp0",))
    pe = pe_analysis.parse_pe_header(p)
    assert pe["is_packed"] is True
    assert pe["packer_name"] == "VMProtect"


def test_parse_pe_rejects_non_pe(tmp_path):
    import pe_analysis
    p = tmp_path / "nao.txt"
    p.write_bytes(b"isto nao e um executavel " * 20)
    assert pe_analysis.parse_pe_header(str(p))["is_pe"] is False


def test_compute_sha256(tmp_path):
    import pe_analysis, hashlib
    p = tmp_path / "f.bin"
    p.write_bytes(b"conteudo de teste")
    assert pe_analysis.compute_sha256(str(p)) == hashlib.sha256(b"conteudo de teste").hexdigest()


# --------------------------- Contrato de todos os scanners ---------------------------

SCANNER_MODULES = [
    "scanners", "forensics", "extra_forensics", "antievasion", "persistence",
    "live_analysis", "command_history", "peripherals", "network_scanners",
    "discord_cache", "fresh_install",
]
_REQUIRED_KEYS = {"name", "description", "status", "items", "summary", "error"}


def test_all_scanners_honor_contract():
    """
    Executa TODOS os scanners registrados e garante que cada um:
      - não crasha (têm try/except internos; o pipeline depende disso)
      - retorna dict com as 6 chaves que report.py e fp_filter.py consomem
      - 'items' é lista e 'status' é um dos valores esperados
    Trava regressão: scanner novo mal-formado quebra aqui, não em produção.
    """
    import importlib
    falhas = []
    for mod_name in SCANNER_MODULES:
        mod = importlib.import_module(mod_name)
        listas = [getattr(mod, a) for a in dir(mod)
                  if a.startswith("ALL_") and a.endswith("SCANNERS")]
        assert listas, f"{mod_name} não expõe ALL_*_SCANNERS"
        for lst in listas:
            for fn in lst:
                try:
                    r = fn()
                except Exception as e:  # noqa: BLE001 — o teste É pra pegar isso
                    falhas.append(f"{mod_name}.{fn.__name__} crashou: {e!r}")
                    continue
                if not isinstance(r, dict):
                    falhas.append(f"{mod_name}.{fn.__name__} não retornou dict")
                    continue
                faltando = _REQUIRED_KEYS - set(r)
                if faltando:
                    falhas.append(f"{mod_name}.{fn.__name__} sem chaves {faltando}")
                if not isinstance(r.get("items"), list):
                    falhas.append(f"{mod_name}.{fn.__name__} items não é lista")
                if r.get("status") not in ("clean", "suspicious", "error"):
                    falhas.append(f"{mod_name}.{fn.__name__} status inválido: {r.get('status')}")
    assert not falhas, "Scanners fora do contrato:\n" + "\n".join(falhas)
