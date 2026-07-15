"""
Testes da GUI CustomTkinter — helpers puros + smoke test de state machine.

Não abre janela em CI (headless-friendly) — só valida:
  - Verdict style mapping (LIMPO/SUSPEITO/CHEATER/INCONCLUSIVO)
  - _minimal_sys_info schema
  - _try_elevate não faz nada se já admin (evita relaunch loop em CI)
  - Estrutura do módulo (import + main() callable)
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_gui_imports():
    """Módulo carrega sem crash — mesmo sem CTk instalado, HAS_CTK avisa."""
    from telador import gui
    assert hasattr(gui, "HAS_CTK")
    assert hasattr(gui, "main")
    assert hasattr(gui, "VERDICT_STYLES")


def test_verdict_style_limpo():
    from telador import gui
    s = gui._verdict_style("LIMPO")
    assert s["label"] == "LIMPO"
    assert s["color"] == gui.BRAND["green"]
    # v3.55: badge textual, nao emoji
    assert s["emoji"] == "OK"


def test_verdict_style_cheater():
    from telador import gui
    s = gui._verdict_style("CHEATER")
    assert s["label"] == "CHEATER"
    assert s["color"] == gui.BRAND["red"]
    assert s["emoji"] == "X"


def test_verdict_style_confirmed_via_cluster():
    from telador import gui
    s = gui._verdict_style("CONFIRMED")
    assert s["label"] == "CONFIRMADO"
    assert s["color"] == gui.BRAND["red_hi"]


def test_verdict_style_inconclusivo():
    from telador import gui
    s = gui._verdict_style("INCONCLUSIVO")
    assert s["label"] == "INCONCLUSIVO"
    assert s["emoji"] == "?"


def test_verdict_style_suspeito_pt_and_en():
    from telador import gui
    assert gui._verdict_style("SUSPECT")["label"] == "SUSPEITO"
    assert gui._verdict_style("SUSPEITO")["label"] == "SUSPEITO"


def test_verdict_style_altamente():
    """'ALTAMENTE SUSPEITO' agora tem label proprio (v3.55)."""
    from telador import gui
    s = gui._verdict_style("ALTAMENTE SUSPEITO")
    assert s["label"] == "ALTAMENTE SUSPEITO"


def test_verdict_style_unknown_falls_to_dash():
    from telador import gui
    s = gui._verdict_style("random_nonsense")
    assert s["label"] == "-"


def test_verdict_style_possiveis_pistas():
    """A1: POSSIVEIS PISTAS nao cai no fallback '-'."""
    from telador import gui
    s = gui._verdict_style("POSSÍVEIS PISTAS")
    assert "PISTA" in s["label"].upper()
    assert s["label"] != "-"


def test_brand_colors_defined():
    """v3.55: cores de marca alinhadas com CLI (ambar/gold)."""
    from telador import gui
    assert "amber" in gui.BRAND
    assert gui.BRAND["amber"].startswith("#")
    assert "green" in gui.BRAND
    assert "red" in gui.BRAND
    assert "yellow" in gui.BRAND


def test_human_scanner_name():
    from telador import gui
    assert gui._human_scanner_name("scan_prefetch_executables") == "Prefetch executables"
    assert "Preparando" in gui._human_scanner_name("iniciando")


def test_format_eta():
    from telador import gui
    assert "s" in gui._format_eta(12)
    assert "min" in gui._format_eta(90) or "m" in gui._format_eta(90)


def test_staff_next_step_limpo():
    from telador import gui
    text, key = gui._staff_next_step("LIMPO", has_admin=True)
    assert "liberar" in text.lower()
    assert key == "green"


def test_staff_next_step_inconclusivo_sem_admin():
    from telador import gui
    text, key = gui._staff_next_step("INCONCLUSIVO", has_admin=False)
    assert "administrador" in text.lower()
    assert key == "yellow"


def test_top_target_labels():
    from telador import gui
    class C:
        def __init__(self, label, verdict, conf=50):
            self.label = label
            self.verdict = verdict
            self.confidence_pct = conf

    labs = gui._top_target_labels([
        C("WeakThing", "WEAK", 10),
        C("Solara", "CONFIRMED", 95),
        C("Wave", "DETECTED", 70),
    ])
    assert labs[0] == "Solara"
    assert "Wave" in labs


def test_collect_hits_by_severity_includes_lows():
    """GUI deve conseguir listar detects LOW (nao so HIGH)."""
    from telador import gui
    findings = [{
        "name": "Prefetch",
        "items": [
            {"label": "kms.exe", "matched": "kmsauto", "severity": "low"},
            {"label": "cheat.exe", "matched": "solara", "severity": "high"},
            {"label": "meta", "matched": "x", "severity": "low", "meta_only": True},
            {"label": "ghub", "matched": "logitech", "severity": "medium"},
        ],
    }]
    lows = gui._collect_hits_by_severity(findings, ("low",))
    assert len(lows) == 1
    assert lows[0]["matched"] == "kmsauto"
    assert lows[0]["scanner"] == "Prefetch"
    meds = gui._collect_hits_by_severity(findings, ("medium",))
    assert len(meds) == 1
    highs = gui._collect_hits_by_severity(findings, ("high",))
    assert len(highs) == 1


def test_no_em_dashes_in_gui():
    """Regressao: usuario nao quer em-dashes."""
    import os
    src_path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "telador", "gui.py")
    with open(src_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    # Ignora em-dashes em strings de docstring/comentario de codigo Python
    # que nao aparecem na UI — mas nao vale a pena distinguir, so tira tudo.
    assert "—" not in content, "gui.py ainda tem em-dashes (—)"


def test_minimal_sys_info_schema():
    from telador import gui
    info = gui._minimal_sys_info()
    expected = {"host", "user", "os", "scan_time",
                "admin", "session_id", "session_code", "telador_version"}
    assert expected.issubset(set(info.keys())), \
        f"faltando: {expected - set(info.keys())}"
    assert isinstance(info["admin"], bool)
    assert info["telador_version"].startswith("v3.")


def test_sys_info_session_code_and_stable_id():
    """session_id nao muda no mesmo dict; session_code respeita o argumento."""
    from telador import gui
    info = gui._build_sys_info("ABC123")
    sid = info["session_id"]
    assert info["session_code"] == "ABC123"
    assert len(sid) == 8
    # reuso do mesmo dict (HTML + Discord) preserva id
    info["scan_time"] = info["scan_time"]
    assert info["session_id"] == sid
    other = gui._build_sys_info("ABC123")
    assert other["session_id"] != sid  # novo scan = novo id


def test_run_scan_thread_uses_cli_parallel():
    """GUI deve reusar telador.run_scanners_parallel / _run_one (nao fork)."""
    import inspect
    from telador import gui
    src = inspect.getsource(gui._run_scan_thread)
    assert "run_scanners_parallel" in src
    assert "ThreadPoolExecutor" not in src
    # crash path da CLI
    from telador import cli as telador
    crashed = telador._run_one(lambda: (_ for _ in ()).throw(RuntimeError("x")))
    # nome humanizado, nao scan_*
    assert crashed["status"] == "error"
    assert not str(crashed.get("name", "")).startswith("scan_")


def test_is_admin_returns_bool():
    from telador import gui
    result = gui._is_admin()
    assert isinstance(result, bool)


def test_try_elevate_no_op_if_admin(monkeypatch):
    """Se já é admin, _try_elevate não faz nada (retorna False, não sai)."""
    from telador import gui
    monkeypatch.setattr(gui, "_is_admin", lambda: True)
    result = gui._try_elevate()
    assert result is False


def test_gui_state_machine_transitions():
    """State machine: initial → scanning → verdict → error → initial (voltar).
    Roda em janela real (sem mainloop) — headless CI precisa de display."""
    from telador import gui
    if not gui.HAS_CTK:
        return  # skip se CTk não instalado
    try:
        app = gui.TeladorGUI()
    except Exception as e:
        # CI sem display (Linux headless) vai falhar aqui — skip
        if "no display" in str(e).lower() or "couldn't connect" in str(e).lower():
            return
        raise

    try:
        # Initial state (rendered no __init__)
        assert len(app.container.winfo_children()) > 0

        # Scanning state (v3.55: recebe mode)
        app._show_scanning("fast")
        assert hasattr(app, "progress_bar")
        assert hasattr(app, "progress_lbl")

        # Verdict state (com data fake)
        class FakeCluster:
            def __init__(self):
                self.label = "Solara"
                self.verdict = "CONFIRMED"
                self.confidence_pct = 95
                self.sources = ["prefetch"]
                self.score = 8.0
                self.n_sources = 1
                self.evidences = [type("E",(),{"source":"prefetch"})()]
                self.first_seen = None
                self.kind = "executor"
                self.worst_severity = "critical"

        app.findings = []
        app.verdict_obj = {"verdict": "CHEATER", "score": 42,
                           "highest_confidence": 95}
        app.clusters = [FakeCluster()]
        app.coverage = {"blind_strong": 0}
        app.html_path = ""
        app._show_verdict()
        assert len(app.container.winfo_children()) > 0

        # Error state
        app._show_error("Test error")
        assert len(app.container.winfo_children()) > 0

        # Back to initial
        app._show_initial()
        assert len(app.container.winfo_children()) > 0

    finally:
        app.destroy()


def test_ss_live_flag_still_available():
    """Regressão: --ss-live continua funcionando (GUI não substitui CLI)."""
    import inspect
    from telador import cli as telador
    src = inspect.getsource(telador.main)
    assert "--ss-live" in src
    assert "--gui" in src


def test_gui_main_uses_ss_live_chain():
    """GUI deve rodar chain de --ss-live (< 45s target), não full scan."""
    import inspect
    from telador import gui
    src = inspect.getsource(gui._run_scan_thread)
    assert "assemble_ss_live_scanners" in src


def test_gui_spec_bundles_customtkinter():
    """Regressão: telador.spec bundla customtkinter (senão CI falha runtime)."""
    import os
    spec_path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "telador.spec")
    with open(spec_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "customtkinter" in content.lower(), \
        "telador.spec não bundla customtkinter — GUI vai falhar no exe"
