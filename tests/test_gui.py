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
    import gui
    assert hasattr(gui, "HAS_CTK")
    assert hasattr(gui, "main")
    assert hasattr(gui, "VERDICT_STYLES")


def test_verdict_style_limpo():
    import gui
    s = gui._verdict_style("LIMPO")
    assert s["label"] == "LIMPO"
    assert s["color"] == gui.BRAND["green"]
    # v3.55: badge textual, nao emoji
    assert s["emoji"] == "OK"


def test_verdict_style_cheater():
    import gui
    s = gui._verdict_style("CHEATER")
    assert s["label"] == "CHEATER"
    assert s["color"] == gui.BRAND["red"]
    assert s["emoji"] == "X"


def test_verdict_style_confirmed_via_cluster():
    import gui
    s = gui._verdict_style("CONFIRMED")
    assert s["label"] == "CONFIRMADO"
    assert s["color"] == gui.BRAND["red_hi"]


def test_verdict_style_inconclusivo():
    import gui
    s = gui._verdict_style("INCONCLUSIVO")
    assert s["label"] == "INCONCLUSIVO"
    assert s["emoji"] == "?"


def test_verdict_style_suspeito_pt_and_en():
    import gui
    assert gui._verdict_style("SUSPECT")["label"] == "SUSPEITO"
    assert gui._verdict_style("SUSPEITO")["label"] == "SUSPEITO"


def test_verdict_style_altamente():
    """'ALTAMENTE SUSPEITO' agora tem label proprio (v3.55)."""
    import gui
    s = gui._verdict_style("ALTAMENTE SUSPEITO")
    assert s["label"] == "ALTAMENTE SUSPEITO"


def test_verdict_style_unknown_falls_to_dash():
    import gui
    s = gui._verdict_style("random_nonsense")
    assert s["label"] == "-"


def test_brand_colors_defined():
    """v3.55: cores de marca alinhadas com CLI (ambar/gold)."""
    import gui
    assert "amber" in gui.BRAND
    assert gui.BRAND["amber"].startswith("#")
    assert "green" in gui.BRAND
    assert "red" in gui.BRAND
    assert "yellow" in gui.BRAND


def test_no_em_dashes_in_gui():
    """Regressao: usuario nao quer em-dashes."""
    import os
    src_path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "gui.py")
    with open(src_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    # Ignora em-dashes em strings de docstring/comentario de codigo Python
    # que nao aparecem na UI — mas nao vale a pena distinguir, so tira tudo.
    assert "—" not in content, "gui.py ainda tem em-dashes (—)"


def test_minimal_sys_info_schema():
    import gui
    info = gui._minimal_sys_info()
    expected = {"host", "user", "os", "scan_time",
                "admin", "session_id", "session_code", "telador_version"}
    assert expected.issubset(set(info.keys())), \
        f"faltando: {expected - set(info.keys())}"
    assert isinstance(info["admin"], bool)
    assert info["telador_version"].startswith("v3.")


def test_is_admin_returns_bool():
    import gui
    result = gui._is_admin()
    assert isinstance(result, bool)


def test_try_elevate_no_op_if_admin(monkeypatch):
    """Se já é admin, _try_elevate não faz nada (retorna False, não sai)."""
    import gui
    monkeypatch.setattr(gui, "_is_admin", lambda: True)
    result = gui._try_elevate()
    assert result is False


def test_gui_state_machine_transitions():
    """State machine: initial → scanning → verdict → error → initial (voltar).
    Roda em janela real (sem mainloop) — headless CI precisa de display."""
    import gui
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
    import telador, inspect
    src = inspect.getsource(telador.main)
    assert "--ss-live" in src
    assert "--gui" in src


def test_gui_main_uses_ss_live_chain():
    """GUI deve rodar chain de --ss-live (< 45s target), não full scan."""
    import gui, inspect
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
