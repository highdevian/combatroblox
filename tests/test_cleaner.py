"""
Testes da detecção de ferramentas de limpeza / secure-delete (cleaner_tools.py).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cleaner_tools as cl  # noqa: E402


def test_match_secure_delete_high():
    assert cl._match_cleaner("SDELETE64.EXE-A1B2.pf") == ("high", "SDelete (secure delete)")
    assert cl._match_cleaner("ERASER.EXE-C3.pf")[0] == "high"


def test_match_bleachbit_medium():
    assert cl._match_cleaner("BLEACHBIT.EXE-D4.pf") == ("medium", "BleachBit")


def test_match_ccleaner_low():
    assert cl._match_cleaner("CCLEANER64.EXE-E5.pf") == ("low", "CCleaner")


def test_match_non_cleaner_none():
    assert cl._match_cleaner("NOTEPAD.EXE-F6.pf") is None


def test_match_non_pf_none():
    assert cl._match_cleaner("bleachbit.txt") is None
    assert cl._match_cleaner("bleachbit") is None


# ============== FP: substring 'eraser' pegava editor de foto ==============

def test_photo_eraser_not_flagged():
    """REGRESSÃO FP: 'eraser' por substring pegava editores de imagem
    ('Photo Eraser', 'Background Eraser', 'Magic Eraser') — não são secure-delete."""
    for name in ("PHOTOERASER.EXE-A1.pf", "BACKGROUNDERASER.EXE-B2.pf",
                 "MAGICERASER.EXE-C3.pf", "BGERASER.EXE-D4.pf"):
        assert cl._match_cleaner(name) is None, f"{name} não devia casar"


def test_secure_eraser_still_flagged():
    """Secure Eraser (token próprio) continua HIGH mesmo com o boundary."""
    assert cl._match_cleaner("SECUREERASER.EXE-A1.pf") == ("high", "Secure Eraser")


def test_freeraser_still_flagged_by_own_token():
    """Freeraser contém 'eraser' mas tem token próprio — continua pego."""
    assert cl._match_cleaner("FREERASER.EXE-A1.pf") == ("high", "Freeraser")


def test_bare_eraser_at_word_start_flagged():
    """O Eraser real (nome começa com 'eraser') continua HIGH."""
    assert cl._match_cleaner("ERASER.EXE-C3.pf")[0] == "high"
    # precedido por separador não-alfanumérico também conta
    assert cl._match_cleaner("MY-ERASER.EXE-C3.pf")[0] == "high"


def test_sdelete_with_version_suffix_flagged():
    """Boundary só à esquerda — sufixo numérico (versão) não atrapalha."""
    assert cl._match_cleaner("SDELETE64.EXE-A1.pf")[0] == "high"
    assert cl._match_cleaner("SDELETE.EXE-A1.pf")[0] == "high"


def test_token_at_word_start_helper():
    assert cl._token_at_word_start("eraser", "eraser.exe-a1.pf") is True
    assert cl._token_at_word_start("eraser", "photoeraser.exe.pf") is False
    assert cl._token_at_word_start("eraser", "my-eraser.pf") is True
    assert cl._token_at_word_start("sdelete", "sdelete64.exe.pf") is True


def test_scan_flags_secure_delete(monkeypatch):
    monkeypatch.setattr(cl.os, "listdir",
                        lambda p: ["SDELETE64.EXE-A1.pf", "NOTEPAD.EXE-B2.pf"])
    r = cl.scan_cleaner_tools()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    assert r["items"][0]["severity"] == "high"
    assert r["items"][0]["matched"].startswith("cleaner:")


def test_scan_dedupes_by_tool(monkeypatch):
    monkeypatch.setattr(cl.os, "listdir",
                        lambda p: ["BLEACHBIT.EXE-A.pf", "BLEACHBIT.EXE-B.pf"])
    r = cl.scan_cleaner_tools()
    assert len(r["items"]) == 1


def test_scan_clean_when_no_cleaners(monkeypatch):
    monkeypatch.setattr(cl.os, "listdir",
                        lambda p: ["CHROME.EXE-1.pf", "ROBLOXPLAYERBETA.EXE-2.pf"])
    assert cl.scan_cleaner_tools()["status"] == "clean"


def test_scan_error_no_prefetch(monkeypatch):
    def boom(p):
        raise PermissionError("denied")
    monkeypatch.setattr(cl.os, "listdir", boom)
    assert cl.scan_cleaner_tools()["status"] == "error"


def test_real_machine_no_crash():
    r = cl.scan_cleaner_tools()
    assert r["status"] in ("clean", "suspicious", "error")
    for it in r["items"]:
        assert it["severity"] in ("low", "medium", "high")


def test_slug_maps_to_anti_forense():
    import evidence as ev
    assert ev._source_slug_from_name("Ferramentas de limpeza / anti-forense") == "anti_forense"


def test_feeds_cluster_engine():
    import evidence as ev
    findings = [{
        "name": "Ferramentas de limpeza / anti-forense", "status": "suspicious",
        "items": [{"label": "Ferramenta de limpeza executada: SDelete",
                   "detail": "x", "matched": "cleaner:sdelete", "severity": "high",
                   "timestamp": "", "confidence": 60}],
    }]
    cl_ = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(cl_) == 1
    assert cl_[0].verdict != "CONFIRMED"
