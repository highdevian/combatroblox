"""
Testes do scanner de mídia removível (removable_media.py).

Cobre:
  - parsing do nome amigável de USB;
  - lógica de recência do histórico de USB (helper isolado do registro);
  - detecção de executor numa unidade removível plugada (match de keyword);
  - anti-FP (app neutro na USB não dispara);
  - real-machine sem crash;
  - integração com o Confidence Engine (slug removable_media).
"""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import removable_media as rm  # noqa: E402


def test_friendly_usb_name():
    assert (rm._friendly_usb_name("Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00")
            == "SanDisk Cruzer Blade 1.00")


# ---------------- histórico de USB (recência) ----------------

def test_usb_history_item_recent_flags():
    now = datetime(2026, 6, 8, 20, 0, 0)
    last = now - timedelta(hours=2)
    it = rm._usb_history_item("Disk&Ven_Kingston&Prod_DT&Rev_1.0", last, now=now)
    assert it is not None
    assert it["severity"] == "low"  # contexto, não infla veredito
    assert it["matched"].startswith("usb-recente:")


def test_usb_history_item_old_skipped():
    now = datetime(2026, 6, 8, 20, 0, 0)
    last = now - timedelta(days=10)
    assert rm._usb_history_item("Disk&Ven_X&Prod_Y&Rev_1", last, now=now) is None


def test_usb_history_item_none_skipped():
    assert rm._usb_history_item("Disk&Ven_X&Prod_Y&Rev_1", None) is None


# ---------------- conteúdo de drive removível ----------------

def _make_exe(path):
    with open(path, "wb") as f:
        f.write(b"MZ" + b"\x00" * 32)


def test_removable_drives_flags_executor(monkeypatch, tmp_path):
    drive = str(tmp_path) + os.sep
    _make_exe(os.path.join(str(tmp_path), "solara.exe"))
    monkeypatch.setattr(rm, "_removable_drive_letters", lambda: [drive])

    r = rm.scan_removable_drives()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    it = r["items"][0]
    assert it["severity"] == "high"
    assert "solara" in it["matched"].lower()


def test_removable_drives_ignores_neutral_app(monkeypatch, tmp_path):
    drive = str(tmp_path) + os.sep
    _make_exe(os.path.join(str(tmp_path), "meu_jogo.exe"))  # nome neutro
    monkeypatch.setattr(rm, "_removable_drive_letters", lambda: [drive])

    r = rm.scan_removable_drives()
    assert r["status"] == "clean"
    assert len(r["items"]) == 0


def test_removable_drives_no_drives(monkeypatch):
    monkeypatch.setattr(rm, "_removable_drive_letters", lambda: [])
    r = rm.scan_removable_drives()
    assert r["status"] == "clean"


# ---------------- real machine ----------------

def test_real_machine_no_crash():
    """Os dois scanners rodam no PC real sem erro; severidades válidas."""
    for fn in rm.ALL_REMOVABLE_SCANNERS:
        r = fn()
        assert r["status"] in ("clean", "suspicious", "error")
        for it in r["items"]:
            assert it["severity"] in ("low", "medium", "high")


# ---------------- integração com o Confidence Engine ----------------

def test_slug_maps_to_removable_media():
    import evidence as ev
    assert ev._source_slug_from_name("Mídia removível plugada") == "removable_media"
    assert ev._source_slug_from_name("Histórico de USB") == "removable_media"


def test_feeds_cluster_engine():
    import evidence as ev
    findings = [{
        "name": "Mídia removível plugada",
        "status": "suspicious",
        "items": [{
            "label": "Cheat em mídia removível: solara.exe",
            "detail": r"E:\solara.exe",
            "matched": "solara", "severity": "high",
            "timestamp": "", "confidence": 70,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(clusters) == 1
    # 1 fonte só nunca CONFIRMED (FP protection)
    assert clusters[0].verdict != "CONFIRMED"
