"""
Testes do scanner de múltiplas contas de Windows (user_accounts.py).

Cobre o filtro de contas de sistema, a lógica de 'outra conta' (recente vs
antiga, pular a própria), o real-machine sem crash e a integração com o
Confidence Engine.
"""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import user_accounts as ua  # noqa: E402


def test_is_system_profile_by_sid():
    assert ua._is_system_profile("S-1-5-18", r"C:\Windows\system32\config\systemprofile")
    assert ua._is_system_profile("S-1-5-80-3139157870-2983391045", r"C:\qualquer")
    assert not ua._is_system_profile("S-1-5-21-1-2-3-1001", r"C:\Users\Gabriel")


def test_is_system_profile_by_name():
    assert ua._is_system_profile("S-1-5-21-1-2-3-503", r"C:\Users\defaultuser0")
    assert not ua._is_system_profile("S-1-5-21-1-2-3-1001", r"C:\Users\Joao")


def test_profile_item_recent_other_account_medium():
    now = datetime(2026, 6, 8, 20, 0, 0)
    last = now - timedelta(hours=3)
    it = ua._profile_item("Joao", r"C:\Users\Joao", last, current="Gabriel", now=now)
    assert it is not None
    assert it["severity"] == "medium"
    assert "joao" in it["matched"].lower()


def test_profile_item_old_other_account_low():
    now = datetime(2026, 6, 8, 20, 0, 0)
    last = now - timedelta(days=20)
    it = ua._profile_item("Joao", r"C:\Users\Joao", last, current="Gabriel", now=now)
    assert it is not None
    assert it["severity"] == "low"


def test_profile_item_current_account_skipped():
    it = ua._profile_item("Gabriel", r"C:\Users\Gabriel", datetime.now(), current="Gabriel")
    assert it is None
    # case-insensitive
    assert ua._profile_item("GABRIEL", r"C:\Users\GABRIEL", datetime.now(),
                            current="gabriel") is None


def test_profile_item_no_date_low():
    it = ua._profile_item("Joao", r"C:\Users\Joao", None, current="Gabriel")
    assert it is not None
    assert it["severity"] == "low"


def test_real_machine_no_crash():
    r = ua.scan_user_profiles()
    assert r["status"] in ("clean", "suspicious", "error")
    for it in r["items"]:
        assert it["severity"] in ("low", "medium")


def test_slug_maps_to_user_accounts():
    import evidence as ev
    assert ev._source_slug_from_name("Contas de usuário do Windows") == "user_accounts"


def test_feeds_cluster_engine():
    import evidence as ev
    findings = [{
        "name": "Contas de usuário do Windows",
        "status": "suspicious",
        "items": [{
            "label": "Outra conta de Windows: Joao",
            "detail": r"C:\Users\Joao",
            "matched": "conta-windows:joao", "severity": "medium",
            "timestamp": "", "confidence": 40,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(clusters) == 1
    assert clusters[0].verdict != "CONFIRMED"  # 1 fonte só, medium
