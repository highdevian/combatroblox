"""
Testes do scanner de DLL sideloading no Roblox (scan_roblox_dll_sideload).

Prova as duas pontas:
  - PEGA proxy DLL: DLL com nome de DLL de sistema (version.dll, dinput8.dll…)
    na pasta do Roblox e NÃO-ASSINADA → HIGH.
  - NÃO dispara em DLL legítima assinada que o Roblox embarca (ex.:
    d3dcompiler_47.dll, Microsoft-signed) nem em assinatura indeterminada.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import live_analysis as la  # noqa: E402
def _setup_roblox(tmp_path, files, monkeypatch):
    """Cria uma árvore Roblox/Versions/<ver>/ com os arquivos dados e aponta
    o scanner pra ela."""
    vdir = tmp_path / "Versions" / "version-abc123"
    vdir.mkdir(parents=True)
    for fn in files:
        (vdir / fn).write_bytes(b"MZ\x90\x00")
    monkeypatch.setattr(la, "_roblox_official_root", lambda: str(tmp_path))
    return vdir


def test_unsigned_version_dll_flagged(tmp_path, monkeypatch):
    """version.dll não-assinada ao lado do Roblox = proxy DLL → HIGH."""
    _setup_roblox(tmp_path, ["version.dll"], monkeypatch)
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)
    r = la.scan_roblox_dll_sideload()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    assert r["items"][0]["severity"] == "high"
    assert r["items"][0]["matched"] == "sideload:version.dll"


def test_unsigned_dinput8_flagged(tmp_path, monkeypatch):
    _setup_roblox(tmp_path, ["dinput8.dll"], monkeypatch)
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)
    r = la.scan_roblox_dll_sideload()
    assert r["items"][0]["matched"] == "sideload:dinput8.dll"


def test_signed_d3dcompiler_not_flagged(tmp_path, monkeypatch):
    """REGRESSÃO/FP real: o Roblox embarca d3dcompiler_47.dll ASSINADA pela
    Microsoft. O gate de assinatura tem que deixar passar."""
    _setup_roblox(tmp_path, ["d3dcompiler_47.dll"], monkeypatch)
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: True)
    assert la.scan_roblox_dll_sideload()["status"] == "clean"


def test_indeterminate_signature_not_flagged(tmp_path, monkeypatch):
    """Assinatura indeterminada (None) nunca flagga — só False (mesma doutrina
    do launcher integrity)."""
    _setup_roblox(tmp_path, ["version.dll"], monkeypatch)
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: None)
    assert la.scan_roblox_dll_sideload()["status"] == "clean"


def test_non_sideload_dll_ignored(tmp_path, monkeypatch):
    """DLL fora da lista de sideloading (ex.: a própria do Roblox) é ignorada
    mesmo não-assinada — não é vetor de search-order hijack."""
    _setup_roblox(tmp_path, ["RobloxPlayerBeta.dll", "qualquercoisa.dll"], monkeypatch)
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)
    assert la.scan_roblox_dll_sideload()["status"] == "clean"


def test_mixed_only_unsigned_sideload_flagged(tmp_path, monkeypatch):
    """Pasta com proxy não-assinada + DLL legítima assinada: só a proxy cai."""
    _setup_roblox(tmp_path, ["version.dll", "d3dcompiler_47.dll"], monkeypatch)
    monkeypatch.setattr(la, "_is_dll_signed",
                        lambda p: False if p.lower().endswith("version.dll") else True)
    r = la.scan_roblox_dll_sideload()
    assert len(r["items"]) == 1
    assert r["items"][0]["matched"] == "sideload:version.dll"


def test_case_insensitive_dll_name(tmp_path, monkeypatch):
    _setup_roblox(tmp_path, ["VERSION.DLL"], monkeypatch)
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)
    r = la.scan_roblox_dll_sideload()
    assert r["items"][0]["matched"] == "sideload:version.dll"


def test_error_when_roblox_not_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(la, "_roblox_official_root",
                        lambda: str(tmp_path / "nao_existe"))
    assert la.scan_roblox_dll_sideload()["status"] == "error"


def test_real_machine_no_crash_no_fp():
    """No PC real: não pode dar erro fatal; qualquer hit (não deveria haver)
    tem que ser HIGH."""
    r = la.scan_roblox_dll_sideload()
    assert r["status"] in ("clean", "suspicious", "error")
    for it in r["items"]:
        assert it["severity"] == "high"


def test_slug_maps_to_live_dll_injection():
    from telador import evidence as ev
    slug = ev._source_slug_from_name("DLL sideloading no Roblox (anti-bypass)")
    assert slug == "live_dll_injection"


def test_feeds_cluster_engine():
    from telador import evidence as ev
    findings = [{
        "name": "DLL sideloading no Roblox (anti-bypass)",
        "status": "suspicious",
        "items": [{
            "label": "DLL sideloading no Roblox: version.dll",
            "detail": r"C:\Users\x\AppData\Local\Roblox\Versions\v\version.dll",
            "matched": "sideload:version.dll", "severity": "high",
            "timestamp": "", "confidence": 80,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(clusters) == 1
    assert clusters[0].verdict != "CONFIRMED"  # 1 fonte só não crava


def test_registered_in_scanner_list():
    assert la.scan_roblox_dll_sideload in la.ALL_LIVE_ANALYSIS_SCANNERS
