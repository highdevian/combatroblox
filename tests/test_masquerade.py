"""
Testes do scanner de process masquerading (scan_process_masquerade).

Prova as duas pontas:
  - PEGA cheat renomeado pra nome de processo do Windows rodando de fora da
    pasta do sistema (Downloads/Temp/AppData) -> HIGH.
  - NÃO dispara nos processos legítimos do SO rodando de System32/SysWOW64/
    WinSxS (e explorer de %WINDIR%), nem nos protegidos sem path exposto.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import live_analysis as la  # noqa: E402
import psutil  # noqa: E402


class _FakeProc:
    def __init__(self, pid, name, exe, create_time=0):
        self.info = {"pid": pid, "name": name, "exe": exe,
                     "create_time": create_time}


def _patch_procs(monkeypatch, procs):
    monkeypatch.setattr(la, "HAS_PSUTIL", True)
    monkeypatch.setattr(la.psutil, "process_iter", lambda attrs=None: iter(procs))


def test_flags_svchost_in_user_folder(monkeypatch):
    """svchost.exe rodando de Downloads = masquerade clássico -> HIGH."""
    procs = [_FakeProc(10, "svchost.exe", r"C:\Users\x\Downloads\svchost.exe")]
    _patch_procs(monkeypatch, procs)
    r = la.scan_process_masquerade()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    it = r["items"][0]
    assert it["severity"] == "high"
    assert it["matched"] == "masquerade:svchost.exe"


def test_legit_svchost_system32_clean(monkeypatch):
    """svchost.exe de System32 = legítimo, não flaga."""
    procs = [_FakeProc(11, "svchost.exe", r"C:\Windows\System32\svchost.exe")]
    _patch_procs(monkeypatch, procs)
    assert la.scan_process_masquerade()["status"] == "clean"


def test_legit_svchost_syswow64_clean(monkeypatch):
    procs = [_FakeProc(12, "svchost.exe", r"C:\Windows\SysWOW64\svchost.exe")]
    _patch_procs(monkeypatch, procs)
    assert la.scan_process_masquerade()["status"] == "clean"


def test_protected_process_no_path_skipped(monkeypatch):
    """Processo protegido (PPL) — o REAL — não expõe path; pula, não FP."""
    procs = [_FakeProc(13, "lsass.exe", "")]
    _patch_procs(monkeypatch, procs)
    assert la.scan_process_masquerade()["status"] == "clean"


def test_explorer_in_windir_clean_but_user_folder_flagged(monkeypatch):
    """explorer.exe roda de %WINDIR% (não System32). Lá = ok; em pasta de
    usuário = masquerade."""
    _patch_procs(monkeypatch, [_FakeProc(14, "explorer.exe", r"C:\Windows\explorer.exe")])
    assert la.scan_process_masquerade()["status"] == "clean"

    _patch_procs(monkeypatch, [_FakeProc(15, "explorer.exe", r"C:\Users\x\AppData\explorer.exe")])
    r = la.scan_process_masquerade()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "high"


def test_non_system_name_ignored(monkeypatch):
    """Nome que não é de processo do SO não é deste scanner."""
    procs = [_FakeProc(16, "randomcheat.exe", r"C:\Users\x\Downloads\randomcheat.exe")]
    _patch_procs(monkeypatch, procs)
    assert la.scan_process_masquerade()["status"] == "clean"


def test_case_insensitive_name_and_path(monkeypatch):
    """Nome/path em qualquer caixa: SVCHOST.EXE em Temp = HIGH."""
    procs = [_FakeProc(17, "SVCHOST.EXE", r"C:\Users\X\AppData\Local\Temp\SVCHOST.EXE")]
    _patch_procs(monkeypatch, procs)
    r = la.scan_process_masquerade()
    assert r["status"] == "suspicious"
    assert r["items"][0]["matched"] == "masquerade:svchost.exe"


def test_dwm_masquerade(monkeypatch):
    """Outro nome comum de disfarce: dwm.exe fora do System32."""
    procs = [_FakeProc(18, "dwm.exe", r"C:\Users\x\Desktop\dwm.exe")]
    _patch_procs(monkeypatch, procs)
    assert la.scan_process_masquerade()["items"][0]["severity"] == "high"


def test_real_machine_no_crash_no_fp():
    """No PC real: não pode dar erro nem FP — todo processo de sistema roda
    do lugar certo. Qualquer hit (não deveria haver) tem que ser HIGH."""
    r = la.scan_process_masquerade()
    assert r["status"] in ("clean", "suspicious")
    for it in r["items"]:
        assert it["severity"] == "high"


def test_slug_maps_to_live_processes():
    import evidence as ev
    slug = ev._source_slug_from_name("Processo disfarçado de sistema (masquerading)")
    assert slug == "live_processes"


def test_feeds_cluster_engine():
    import evidence as ev
    findings = [{
        "name": "Processo disfarçado de sistema (masquerading)",
        "status": "suspicious",
        "items": [{
            "label": "Processo DISFARÇADO de sistema: svchost.exe",
            "detail": r"PID 10 · C:\Users\x\Downloads\svchost.exe",
            "matched": "masquerade:svchost.exe", "severity": "high",
            "timestamp": "", "confidence": 80,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(clusters) == 1
    assert clusters[0].verdict != "CONFIRMED"  # 1 fonte só não crava


def test_registered_in_scanner_list():
    assert la.scan_process_masquerade in la.ALL_LIVE_ANALYSIS_SCANNERS
