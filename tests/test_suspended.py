"""
Testes do scanner de processo suspenso (scan_suspended_processes).

Prova as duas pontas:
  - PEGA o truque de anti-bypass (pausar o cheat durante a SS) quando o
    processo é executor conhecido (HIGH) ou não-assinado em pasta de usuário (MEDIUM).
  - NÃO dispara nos processos que o Windows legitimamente suspende
    (UWP/Store em background, navegador, shell).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import live_analysis as la  # noqa: E402
import psutil  # noqa: E402


class _FakeProc:
    """Imita psutil.Process com .info preenchido pelo process_iter(attrs)."""
    def __init__(self, pid, name, exe, status, create_time=0):
        self.info = {
            "pid": pid, "name": name, "exe": exe,
            "status": status, "create_time": create_time,
        }


def _patch_procs(monkeypatch, procs):
    monkeypatch.setattr(la, "HAS_PSUTIL", True)
    monkeypatch.setattr(la.psutil, "process_iter", lambda attrs=None: iter(procs))


def test_flags_suspended_known_executor(monkeypatch):
    """Executor conhecido SUSPENSO = sinal forte (HIGH)."""
    procs = [_FakeProc(1234, "solara.exe",
                       r"C:\Users\x\Downloads\solara.exe",
                       psutil.STATUS_STOPPED)]
    _patch_procs(monkeypatch, procs)

    r = la.scan_suspended_processes()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    it = r["items"][0]
    assert it["severity"] == "high"
    assert "solara" in it["matched"].lower()


def test_flags_suspended_unsigned_user_exe(monkeypatch):
    """Renomeado (sem keyword) mas NÃO-ASSINADO em pasta de usuário + suspenso = MEDIUM."""
    procs = [_FakeProc(22, "randomname123.exe",
                       r"C:\Users\x\AppData\Local\Temp\randomname123.exe",
                       psutil.STATUS_STOPPED)]
    _patch_procs(monkeypatch, procs)
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)  # não-assinado

    r = la.scan_suspended_processes()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    assert r["items"][0]["severity"] == "medium"
    assert r["items"][0]["matched"] == "processo-suspenso-nao-assinado"


def test_ignores_running_executor(monkeypatch):
    """Executor RODANDO (não suspenso) não é deste scanner — só o suspenso."""
    procs = [_FakeProc(1, "solara.exe", r"C:\Users\x\Downloads\solara.exe",
                       psutil.STATUS_RUNNING)]
    _patch_procs(monkeypatch, procs)

    r = la.scan_suspended_processes()
    assert r["status"] == "clean"
    assert len(r["items"]) == 0


def test_ignores_whitelisted_browser_and_shell(monkeypatch):
    """Navegador/shell suspenso pelo Windows = normal, não flaga."""
    procs = [
        _FakeProc(2, "chrome.exe",
                  r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                  psutil.STATUS_STOPPED),
        _FakeProc(3, "TextInputHost.exe",
                  r"C:\Windows\SystemApps\xxx\TextInputHost.exe",
                  psutil.STATUS_STOPPED),
    ]
    _patch_procs(monkeypatch, procs)

    r = la.scan_suspended_processes()
    assert r["status"] == "clean"


def test_ignores_uwp_package_path(monkeypatch):
    """App empacotado (WindowsApps) suspenso = esperado, mesmo 'não-assinado'."""
    procs = [_FakeProc(4, "SomeStoreApp.exe",
                       r"C:\Program Files\WindowsApps\Pkg_1.0_x64\SomeStoreApp.exe",
                       psutil.STATUS_STOPPED)]
    _patch_procs(monkeypatch, procs)
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)

    r = la.scan_suspended_processes()
    assert r["status"] == "clean"


def test_ignores_signed_user_exe(monkeypatch):
    """Suspenso em pasta de usuário mas ASSINADO = app legítimo, não flaga."""
    procs = [_FakeProc(5, "updater.exe",
                       r"C:\Users\x\AppData\Roaming\SomeApp\updater.exe",
                       psutil.STATUS_STOPPED)]
    _patch_procs(monkeypatch, procs)
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: True)  # assinado

    r = la.scan_suspended_processes()
    assert r["status"] == "clean"


def test_real_machine_no_crash_no_noise():
    """No PC real onde os testes rodam: não pode dar erro, e qualquer hit tem
    que vir dos sinais fortes (medium/high), nunca ruído de severidade baixa."""
    r = la.scan_suspended_processes()
    assert r["status"] in ("clean", "suspicious")
    for it in r["items"]:
        assert it["severity"] in ("medium", "high")


def test_feeds_cluster_engine():
    """Processo suspenso de executor vira evidência clusterizável — SUSPECT/
    DETECTED no máximo sozinho, nunca CONFIRMED sem corroboração."""
    import evidence as ev
    findings = [{
        "name": "Processos suspensos (anti-bypass)",
        "status": "suspicious",
        "items": [{
            "label": "Processo SUSPENSO: solara.exe",
            "detail": r"PID 1 · C:\Users\x\Downloads\solara.exe",
            "matched": "solara", "severity": "high",
            "timestamp": "", "confidence": 70,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(clusters) == 1
    assert clusters[0].verdict in ("WEAK", "SUSPECT", "DETECTED")
    assert clusters[0].verdict != "CONFIRMED"
