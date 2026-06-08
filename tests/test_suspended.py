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


class _FakeParent:
    def __init__(self, name):
        self._name = name

    def name(self):
        return self._name


class _FakeProc:
    """Imita psutil.Process com .info preenchido pelo process_iter(attrs).
    parent_name opcional simula proc.parent().name() (debugger/IDE)."""
    def __init__(self, pid, name, exe, status, create_time=0, parent_name=None):
        self.info = {
            "pid": pid, "name": name, "exe": exe,
            "status": status, "create_time": create_time,
        }
        self._parent_name = parent_name

    def parent(self):
        return _FakeParent(self._parent_name) if self._parent_name else None


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


# ============== FP: dev pausando o próprio exe no debugger ==============

def test_debugger_parent_suppresses_medium(monkeypatch):
    """REGRESSÃO FP: dev depurando o próprio .exe não-assinado (recém compilado
    em pasta de usuário) — o filho fica SUSPENSO no breakpoint. Se o pai é
    debugger/IDE, não é cheat pausado: não flaga."""
    procs = [_FakeProc(77, "myapp.exe",
                       r"C:\Users\x\source\repos\myapp\bin\Debug\myapp.exe",
                       psutil.STATUS_STOPPED, parent_name="pycharm64.exe")]
    _patch_procs(monkeypatch, procs)
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)

    r = la.scan_suspended_processes()
    assert r["status"] == "clean", "debugger como pai deveria suprimir o MEDIUM"


def test_non_debugger_parent_still_flags_medium(monkeypatch):
    """Pai comum (não-debugger) + não-assinado suspenso = continua MEDIUM."""
    procs = [_FakeProc(78, "randomname.exe",
                       r"C:\Users\x\AppData\Local\Temp\randomname.exe",
                       psutil.STATUS_STOPPED, parent_name="explorer.exe")]
    _patch_procs(monkeypatch, procs)
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)

    r = la.scan_suspended_processes()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "medium"


def test_debugger_parent_does_not_save_known_executor(monkeypatch):
    """Executor CONHECIDO suspenso continua HIGH mesmo com pai debugger —
    rodar o cheat 'no debugger' não o inocenta."""
    procs = [_FakeProc(79, "solara.exe", r"C:\Users\x\Downloads\solara.exe",
                       psutil.STATUS_STOPPED, parent_name="x64dbg.exe")]
    _patch_procs(monkeypatch, procs)

    r = la.scan_suspended_processes()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "high"


def test_parent_is_debugger_helper():
    assert la._parent_is_debugger(
        _FakeProc(1, "a.exe", "", psutil.STATUS_STOPPED, parent_name="devenv.exe")) is True
    assert la._parent_is_debugger(
        _FakeProc(1, "a.exe", "", psutil.STATUS_STOPPED, parent_name="explorer.exe")) is False
    # sem pai → False (não suprime na dúvida)
    assert la._parent_is_debugger(
        _FakeProc(1, "a.exe", "", psutil.STATUS_STOPPED, parent_name=None)) is False


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
