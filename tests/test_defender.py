"""
Testes da detecção de adulteração do Windows Defender (defender_tampering.py).

Foco na classificação de exclusões (o núcleo), nos mocks de registro, na
integração com o Confidence Engine e no real-machine sem crash.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import defender_tampering as dt  # noqa: E402


def test_classify_executor_name_high():
    sev, m = dt._classify_exclusion(r"C:\Users\x\Downloads\solara.exe", "path")
    assert sev == "high"
    assert "executor" in m


def test_classify_user_folder_high():
    sev, m = dt._classify_exclusion(r"C:\Users\x\AppData\Local\Temp", "path")
    assert sev == "high"
    assert m == "exclusao-pasta-usuario"


def test_classify_exe_extension_high():
    assert dt._classify_exclusion("*.exe", "extension")[0] == "high"
    assert dt._classify_exclusion(".exe", "extension")[0] == "high"
    assert dt._classify_exclusion("dll", "extension")[0] == "high"


def test_classify_program_files_path_low():
    sev, m = dt._classify_exclusion(r"C:\Program Files\MeuJogo", "path")
    assert sev == "low"


def test_classify_process_outside_pf_medium():
    assert dt._classify_exclusion("helperaleatorio.exe", "process")[0] == "medium"
    # processo dentro de Program Files = contexto
    assert dt._classify_exclusion(r"C:\Program Files\App\app.exe", "process")[0] == "low"


def _mp(path=None, process=None, extension=None, rtp_off=False):
    return {"path": path or [], "process": process or [],
            "extension": extension or [], "realtime_disabled": rtp_off}


def test_scan_flags_user_folder_exclusion(monkeypatch):
    monkeypatch.setattr(dt, "_query_defender",
                        lambda: _mp(path=[r"C:\Users\x\Downloads\meucheat"]))
    r = dt.scan_defender_tampering()
    assert r["status"] == "suspicious"
    assert any(i["severity"] == "high" for i in r["items"])


def test_scan_flags_realtime_disabled(monkeypatch):
    monkeypatch.setattr(dt, "_query_defender", lambda: _mp(rtp_off=True))
    r = dt.scan_defender_tampering()
    assert any(i["matched"] == "defender-realtime-off" for i in r["items"])
    assert any(i["severity"] == "medium" for i in r["items"])


def test_scan_clean_when_nothing(monkeypatch):
    monkeypatch.setattr(dt, "_query_defender", lambda: _mp())
    r = dt.scan_defender_tampering()
    assert r["status"] == "clean"
    assert len(r["items"]) == 0


def test_scan_error_when_defender_unavailable(monkeypatch):
    monkeypatch.setattr(dt, "_query_defender", lambda: None)
    r = dt.scan_defender_tampering()
    assert r["status"] == "error"


class _FakeCompleted:
    def __init__(self, stdout, rc=0):
        self.stdout = stdout
        self.returncode = rc
        self.stderr = ""


def test_query_defender_non_admin_placeholder(monkeypatch):
    """REGRESSÃO: sem admin o Get-MpPreference devolve 'Must be an administrator'
    no lugar do valor — não pode virar exclusão (FP). Tem que dar None."""
    out = ("PATH:N/A: Must be an administrator to view exclusions\n"
           "PROC:N/A: Must be an administrator to view exclusions\n"
           "EXT:N/A: Must be an administrator to view exclusions\n"
           "RTP:True\n")
    monkeypatch.setattr(dt.subprocess, "run", lambda *a, **k: _FakeCompleted(out))
    assert dt._query_defender() is None


def test_query_defender_parses_real_values(monkeypatch):
    out = ("PATH:C:\\Users\\x\\Downloads\\cheat;;C:\\Program Files\\Game\n"
           "PROC:\n"
           "EXT:exe\n"
           "RTP:False\n")
    monkeypatch.setattr(dt.subprocess, "run", lambda *a, **k: _FakeCompleted(out))
    info = dt._query_defender()
    assert info["path"] == [r"C:\Users\x\Downloads\cheat", r"C:\Program Files\Game"]
    assert info["process"] == []
    assert info["extension"] == ["exe"]
    assert info["realtime_disabled"] is True


def test_real_machine_no_crash():
    r = dt.scan_defender_tampering()
    assert r["status"] in ("clean", "suspicious", "error")
    for it in r["items"]:
        assert it["severity"] in ("low", "medium", "high")


def test_slug_maps_to_defender():
    import evidence as ev
    assert ev._source_slug_from_name("Adulteração do Windows Defender") == "defender_tampering"


def test_feeds_cluster_engine():
    import evidence as ev
    findings = [{
        "name": "Adulteração do Windows Defender",
        "status": "suspicious",
        "items": [{
            "label": "Exclusão do Defender (pasta): solara",
            "detail": "x", "matched": "exclusao-executor:solara",
            "severity": "high", "timestamp": "", "confidence": 70,
        }],
    }]
    cl = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(cl) == 1
    assert cl[0].verdict != "CONFIRMED"
