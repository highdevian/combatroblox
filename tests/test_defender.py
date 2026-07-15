"""
Testes da detecção de adulteração do Windows Defender (defender_tampering.py).

Foco na classificação de exclusões (o núcleo), nos mocks de registro, na
integração com o Confidence Engine e no real-machine sem crash.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import defender_tampering as dt  # noqa: E402
from telador import fp_filter as fp  # noqa: E402
def test_classify_executor_name_high():
    sev, m = dt._classify_exclusion(r"C:\Users\x\Downloads\solara.exe", "path")
    assert sev == "high"
    assert "executor" in m


def test_classify_user_folder_high():
    sev, m = dt._classify_exclusion(r"C:\Users\x\AppData\Local\Temp", "path")
    assert sev == "high"
    assert m == "exclusao-pasta-usuario"


def test_classify_dev_tool_path_low():
    """Pasta de IDE conhecida deve sair LOW do scanner, nunca HIGH."""
    for path in (
        r"C:\Users\x\AppData\Local\JetBrains\PyCharm2025.3",
        r"C:\Users\x\AppData\Local\Programs\Microsoft VS Code",
        r"C:\Program Files\JetBrains\IntelliJ IDEA",
        r"C:\Users\x\.vscode",
        r"C:\Users\x\.cursor",
    ):
        sev, m = dt._classify_exclusion(path, "path")
        assert sev == "low", f"esperado low para {path!r}, obtido {sev!r}"
        assert m == "exclusao-dev", f"esperado exclusao-dev para {path!r}, obtido {m!r}"


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
    from telador import evidence as ev
    assert ev._source_slug_from_name("Adulteração do Windows Defender") == "defender_tampering"


def test_feeds_cluster_engine():
    from telador import evidence as ev
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


# ====== fp_filter integration (mantido do v3.29.1) ======

def test_fp_filter_dev_exclusions_visible_as_context():
    """Em PC de dev, exclusões Defender ficam listadas (contexto), fora do veredito."""
    fp._dev_cache = {"is_dev": True, "evidence": ["x", "y"]}
    findings = [{
        "name": "Adulteração do Windows Defender",
        "status": "suspicious",
        "items": [
            {
                "label": "Exclusão do Defender (pasta): C:\\Users\\gabri\\AppData\\Local\\JetBrains\\PyCharm2025.3",
                "detail": "C:\\Users\\gabri\\AppData\\Local\\JetBrains\\PyCharm2025.3\nO Windows Defender foi mandado IGNORAR esta pasta.",
                "severity": "high",
                "matched": "exclusao-pasta-usuario",
                "timestamp": "",
            },
            {
                "label": "Exclusão do Defender (pasta): C:\\Users\\gabri\\Desktop\\portfolio",
                "detail": "C:\\Users\\gabri\\Desktop\\portfolio\nO Windows Defender foi mandado IGNORAR esta pasta.",
                "severity": "high",
                "matched": "exclusao-pasta-usuario",
                "timestamp": "",
            },
        ],
    }]

    processed, stats = fp.post_process_findings(findings)

    assert stats["items_whitelisted"] >= 2
    assert len(processed[0]["items"]) == 2
    assert all(i.get("meta_only") for i in processed[0]["items"])
    assert processed[0]["status"] == "clean"


# ============== FP fixes v3.29.2 ==============

def test_classify_jetbrains_pycharm_is_dev_low():
    """REGRESSÃO FP: JetBrains recomenda excluir a pasta do PyCharm por perf.
    É exclusão LEGÍTIMA de IDE — não pode ser HIGH só porque cai em AppData."""
    sev, m = dt._classify_exclusion(
        r"C:\Users\gabri\AppData\Local\JetBrains\PyCharm2025.3", "path")
    assert sev == "low"
    assert m == "exclusao-dev"


def test_classify_git_path_is_dev_low():
    """Pasta com .git é repo de dev — exclusão por perf é legítima."""
    sev, m = dt._classify_exclusion(
        r"C:\Users\x\Documents\projeto\.git", "path")
    assert sev == "low"
    assert m == "exclusao-dev"


def test_classify_node_modules_path_is_dev_low():
    sev, m = dt._classify_exclusion(
        r"C:\Users\x\projeto\node_modules", "path")
    assert sev == "low"
    assert m == "exclusao-dev"


def test_classify_appdata_temp_still_high():
    """Não pode regredir: AppData\\Temp puro continua HIGH (clássico de cheat)."""
    sev, m = dt._classify_exclusion(r"C:\Users\x\AppData\Local\Temp", "path")
    assert sev == "high"
    assert m == "exclusao-pasta-usuario"


def test_classify_desktop_dev_folder_downgraded(tmp_path, monkeypatch):
    """Desktop com marcadores de projeto (.git, package.json) = LOW exclusao-dev.
    Cheater não cria .git só pra disfarçar."""
    proj = tmp_path / "portfolio"
    proj.mkdir()
    (proj / ".git").mkdir()
    (proj / "package.json").write_text("{}")
    # Força caminho em c:\\users\\...\\desktop pra cair na lógica de user-writable
    fake_path = r"C:\Users\x\Desktop\portfolio"
    monkeypatch.setattr(dt, "_probe_dev_folder", lambda p: p == fake_path)
    sev, m = dt._classify_exclusion(fake_path, "path")
    assert sev == "low"
    assert m == "exclusao-dev"


def test_classify_desktop_random_folder_is_low(monkeypatch):
    """Desktop SEM marcadores de dev = LOW (portfolio/projeto sem .git).
    HIGH fica pra Downloads/Temp/AppData (drop clássico de cheat)."""
    monkeypatch.setattr(dt, "_probe_dev_folder", lambda p: False)
    sev, m = dt._classify_exclusion(r"C:\Users\x\Desktop\cheat_hide", "path")
    assert sev == "low"
    assert m == "exclusao-pasta-usuario"
    # Downloads ainda é HIGH
    sev2, m2 = dt._classify_exclusion(r"C:\Users\x\Downloads\hide", "path")
    assert sev2 == "high"
    assert m2 == "exclusao-pasta-usuario"


def test_probe_dev_folder_detects_markers(tmp_path):
    """Probe direto: pasta com .git OU package.json OU pyproject = True."""
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "package.json").write_text("{}")
    assert dt._probe_dev_folder(str(proj)) is True


def test_probe_dev_folder_returns_false_for_empty(tmp_path):
    proj = tmp_path / "empty"
    proj.mkdir()
    assert dt._probe_dev_folder(str(proj)) is False


def test_probe_dev_folder_returns_false_for_nonexistent():
    assert dt._probe_dev_folder(r"C:\nope\does\not\exist\xyz123") is False


def test_dev_exclusion_message_is_contextual(monkeypatch):
    """Detail do exclusao-dev deve dizer 'contexto', não 'rodar cheat sem Defender'."""
    monkeypatch.setattr(dt, "_query_defender",
                        lambda: _mp(path=[r"C:\Users\x\AppData\Local\JetBrains\PyCharm"]))
    r = dt.scan_defender_tampering()
    dev_items = [i for i in r["items"] if i["matched"] == "exclusao-dev"]
    assert len(dev_items) == 1
    assert "contexto" in dev_items[0]["detail"].lower()
    assert "rodar cheat" not in dev_items[0]["detail"].lower()
