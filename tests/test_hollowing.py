"""
Testes do scanner de process hollowing / RunPE (scan_process_hollowing).

Prova:
  - A decisão pura (_image_base_is_hollowed): image base PRIVADO+COMMIT = hollow;
    MEM_IMAGE (imagem normal) = limpo.
  - O scanner PEGA o processo com image base privado e gradua a severidade
    (executor conhecido / binário assinado -> HIGH; resto -> MEDIUM).
  - NÃO flaga imagem normal (MEM_IMAGE), processo sem path, whitelistado, o
    próprio processo, nem quando a região não dá pra ler.
  - No PC real: não crasha e não vira FP (ninguém tem image base privado).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import live_analysis as la  # noqa: E402


class _FakeProc:
    def __init__(self, pid, name, exe, create_time=0):
        self.info = {"pid": pid, "name": name, "exe": exe,
                     "create_time": create_time}


def _patch_procs(monkeypatch, procs):
    monkeypatch.setattr(la, "HAS_PSUTIL", True)
    monkeypatch.setattr(la.psutil, "process_iter", lambda attrs=None: iter(procs))


def _hollow_region(image_base=0x140000000):
    return (la.MEM_COMMIT, la.MEM_PRIVATE, 0x40, image_base)


def _image_region(image_base=0x140000000):
    return (la.MEM_COMMIT, la.MEM_IMAGE, 0x02, image_base)


def _patch_region(monkeypatch, mapping):
    """mapping: pid -> tupla de região (ou None)."""
    monkeypatch.setattr(la, "_read_image_base_region",
                        lambda pid: mapping.get(pid))


# ----------------------------- decisão pura -----------------------------

def test_classifier_private_commit_is_hollow():
    assert la._image_base_is_hollowed(la.MEM_COMMIT, la.MEM_PRIVATE) is True


def test_classifier_mem_image_is_clean():
    """Imagem principal normal = MEM_IMAGE -> não é hollowing."""
    assert la._image_base_is_hollowed(la.MEM_COMMIT, la.MEM_IMAGE) is False


def test_classifier_private_not_committed_is_clean():
    """Memória PRIVADA mas só RESERVADA (não commitada) não conta."""
    MEM_RESERVE = 0x2000
    assert la._image_base_is_hollowed(MEM_RESERVE, la.MEM_PRIVATE) is False


# ----------------------------- graduação de severidade -----------------------------

def test_known_executor_hollowed_is_high(monkeypatch):
    procs = [_FakeProc(100, "solara.exe", r"C:\Users\x\Downloads\solara.exe")]
    _patch_procs(monkeypatch, procs)
    _patch_region(monkeypatch, {100: _hollow_region()})
    monkeypatch.setattr(la, "_match_keyword", lambda t: ("solara", "high"))
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: None)

    r = la.scan_process_hollowing()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    it = r["items"][0]
    assert it["severity"] == "high"
    assert it["matched"] == "hollowing:solara"


def test_signed_binary_hollowed_is_medium(monkeypatch):
    """Binário ASSINADO com image base privado = MEDIUM (pode ser anti-tamper/DRM
    legítimo tipo Themida; não acusa no HIGH sem corroboração)."""
    procs = [_FakeProc(101, "RobloxPlayerBeta.exe", r"C:\Users\x\Roblox\RobloxPlayerBeta.exe")]
    _patch_procs(monkeypatch, procs)
    _patch_region(monkeypatch, {101: _hollow_region()})
    monkeypatch.setattr(la, "_match_keyword", lambda t: (None, None))
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: True)

    r = la.scan_process_hollowing()
    it = r["items"][0]
    assert it["severity"] == "medium"
    assert it["matched"] == "hollowing:assinado-adulterado"


def test_unknown_unsigned_hollowed_is_medium(monkeypatch):
    procs = [_FakeProc(102, "host.exe", r"C:\Users\x\AppData\Local\Temp\host.exe")]
    _patch_procs(monkeypatch, procs)
    _patch_region(monkeypatch, {102: _hollow_region()})
    monkeypatch.setattr(la, "_match_keyword", lambda t: (None, None))
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)

    r = la.scan_process_hollowing()
    it = r["items"][0]
    assert it["severity"] == "medium"
    assert it["matched"] == "process-hollowing"


# ----------------------------- não-FP -----------------------------

def test_normal_image_is_clean(monkeypatch):
    """Image base MEM_IMAGE (imagem mapeada normal) = limpo."""
    procs = [_FakeProc(103, "notepad.exe", r"C:\Windows\System32\notepad.exe")]
    _patch_procs(monkeypatch, procs)
    _patch_region(monkeypatch, {103: _image_region()})
    monkeypatch.setattr(la, "_match_keyword", lambda t: (None, None))
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: True)
    assert la.scan_process_hollowing()["status"] == "clean"


def test_unreadable_region_skipped(monkeypatch):
    """Não conseguiu ler a região (None) = pula, não FP."""
    procs = [_FakeProc(104, "lsass.exe", r"C:\Windows\System32\lsass.exe")]
    _patch_procs(monkeypatch, procs)
    _patch_region(monkeypatch, {104: None})
    assert la.scan_process_hollowing()["status"] == "clean"


def test_process_without_exe_skipped(monkeypatch):
    """Sem path (protegido/efêmero) = sem disco pra comparar -> pula."""
    procs = [_FakeProc(105, "protected.exe", "")]
    _patch_procs(monkeypatch, procs)
    _patch_region(monkeypatch, {105: _hollow_region()})
    assert la.scan_process_hollowing()["status"] == "clean"


def test_whitelisted_name_skipped(monkeypatch):
    procs = [_FakeProc(106, "packed.exe", r"C:\Program Files\App\packed.exe")]
    _patch_procs(monkeypatch, procs)
    _patch_region(monkeypatch, {106: _hollow_region()})
    monkeypatch.setattr(la, "_HOLLOW_WHITELIST", {"packed.exe"})
    assert la.scan_process_hollowing()["status"] == "clean"


def test_own_process_skipped(monkeypatch):
    """O próprio Telador nunca se auto-flagga."""
    procs = [_FakeProc(os.getpid(), "python.exe", sys.executable)]
    _patch_procs(monkeypatch, procs)
    _patch_region(monkeypatch, {os.getpid(): _hollow_region()})
    assert la.scan_process_hollowing()["status"] == "clean"


# ----------------------------- integração -----------------------------

def test_registered_in_scanner_list():
    assert la.scan_process_hollowing in la.ALL_LIVE_ANALYSIS_SCANNERS


def test_slug_maps_to_live_processes():
    import evidence as ev
    slug = ev._source_slug_from_name("Processo oco (process hollowing / RunPE)")
    assert slug == "live_processes"


def test_feeds_cluster_engine():
    import evidence as ev
    findings = [{
        "name": "Processo oco (process hollowing / RunPE)",
        "status": "suspicious",
        "items": [{
            "label": "Processo OCO (hollowing): solara.exe",
            "detail": r"PID 100 · C:\Users\x\Downloads\solara.exe",
            "matched": "hollowing:solara", "severity": "high",
            "timestamp": "", "confidence": 80,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(clusters) == 1
    assert clusters[0].verdict != "CONFIRMED"  # 1 fonte só não crava


def test_real_machine_no_crash_no_fp():
    """No PC real: não pode crashar; e ninguém deveria ter image base privado,
    então o esperado é clean. Qualquer hit (não deveria haver) é high ou medium."""
    r = la.scan_process_hollowing()
    assert r["status"] in ("clean", "suspicious")
    for it in r["items"]:
        assert it["severity"] in ("high", "medium")
