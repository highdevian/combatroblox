"""
Testes do anti_forensic_deep — 4 scanners de resíduo pós-mortem.

Cobre:
  - String extraction dos blobs do Defender: paths, threats, hashes
  - Cheat keyword match eleva severity pra HIGH
  - DXCache burst detection com sliding window
  - WER report.wer parsing
  - Integração: 4 scanners registrados, slugs roteados, labels presentes
"""

import os
import sys
import struct
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import anti_forensic_deep as af  # noqa: E402


# ============================ Defender string extraction ============================

def test_extract_defender_strings_finds_ascii_path():
    """Path ASCII embutido no blob é extraído."""
    blob = b"\x00\x01padding" + rb"C:\Users\x\Downloads\cheat.exe".replace(b'\\', b'\\\\') + b"\x00more"
    # Sanidade: mais direto sem escape
    blob = b"\x00" * 8 + b"C:\\Users\\x\\Downloads\\cheat.exe\x00" + b"\x00" * 8
    r = af._extract_defender_strings(blob)
    assert any("cheat.exe" in p for p in r["paths"])


def test_extract_defender_strings_finds_threat_name():
    blob = b"\x00" * 8 + b"HackTool:Win32/AutoKMS\x00" + b"\x00" * 8
    r = af._extract_defender_strings(blob)
    assert any("hacktool" in t.lower() for t in r["threats"])


def test_extract_defender_strings_finds_utf16_path():
    """Path UTF-16 LE embutido também é extraído."""
    path = "C:\\Users\\x\\AppData\\Local\\Temp\\bypass.exe"
    blob = b"\x00" * 8 + path.encode("utf-16-le") + b"\x00\x00"
    r = af._extract_defender_strings(blob)
    assert any("bypass.exe" in p for p in r["paths"])


def test_extract_defender_strings_finds_hash():
    """SHA256 hex é capturado."""
    blob = b"\x00" * 8 + b"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" + b"\x00" * 8
    r = af._extract_defender_strings(blob)
    assert len(r["hashes"]) >= 1


# ============================ Defender scanner ============================

def test_defender_scanner_returns_error_when_no_history(monkeypatch, tmp_path):
    """Sem detection history dir, retorna error com mensagem clara."""
    monkeypatch.setattr(af, "_DEFENDER_HISTORY_ROOTS", (str(tmp_path / "nope"),))
    r = af.scan_defender_detection_history()
    assert r["status"] == "error"


def test_defender_scanner_reads_binary_file(monkeypatch, tmp_path):
    """Cria um blob fake com path de interest + threat, verifica que é detectado."""
    d = tmp_path / "DetectionHistory" / "abc-guid"
    d.mkdir(parents=True)
    blob_file = d / "detection.bin"
    blob = (
        b"\x00" * 16 +
        b"HackTool:Win32/AutoKMS\x00" +
        b"\x00" * 16 +
        b"C:\\Users\\x\\Downloads\\solara.exe\x00" +
        b"\x00" * 16
    )
    blob_file.write_bytes(blob)

    monkeypatch.setattr(af, "_DEFENDER_HISTORY_ROOTS", (str(tmp_path),))
    r = af.scan_defender_detection_history()
    assert r["status"] == "suspicious"
    labels = [it["label"] for it in r["items"]]
    assert any("solara.exe" in l for l in labels)
    # Path forense + threat HackTool = HIGH
    hi = [it for it in r["items"] if it["severity"] == "high"]
    assert len(hi) >= 1


def test_defender_scanner_ignores_benign_user_path(monkeypatch, tmp_path):
    """python.exe / path genérico em Downloads NÃO flagga (anti-FP)."""
    d = tmp_path / "DetectionHistory" / "guid"
    d.mkdir(parents=True)
    (d / "d.bin").write_bytes(
        b"\x00" * 16 + b"C:\\Users\\x\\AppData\\Local\\Python\\bin\\python.exe\x00"
        + b"\x00" * 16 + b"Trojan:Win32/Generic\x00"
    )
    monkeypatch.setattr(af, "_DEFENDER_HISTORY_ROOTS", (str(tmp_path),))
    r = af.scan_defender_detection_history()
    assert r["status"] == "clean"


def test_defender_scanner_ignores_windows_path(monkeypatch, tmp_path):
    """Path do C:\\Windows não deve ser reportado (ruído)."""
    d = tmp_path / "DetectionHistory" / "guid"
    d.mkdir(parents=True)
    (d / "d.bin").write_bytes(
        b"\x00" * 16 + b"C:\\Windows\\System32\\svchost.exe\x00" + b"\x00" * 16
    )
    monkeypatch.setattr(af, "_DEFENDER_HISTORY_ROOTS", (str(tmp_path),))
    r = af.scan_defender_detection_history()
    # Path é ignorado (windows), threat é ignorado (não tem hacktool aqui)
    # Portanto status == clean
    assert r["status"] == "clean"


# ============================ DXCache burst ============================

def test_dxcache_burst_detected(monkeypatch, tmp_path):
    """5 arquivos em janela de 15 min = burst reportado."""
    import time
    cache = tmp_path / "DXCache"
    cache.mkdir()
    now = time.time()
    # 5 shaders num intervalo de 5 min (dentro de 15) — dentro das 24h
    for i in range(5):
        f = cache / f"shader_{i}.bin"
        f.write_bytes(b"x")
        os.utime(f, (now - 3600 - i * 60, now - 3600 - i * 60))

    monkeypatch.setattr(af, "_DX_SHADER_CACHE_ROOTS", (str(cache),))
    r = af.scan_dxshader_cache()
    assert r["status"] == "suspicious"
    assert "5" in r["items"][0]["label"]


def test_dxcache_burst_ignores_scattered_files(monkeypatch, tmp_path):
    """Arquivos espalhados (>15 min entre eles) não são burst."""
    import time
    cache = tmp_path / "DXCache"
    cache.mkdir()
    now = time.time()
    # 5 shaders espaçados de 30 min cada
    for i in range(5):
        f = cache / f"s_{i}.bin"
        f.write_bytes(b"x")
        os.utime(f, (now - i * 1800, now - i * 1800))
    monkeypatch.setattr(af, "_DX_SHADER_CACHE_ROOTS", (str(cache),))
    assert af.scan_dxshader_cache()["status"] == "clean"


def test_dxcache_ignores_old_files(monkeypatch, tmp_path):
    """Arquivos > 24h atrás não contam — janela é últimas 24h."""
    import time
    cache = tmp_path / "DXCache"
    cache.mkdir()
    old = time.time() - 48 * 3600
    for i in range(10):
        f = cache / f"old_{i}.bin"
        f.write_bytes(b"x")
        os.utime(f, (old, old))
    monkeypatch.setattr(af, "_DX_SHADER_CACHE_ROOTS", (str(cache),))
    assert af.scan_dxshader_cache()["status"] == "clean"


# ============================ WER reports ============================

def test_wer_parse_report_wer(tmp_path):
    """Parse INI UTF-16 do Report.wer extrai AppPath e AppName."""
    rep = tmp_path / "Report.wer"
    content = "AppPath=C:\\Users\\x\\Downloads\\cheat.exe\r\nAppName=cheat.exe\r\n"
    rep.write_bytes(content.encode("utf-16"))
    info = af._parse_wer_report_wer(str(rep))
    assert "cheat.exe" in info["app_path"]
    assert info["app_name"] == "cheat.exe"


def test_wer_scanner_flags_user_path(monkeypatch, tmp_path):
    """Report com AppPath forense em pasta de usuário = flagga."""
    archive = tmp_path / "ReportArchive" / "abc"
    archive.mkdir(parents=True)
    rep = archive / "Report.wer"
    rep.write_bytes(
        "AppPath=C:\\Users\\x\\Downloads\\solara.exe\r\n"
        "AppName=solara.exe\r\n".encode("utf-16")
    )
    monkeypatch.setattr(af, "_WER_ROOTS", (str(tmp_path),))
    r = af.scan_wer_reports()
    assert r["status"] == "suspicious"
    assert any("solara" in it["label"].lower() for it in r["items"])


def test_wer_scanner_ignores_benign_installer(monkeypatch, tmp_path):
    """Crash de installer genérico (asio4all etc) NÃO flagga."""
    archive = tmp_path / "ReportArchive" / "abc"
    archive.mkdir(parents=True)
    rep = archive / "Report.wer"
    rep.write_bytes(
        "AppPath=C:\\Users\\x\\AppData\\Local\\Temp\\is-XXXX\\asio4all-installer.tmp\r\n"
        "AppName=Setup//Uninstall\r\n".encode("utf-16")
    )
    monkeypatch.setattr(af, "_WER_ROOTS", (str(tmp_path),))
    assert af.scan_wer_reports()["status"] == "clean"


def test_wer_scanner_ignores_program_files(monkeypatch, tmp_path):
    archive = tmp_path / "ReportArchive" / "x"
    archive.mkdir(parents=True)
    rep = archive / "Report.wer"
    rep.write_bytes(
        "AppPath=C:\\Program Files\\Chrome\\chrome.exe\r\n"
        "AppName=chrome.exe\r\n".encode("utf-16")
    )
    monkeypatch.setattr(af, "_WER_ROOTS", (str(tmp_path),))
    assert af.scan_wer_reports()["status"] == "clean"


# ============================ Integration ============================

def test_all_4_registered():
    assert len(af.ALL_ANTI_FORENSIC_DEEP_SCANNERS) == 4
    for fn in (af.scan_defender_detection_history,
               af.scan_dxshader_cache,
               af.scan_wer_reports,
               af.scan_reliability_monitor):
        assert fn in af.ALL_ANTI_FORENSIC_DEEP_SCANNERS


def test_slug_routing():
    import evidence as ev
    assert ev._source_slug_from_name(
        "Defender: histórico de detecções (persistente)") == "defender_history"
    assert ev._source_slug_from_name(
        "DirectX Shader Cache (burst recente)") == "dxshader_burst"
    assert ev._source_slug_from_name(
        "Windows Error Reporting (WER crash cache)") == "wer_crash"
    assert ev._source_slug_from_name(
        "Reliability Monitor / User Access Log") == "reliability_monitor"
    for slug in ("defender_history", "dxshader_burst", "wer_crash", "reliability_monitor"):
        assert slug in ev.SOURCE_WEIGHTS


def test_labels_present_in_report_assets():
    import report_assets as ra
    for slug in ("defender_history", "dxshader_burst", "wer_crash", "reliability_monitor"):
        assert slug in ra.SOURCE_LABELS


def test_chain_and_scanner_count():
    """Chain integrada bate SCANNER_COUNT."""
    import telador, version
    chain = telador.assemble_scanners(
        skip_forensics=False, skip_antievasion=False, skip_persistence=False,
        skip_live=False, skip_history=False, skip_peripherals=False,
    )
    assert len(chain) == version.SCANNER_COUNT


def test_skip_forensics_removes_anti_forensic_deep():
    """--no-forensics respeita e pula os 4 scanners pós-mortem."""
    import telador
    chain = telador.assemble_scanners(
        skip_forensics=True, skip_antievasion=False, skip_persistence=False,
        skip_live=False, skip_history=False, skip_peripherals=False,
    )
    for fn in af.ALL_ANTI_FORENSIC_DEEP_SCANNERS:
        assert fn not in chain, fn.__name__


def test_registry_group_present():
    import scanner_registry as sr
    reg = sr.build_registry()
    ext = [m for m in reg if m.group == "anti_forensic_deep"]
    assert len(ext) == 4
    for m in ext:
        assert m.requires_admin  # todos precisam admin


def test_no_crash_on_real_machine():
    for fn in af.ALL_ANTI_FORENSIC_DEEP_SCANNERS:
        r = fn()
        assert isinstance(r, dict)
        assert r["status"] in ("clean", "suspicious", "error")
        for it in r["items"]:
            assert it["severity"] in ("high", "medium", "low")
