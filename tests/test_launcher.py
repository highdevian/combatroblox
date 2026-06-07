"""
Testes da detecção de launcher do Roblox modificado (scan_roblox_launcher_integrity).

O que a comunidade pediu (cqnyc no Discord). Prova as duas pontas:
  - PEGA launcher oficial adulterado (assinatura quebrada) e dropper
    disfarçado de Roblox em pasta de usuário.
  - NÃO acusa o Roblox legítimo (assinado) nem instalador real baixado.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import live_analysis as la  # noqa: E402


def _make_exe(path):
    with open(path, "wb") as f:
        f.write(b"MZ" + b"\x00" * 64)


def test_detects_tampered_official_launcher(monkeypatch, tmp_path):
    """RobloxPlayerBeta.exe no path oficial com assinatura quebrada = HIGH."""
    root = tmp_path / "Roblox"
    vdir = root / "Versions" / "version-abc123"
    vdir.mkdir(parents=True)
    _make_exe(str(vdir / "RobloxPlayerBeta.exe"))

    monkeypatch.setattr(la, "_roblox_official_root",
                        lambda: str(root).lower().replace("/", "\\"))
    monkeypatch.setattr(la, "_LAUNCHER_WRONG_LOCATIONS", [])  # isola cenário 1
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)  # assinatura quebrada

    r = la.scan_roblox_launcher_integrity()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    assert r["items"][0]["severity"] == "high"
    assert r["items"][0]["matched"].startswith("launcher-tampered:")


def test_official_signed_launcher_is_clean(monkeypatch, tmp_path):
    """Launcher oficial ASSINADO não pode ser flagado (caso comum)."""
    root = tmp_path / "Roblox"
    vdir = root / "Versions" / "version-abc123"
    vdir.mkdir(parents=True)
    _make_exe(str(vdir / "RobloxPlayerBeta.exe"))

    monkeypatch.setattr(la, "_roblox_official_root",
                        lambda: str(root).lower().replace("/", "\\"))
    monkeypatch.setattr(la, "_LAUNCHER_WRONG_LOCATIONS", [])
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: True)  # assinado OK

    r = la.scan_roblox_launcher_integrity()
    assert r["status"] == "clean"
    assert len(r["items"]) == 0


def test_undetermined_signature_does_not_flag(monkeypatch, tmp_path):
    """Assinatura indeterminada (None) não flaga — mesma lição do bug
    anterior, evita tempestade de FP se WinVerifyTrust falhar."""
    root = tmp_path / "Roblox"
    vdir = root / "Versions" / "v1"
    vdir.mkdir(parents=True)
    _make_exe(str(vdir / "RobloxPlayerBeta.exe"))

    monkeypatch.setattr(la, "_roblox_official_root",
                        lambda: str(root).lower().replace("/", "\\"))
    monkeypatch.setattr(la, "_LAUNCHER_WRONG_LOCATIONS", [])
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: None)

    r = la.scan_roblox_launcher_integrity()
    assert r["status"] == "clean"


def test_detects_fake_launcher_in_downloads(monkeypatch, tmp_path):
    """Arquivo com nome de launcher numa pasta de usuário, não-assinado = dropper."""
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    _make_exe(str(downloads / "RobloxPlayer.exe"))

    monkeypatch.setattr(la, "_roblox_official_root",
                        lambda: str(tmp_path / "nada").lower())  # sem root oficial
    monkeypatch.setattr(la, "_LAUNCHER_WRONG_LOCATIONS", [str(downloads)])
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)

    r = la.scan_roblox_launcher_integrity()
    assert r["status"] == "suspicious"
    assert any(it["matched"].startswith("launcher-fake:") for it in r["items"])


def test_signed_installer_in_downloads_is_clean(monkeypatch, tmp_path):
    """Instalador oficial ASSINADO baixado em Downloads = legítimo, não flaga."""
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    _make_exe(str(downloads / "RobloxPlayerInstaller.exe"))

    monkeypatch.setattr(la, "_roblox_official_root",
                        lambda: str(tmp_path / "nada").lower())
    monkeypatch.setattr(la, "_LAUNCHER_WRONG_LOCATIONS", [str(downloads)])
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: True)  # assinado = real

    r = la.scan_roblox_launcher_integrity()
    assert r["status"] == "clean"


def test_real_clean_machine_zero_hits():
    """Na máquina real (com Roblox legítimo), NÃO pode haver hit.
    Trava de regressão anti-FP — se falhar, a heurística está pegando o
    Roblox legítimo, investigar ANTES de qualquer release."""
    r = la.scan_roblox_launcher_integrity()
    assert r["status"] == "clean", \
        f"FP: {[i['label'] for i in r['items']]}"


def test_feeds_cluster_engine_as_launcher_source():
    """A evidência deve mapear pra fonte launcher_integrity no Confidence Engine."""
    import evidence as ev
    findings = [{
        "name": "Integridade do launcher do Roblox",
        "status": "suspicious",
        "items": [{
            "label": "Launcher do Roblox ADULTERADO: RobloxPlayerBeta.exe",
            "detail": r"C:\Users\x\AppData\Local\Roblox\Versions\v1\RobloxPlayerBeta.exe",
            "matched": "launcher-tampered:robloxplayerbeta.exe",
            "severity": "high", "timestamp": "", "confidence": 90,
        }],
    }]
    evs = ev.findings_to_evidences(findings)
    assert evs[0].source == "launcher_integrity"
    assert evs[0].source_weight == 0.90
