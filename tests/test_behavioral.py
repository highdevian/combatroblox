"""
Testes da detecção comportamental de executor (scan_executor_structure).

Prova as duas pontas:
  - PEGA um executor com a estrutura típica (exe não-assinado + EBWebView)
    mesmo renomeado.
  - NÃO dispara em estruturas legítimas (sem runtime embutido, ou exe só).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import live_analysis as la  # noqa: E402
def _make_fake_exe(path):
    # Um "exe" qualquer — não é PE válido, então WinVerifyTrust devolve
    # não-assinado (False/None), que é o que queremos testar.
    with open(path, "wb") as f:
        f.write(b"MZ" + b"\x00" * 64)


def test_detects_executor_structure_even_renamed(monkeypatch, tmp_path):
    """Pasta com exe (renomeado) + EBWebView em local de usuário = sinal."""
    # Monta a estrutura: <root>/xyz123/loader_renamed.exe + <root>/xyz123/EBWebView/
    fake_local = tmp_path / "Local"
    folder = fake_local / "xyz123randomname"
    (folder / "EBWebView").mkdir(parents=True)
    _make_fake_exe(str(folder / "loader_renamed.exe"))

    # Aponta o scanner pra essa raiz e força "não-assinado"
    monkeypatch.setattr(la, "_EXECUTOR_STRUCT_ROOTS", [str(fake_local)])
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)

    r = la.scan_executor_structure()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    it = r["items"][0]
    assert it["severity"] == "medium"
    assert it["matched"].startswith("executor-struct:")
    assert "xyz123randomname" in it["matched"]


def test_ignores_signed_exe(monkeypatch, tmp_path):
    """Mesmo com EBWebView, exe ASSINADO = app legítimo, não dispara."""
    fake_local = tmp_path / "Local"
    folder = fake_local / "LegitApp"
    (folder / "EBWebView").mkdir(parents=True)
    _make_fake_exe(str(folder / "legit.exe"))

    monkeypatch.setattr(la, "_EXECUTOR_STRUCT_ROOTS", [str(fake_local)])
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: True)  # assinado

    r = la.scan_executor_structure()
    assert r["status"] == "clean"
    assert len(r["items"]) == 0


def test_undetermined_signature_does_not_flag(monkeypatch, tmp_path):
    """REGRESSÃO: se a verificação de assinatura retorna None (não deu pra
    determinar — WinVerifyTrust indisponível/erro), NÃO pode flagar.
    Evita tempestade de FP se a checagem falhar sistemicamente."""
    fake_local = tmp_path / "Local"
    folder = fake_local / "MaybeApp"
    (folder / "EBWebView").mkdir(parents=True)
    _make_fake_exe(str(folder / "app.exe"))

    monkeypatch.setattr(la, "_EXECUTOR_STRUCT_ROOTS", [str(fake_local)])
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: None)  # indeterminado

    r = la.scan_executor_structure()
    assert r["status"] == "clean", "None (indeterminado) não pode virar flag"
    assert len(r["items"]) == 0


def test_ignores_exe_without_embedded_runtime(monkeypatch, tmp_path):
    """Exe não-assinado SEM runtime web embutido não dispara (seria FP)."""
    fake_local = tmp_path / "Local"
    folder = fake_local / "SomeTool"
    folder.mkdir(parents=True)
    _make_fake_exe(str(folder / "tool.exe"))  # sem EBWebView

    monkeypatch.setattr(la, "_EXECUTOR_STRUCT_ROOTS", [str(fake_local)])
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)

    r = la.scan_executor_structure()
    assert r["status"] == "clean"
    assert len(r["items"]) == 0


def test_whitelists_microsoft_folders(monkeypatch, tmp_path):
    """Pastas Microsoft/Windows não disparam mesmo casando o padrão."""
    fake_local = tmp_path / "Local"
    folder = fake_local / "Microsoft" / "EdgeThing"
    (folder / "EBWebView").mkdir(parents=True)
    _make_fake_exe(str(folder / "edge.exe"))

    monkeypatch.setattr(la, "_EXECUTOR_STRUCT_ROOTS", [str(fake_local)])
    monkeypatch.setattr(la, "_is_dll_signed", lambda p: False)

    r = la.scan_executor_structure()
    assert r["status"] == "clean"


def test_real_clean_machine_zero_hits():
    """No PC real onde os testes rodam, NÃO pode haver hit (anti-FP).
    Se isto falhar, a heurística está pegando algo legítimo — investigar
    ANTES de qualquer release."""
    r = la.scan_executor_structure()
    assert r["status"] == "clean", \
        f"FP na máquina de teste: {[i['label'] for i in r['items']]}"


def test_behavioral_feeds_cluster_engine():
    """A evidência comportamental deve formar cluster (SUSPECT sozinha,
    nunca CONFIRMED sem corroboração)."""
    from telador import evidence as ev
    findings = [{
        "name": "Estrutura de executor (comportamental)",
        "status": "suspicious",
        "items": [{
            "label": "Estrutura de executor: loader.exe",
            "detail": r"C:\Users\x\AppData\Local\xyz\loader.exe",
            "matched": "executor-struct:xyz",
            "severity": "medium", "timestamp": "", "confidence": 60,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(clusters) == 1
    # 1 fonte só, medium → no máximo SUSPECT (FP protection)
    assert clusters[0].verdict in ("WEAK", "SUSPECT")
    assert clusters[0].verdict != "CONFIRMED"
