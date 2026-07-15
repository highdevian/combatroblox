"""
Testes do pack.py — script que empacota Telador-vX.X.X.zip.

Roda com um exe fake (arquivo txt renomeado) — não requer PyInstaller.
"""

import os
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pack
import version


def test_sha256_stable():
    """_sha256 é determinístico e retorna hex de 64 chars."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"hello world")
        p = Path(f.name)
    try:
        h1 = pack._sha256(p)
        h2 = pack._sha256(p)
        assert h1 == h2
        assert len(h1) == 64
        assert all(c in "0123456789abcdef" for c in h1)
    finally:
        p.unlink()


def test_build_zip_creates_expected_structure(tmp_path):
    """Zip gerado tem os 7 arquivos esperados + tudo dentro de Telador-vX.X.X/."""
    # Fake exe
    exe = tmp_path / "telador.exe"
    exe.write_bytes(b"fake exe binary content")

    # Project root minimal com bats + playbook
    project = tmp_path / "project"
    project.mkdir()
    (project / "INICIAR-GUI.bat").write_text("@echo GUI\n")
    (project / "INICIAR.bat").write_text("@echo CLI\n")
    (project / "TELADOR-AO-VIVO.bat").write_text("@echo watch\n")
    (project / "PLAYBOOK.md").write_text("# Playbook\n")

    output = tmp_path / "out"
    zip_path = pack.build_zip(exe.resolve(), output.resolve(), project.resolve())

    assert zip_path.is_file()
    assert zip_path.name == f"Telador-{version.VERSION_DISPLAY}.zip"

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        prefix = f"Telador-{version.VERSION_DISPLAY}"
        expected = {
            f"{prefix}/telador.exe",
            f"{prefix}/INICIAR-GUI.bat",
            f"{prefix}/INICIAR.bat",
            f"{prefix}/TELADOR-AO-VIVO.bat",
            f"{prefix}/PLAYBOOK.md",
            f"{prefix}/SHA256.txt",
            f"{prefix}/LEIA-ME.txt",
        }
        assert set(names) == expected, \
            f"missing: {expected - set(names)}, extra: {set(names) - expected}"

        # SHA256.txt contém o hash correto do exe
        sha_txt = zf.read(f"{prefix}/SHA256.txt").decode("utf-8")
        expected_sha = pack._sha256(exe)
        assert expected_sha in sha_txt

        # LEIA-ME.txt tem instruções básicas
        leia = zf.read(f"{prefix}/LEIA-ME.txt").decode("utf-8")
        assert "INICIAR-GUI.bat" in leia
        assert "SHA256" in leia
        assert version.VERSION_DISPLAY in leia


def test_build_zip_missing_exe_raises(tmp_path):
    """exe ausente = SystemExit."""
    import pytest
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(SystemExit):
        pack.build_zip(tmp_path / "nao-existe.exe", tmp_path / "out", project)


def test_build_zip_missing_optional_files_still_works(tmp_path):
    """Se bats/playbook faltam, zip ainda é criado com exe + SHA256 + LEIA-ME."""
    exe = tmp_path / "telador.exe"
    exe.write_bytes(b"fake")
    project = tmp_path / "project"
    project.mkdir()  # vazio — sem bats nem playbook
    output = tmp_path / "out"

    zip_path = pack.build_zip(exe.resolve(), output.resolve(), project.resolve())
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        # Pelo menos o exe + SHA256 + LEIA-ME sempre existem
        prefix = f"Telador-{version.VERSION_DISPLAY}"
        assert f"{prefix}/telador.exe" in names
        assert f"{prefix}/SHA256.txt" in names
        assert f"{prefix}/LEIA-ME.txt" in names


def test_leia_me_uses_current_version():
    """_leia_me renderiza a versão atual."""
    txt = pack._leia_me("abc123")
    assert version.VERSION_DISPLAY in txt
    assert "abc123" in txt


def test_playbook_md_exists_in_project():
    """Regressão: PLAYBOOK.md tem que existir na raiz do repo (senão zip fica sem)."""
    project = Path(__file__).parent.parent
    playbook = project / "PLAYBOOK.md"
    assert playbook.is_file(), "PLAYBOOK.md faltando na raiz — zip do CI vai omitir"
    content = playbook.read_text(encoding="utf-8")
    # Sanity check do conteúdo mínimo
    assert "Telador" in content
    assert "SS" in content
    assert "PLAYBOOK" in content or "Playbook" in content or "playbook" in content


def test_iniciar_gui_bat_exists():
    """Regressão: INICIAR-GUI.bat existe (senão pack.py só warns e usuário fica sem GUI)."""
    project = Path(__file__).parent.parent
    assert (project / "INICIAR-GUI.bat").is_file()
