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

from scripts import pack
from telador import version
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
    """Zip gerado tem os 8 arquivos esperados (v3.55+: inclui telador-gui.exe)."""
    exe = tmp_path / "telador.exe"
    exe.write_bytes(b"fake exe binary content")
    gui_exe = tmp_path / "telador-gui.exe"
    gui_exe.write_bytes(b"fake gui exe (windowed)")

    project = tmp_path / "project"
    project.mkdir()
    (project / "INICIAR-GUI.bat").write_text("@echo GUI\n")
    (project / "INICIAR.bat").write_text("@echo CLI\n")
    (project / "TELADOR-AO-VIVO.bat").write_text("@echo watch\n")
    (project / "PLAYBOOK.md").write_text("# Playbook\n")

    output = tmp_path / "out"
    zip_path = pack.build_zip(
        exe.resolve(), output.resolve(), project.resolve(),
        gui_exe_path=gui_exe.resolve(),
    )

    assert zip_path.is_file()
    assert zip_path.name == f"Telador-{version.VERSION_DISPLAY}.zip"

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        prefix = f"Telador-{version.VERSION_DISPLAY}"
        expected = {
            f"{prefix}/telador.exe",
            f"{prefix}/telador-gui.exe",  # v3.55+
            f"{prefix}/INICIAR-GUI.bat",
            f"{prefix}/INICIAR.bat",
            f"{prefix}/TELADOR-AO-VIVO.bat",
            f"{prefix}/PLAYBOOK.md",
            f"{prefix}/SHA256.txt",
            f"{prefix}/LEIA-ME.txt",
        }
        assert set(names) == expected, \
            f"missing: {expected - set(names)}, extra: {set(names) - expected}"

        # SHA256.txt tem hash de AMBOS os exes
        sha_txt = zf.read(f"{prefix}/SHA256.txt").decode("utf-8")
        assert pack._sha256(exe) in sha_txt
        assert pack._sha256(gui_exe) in sha_txt
        assert "telador.exe" in sha_txt
        assert "telador-gui.exe" in sha_txt

        # LEIA-ME.txt tem instrucoes basicas
        leia = zf.read(f"{prefix}/LEIA-ME.txt").decode("utf-8")
        assert "telador-gui.exe" in leia
        assert "SHA256" in leia
        assert version.VERSION_DISPLAY in leia
        assert "SmartScreen" in leia  # workaround documentado


def test_build_zip_without_gui_exe(tmp_path):
    """Se gui_exe_path=None, zip ainda funciona (backward-compat)."""
    exe = tmp_path / "telador.exe"
    exe.write_bytes(b"fake")
    project = tmp_path / "project"
    project.mkdir()

    zip_path = pack.build_zip(exe.resolve(), (tmp_path / "out").resolve(),
                               project.resolve(), gui_exe_path=None)
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        prefix = f"Telador-{version.VERSION_DISPLAY}"
        assert f"{prefix}/telador.exe" in names
        # SEM telador-gui.exe (nao foi passado)
        assert f"{prefix}/telador-gui.exe" not in names


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
    """_leia_me renderiza a versao atual + SHA(s)."""
    txt = pack._leia_me("abc123", "def456")
    assert version.VERSION_DISPLAY in txt
    assert "abc123" in txt  # cli sha
    assert "def456" in txt  # gui sha
    assert "SmartScreen" in txt  # workaround documentado


def test_leia_me_without_gui_sha():
    """Se gui_sha vazia, LEIA-ME omite a linha do gui exe."""
    txt = pack._leia_me("abc123", "")
    assert "abc123" in txt
    assert "def456" not in txt


def test_playbook_md_exists_in_project():
    """Regressão: PLAYBOOK.md tem que existir na raiz do repo (senão zip fica sem)."""
    project = Path(__file__).parent.parent
    playbook = project / "docs" / "PLAYBOOK.md"
    assert playbook.is_file(), "PLAYBOOK.md faltando em docs/ — zip do CI vai omitir"
    content = playbook.read_text(encoding="utf-8")
    # Sanity check do conteúdo mínimo
    assert "Telador" in content
    assert "SS" in content
    assert "PLAYBOOK" in content or "Playbook" in content or "playbook" in content


def test_iniciar_gui_bat_exists():
    """Regressão: INICIAR-GUI.bat existe (senão pack.py só warns e usuário fica sem GUI)."""
    project = Path(__file__).parent.parent
    assert (project / "INICIAR-GUI.bat").is_file()
