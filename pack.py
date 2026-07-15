"""
Empacota o `Telador-vX.X.X.zip` de distribuição.

Uso:
    python pack.py                        # usa dist/telador.exe
    python pack.py --exe path/to/telador.exe
    python pack.py --output custom/dir

O zip contém:
    Telador-vX.X.X/
        telador.exe
        INICIAR-GUI.bat        (2 cliques → GUI)
        INICIAR.bat            (fallback CLI)
        TELADOR-AO-VIVO.bat    (dashboard --watch)
        PLAYBOOK.md            (1 pág pra staff)
        SHA256.txt             (hash do exe pra verificação)
        LEIA-ME.txt            (instrução mínima)

Roda no CI (release.yml) após buildar o exe, e também localmente.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import zipfile
from pathlib import Path

import version


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _leia_me(exe_sha: str, gui_sha: str = "") -> str:
    """LEIA-ME.txt em .txt (roda em qualquer editor)."""
    gui_line = f"\nSHA256 do telador-gui.exe:\n    {gui_sha}\n" if gui_sha else ""
    return f"""Telador {version.VERSION_DISPLAY}: SS forense pra Roblox
========================================================

COMO USAR (2 cliques):
    1. Descompacte este zip em qualquer pasta (ex: Desktop).
    2. Duplo-clique em telador-gui.exe (janela abre direto,
       sem terminal preto).
    3. Aceite o UAC (Sim no popup do Windows).
    4. Escolha "Completo" ou "Rapido" e clique em INICIAR SS.
    5. Aguarde 30 s (Rapido) ou 2-3 min (Completo).
    6. Leia o veredito, clique em "Copiar resumo Discord".

Alternativas:
    INICIAR-GUI.bat        - abre a mesma GUI via .bat (equivalente)
    INICIAR.bat            - modo terminal (sem janela)
    TELADOR-AO-VIVO.bat    - dashboard local (--watch)

O ritual completo pra staff esta em PLAYBOOK.md.

SHA256 do telador.exe (CLI):
    {exe_sha}
{gui_line}
Compare com os hashes na pagina do release oficial:
    https://github.com/highdevian/combatroblox/releases/latest

AVISO SmartScreen / Antivirus:
    Windows pode mostrar "Windows protegeu seu PC" no primeiro run.
    Isso e' porque o exe nao tem code-signing (custa 200 USD/ano).
    Clique em "Mais informacoes" > "Executar assim mesmo".
    Alternativa: rode via Python (github.com/highdevian/combatroblox).

100% local. Nada sai do PC.
Open source: github.com/highdevian/combatroblox
Licenca: MIT
"""


def _read_bytes_maybe(path: Path) -> bytes | None:
    return path.read_bytes() if path.is_file() else None


def build_zip(
    exe_path: Path,
    output_dir: Path,
    project_root: Path,
    gui_exe_path: Path | None = None,
) -> Path:
    """Monta o zip. Retorna caminho do zip criado.

    Args:
        exe_path: telador.exe (CLI).
        output_dir: onde salvar o zip.
        project_root: raiz do projeto (pra achar bats/playbook).
        gui_exe_path: telador-gui.exe (windowed, sem console). Opcional
            no v3.55.0+ mas altamente recomendado — se ausente, o zip
            fica só com CLI + INICIAR-GUI.bat cai pra `--gui` (console flash).
    """
    if not exe_path.is_file():
        raise SystemExit(f"exe nao encontrado: {exe_path}")

    exe_sha = _sha256(exe_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    zip_name = f"Telador-{version.VERSION_DISPLAY}.zip"
    zip_path = output_dir / zip_name

    dist_root = f"Telador-{version.VERSION_DISPLAY}"

    files_to_include = {
        f"{dist_root}/telador.exe": exe_path.read_bytes(),
    }

    gui_sha = ""
    if gui_exe_path and gui_exe_path.is_file():
        files_to_include[f"{dist_root}/telador-gui.exe"] = gui_exe_path.read_bytes()
        gui_sha = _sha256(gui_exe_path)
    else:
        print(f"[warn] telador-gui.exe ausente - zip so tem CLI + fallback --gui")

    # Bats + docs
    for name in ("INICIAR-GUI.bat", "INICIAR.bat", "TELADOR-AO-VIVO.bat",
                 "PLAYBOOK.md"):
        content = _read_bytes_maybe(project_root / name)
        if content is not None:
            files_to_include[f"{dist_root}/{name}"] = content
        else:
            print(f"[warn] arquivo opcional ausente: {name}")

    # SHA256.txt (agora com AMBOS os exes)
    sha_lines = [
        f"# SHA256 dos exes deste zip",
        f"# Compare com os hashes na pagina do release oficial:",
        f"# https://github.com/highdevian/combatroblox/releases/tag/{version.VERSION_DISPLAY}",
        "",
        f"{exe_sha}  telador.exe",
    ]
    if gui_sha:
        sha_lines.append(f"{gui_sha}  telador-gui.exe")
    files_to_include[f"{dist_root}/SHA256.txt"] = ("\n".join(sha_lines) + "\n").encode("utf-8")

    # LEIA-ME.txt
    files_to_include[f"{dist_root}/LEIA-ME.txt"] = \
        _leia_me(exe_sha, gui_sha).encode("utf-8")

    # Escreve o zip (deflate, sem compressão máxima pra ser rápido no CI)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED,
                          compresslevel=6) as zf:
        for arcname, data in files_to_include.items():
            zf.writestr(arcname, data)

    total_size = sum(len(d) for d in files_to_include.values())
    print(f"[pack] {zip_path}")
    print(f"[pack]   {len(files_to_include)} arquivo(s), "
          f"{total_size / 1024 / 1024:.1f} MB descomprimido")
    print(f"[pack]   zip: {zip_path.stat().st_size / 1024 / 1024:.1f} MB")
    print(f"[pack]   sha256(telador.exe): {exe_sha}")
    return zip_path


def main():
    parser = argparse.ArgumentParser(
        description="Empacota Telador-vX.X.X.zip de distribuicao.")
    parser.add_argument("--exe", default=None,
                        help="Path do telador.exe (default: dist/telador.exe)")
    parser.add_argument("--gui-exe", default=None,
                        help="Path do telador-gui.exe windowed (default: dist/telador-gui.exe)")
    parser.add_argument("--output", default=None,
                        help="Diretorio de saida (default: dist/)")
    args = parser.parse_args()

    project_root = Path(__file__).parent.resolve()

    exe_path = Path(args.exe) if args.exe else project_root / "dist" / "telador.exe"
    gui_exe_path = Path(args.gui_exe) if args.gui_exe else project_root / "dist" / "telador-gui.exe"
    output_dir = Path(args.output) if args.output else project_root / "dist"

    zip_path = build_zip(
        exe_path.resolve(), output_dir.resolve(), project_root,
        gui_exe_path=gui_exe_path.resolve() if gui_exe_path.exists() else None,
    )

    # Sobe também o SHA256 do próprio zip (às vezes útil pra ligas paranoicas)
    zip_sha = _sha256(zip_path)
    print(f"[pack]   sha256(zip):         {zip_sha}")


if __name__ == "__main__":
    main()
