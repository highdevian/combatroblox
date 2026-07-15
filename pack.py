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


def _leia_me(exe_sha: str) -> str:
    """LEIA-ME.txt curtinho — instrução mínima em .txt (roda em qualquer editor)."""
    return f"""Telador {version.VERSION_DISPLAY} — SS forense pra Roblox
========================================================

COMO USAR (2 cliques):
    1. Descompacte este zip em qualquer pasta (ex: Desktop).
    2. Duplo-clique em INICIAR-GUI.bat
    3. Aceite o UAC (Sim no popup do Windows).
    4. Clique em "Iniciar SS" na janela do Telador.
    5. Aguarde ~30-40s.
    6. Leia o veredito e clique em "Copiar resumo Discord".

Alternativas:
    INICIAR.bat            - modo terminal (sem janela)
    TELADOR-AO-VIVO.bat    - dashboard local (--watch)

Read the full ritual in PLAYBOOK.md.

SHA256 do telador.exe:
    {exe_sha}

Compare com o hash na página do release oficial:
    https://github.com/highdevian/combatroblox/releases/latest

100% local. Nada sai do PC.
Open source: github.com/highdevian/combatroblox
Licença: MIT
"""


def _read_bytes_maybe(path: Path) -> bytes | None:
    return path.read_bytes() if path.is_file() else None


def build_zip(
    exe_path: Path,
    output_dir: Path,
    project_root: Path,
) -> Path:
    """Monta o zip. Retorna caminho do zip criado."""
    if not exe_path.is_file():
        raise SystemExit(f"exe não encontrado: {exe_path}")

    exe_sha = _sha256(exe_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    zip_name = f"Telador-{version.VERSION_DISPLAY}.zip"
    zip_path = output_dir / zip_name

    dist_root = f"Telador-{version.VERSION_DISPLAY}"

    files_to_include = {
        f"{dist_root}/telador.exe": exe_path.read_bytes(),
    }

    # Bats + docs — só adiciona se existirem no project_root
    for name in ("INICIAR-GUI.bat", "INICIAR.bat", "TELADOR-AO-VIVO.bat",
                 "PLAYBOOK.md"):
        content = _read_bytes_maybe(project_root / name)
        if content is not None:
            files_to_include[f"{dist_root}/{name}"] = content
        else:
            print(f"[warn] arquivo opcional ausente: {name}")

    # SHA256.txt
    sha_txt = (f"# SHA256 do telador.exe\n"
               f"# Compare com o hash na pagina do release oficial:\n"
               f"# https://github.com/highdevian/combatroblox/releases/tag/{version.VERSION_DISPLAY}\n\n"
               f"{exe_sha}  telador.exe\n").encode("utf-8")
    files_to_include[f"{dist_root}/SHA256.txt"] = sha_txt

    # LEIA-ME.txt
    files_to_include[f"{dist_root}/LEIA-ME.txt"] = \
        _leia_me(exe_sha).encode("utf-8")

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
        description="Empacota Telador-vX.X.X.zip de distribuição.")
    parser.add_argument("--exe", default=None,
                        help="Path do telador.exe (default: dist/telador.exe)")
    parser.add_argument("--output", default=None,
                        help="Diretório de saída (default: dist/)")
    args = parser.parse_args()

    project_root = Path(__file__).parent.resolve()

    exe_path = Path(args.exe) if args.exe else project_root / "dist" / "telador.exe"
    output_dir = Path(args.output) if args.output else project_root / "dist"

    zip_path = build_zip(exe_path.resolve(), output_dir.resolve(), project_root)

    # Sobe também o SHA256 do próprio zip (às vezes útil pra ligas paranoicas)
    zip_sha = _sha256(zip_path)
    print(f"[pack]   sha256(zip):         {zip_sha}")


if __name__ == "__main__":
    main()
