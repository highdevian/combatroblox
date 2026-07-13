# -*- mode: python ; coding: utf-8 -*-
"""
Spec file explícito pro build do telador.exe. Enumera TODOS os módulos
python locais como hiddenimports pra garantir que PyInstaller inclua
mesmo quando análise estática falha em detectar (bug conhecido no 6.21
com onefile + muitos módulos top-level).

Gerado do release.yml e verificado com pytest — se um módulo falta aqui,
os testes teriam quebrado antes.
"""
import glob
import os

# Enumera todo .py na raiz do projeto (excluindo testes e scripts)
_ROOT_MODULES = sorted({
    os.path.splitext(os.path.basename(p))[0]
    for p in glob.glob("*.py")
    if not os.path.basename(p).startswith(("_", "test_", "build_"))
    and os.path.basename(p) not in {"telador.py", "conftest.py"}
})

_STDLIB_HIDDEN = [
    "psutil", "winreg", "sqlite3", "zlib", "ctypes.wintypes",
    "concurrent.futures", "http.server", "urllib.request",
    "hashlib", "hmac",
]

a = Analysis(
    ['telador.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=_STDLIB_HIDDEN + _ROOT_MODULES,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='telador',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
    version='version_info.txt',
)
