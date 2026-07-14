# -*- mode: python ; coding: utf-8 -*-
"""
Spec file explícito pro build do telador.exe. Enumera TODOS os módulos
python locais como hiddenimports pra garantir que PyInstaller inclua
mesmo quando análise estática falha em detectar (bug conhecido no 6.21
com onefile + muitos módulos top-level).

Gerado do release.yml e verificado com pytest — se um módulo falta aqui,
os testes teriam quebrado antes.

v3.54.0+: bundla customtkinter (GUI) — CTk usa data files (temas JSON)
que PyInstaller normalmente perde; usa collect_data_files pra pegar tudo.
"""
import glob
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

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
    # GUI (Tkinter é stdlib mas hiddenimports vezes ajuda)
    "tkinter", "tkinter.ttk", "tkinter.messagebox",
]

# CustomTkinter: precisa dos temas JSON (color-themes, assets) + submodules.
# Sem isso, o GUI abre com erro "assets/CustomTkinter_..." not found.
_ctk_datas = []
_ctk_hidden = []
try:
    _ctk_datas = collect_data_files("customtkinter")
    _ctk_hidden = collect_submodules("customtkinter") + ["darkdetect"]
except Exception:
    # Se PyInstaller não tem os hooks, deixa vazio — CTk vai falhar em runtime
    # com msg amigável (gui.py cai pra CLI se HAS_CTK False).
    pass

a = Analysis(
    ['telador.py'],
    pathex=['.'],
    binaries=[],
    datas=_ctk_datas,
    hiddenimports=_STDLIB_HIDDEN + _ROOT_MODULES + _ctk_hidden,
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
    console=True,  # mantém console pro CLI; --gui abre janela por cima
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
    version='version_info.txt',
)
