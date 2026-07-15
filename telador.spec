# -*- mode: python ; coding: utf-8 -*-
"""
Spec file explícito pro build do telador.exe. Enumera TODOS os módulos
python locais como hiddenimports pra garantir que PyInstaller inclua
mesmo quando análise estática falha em detectar (bug conhecido no 6.21
com onefile + muitos módulos top-level).

Gerado do release.yml e verificado com pytest — se um módulo falta aqui,
os testes teriam quebrado antes.

v3.54.0+: bundla customtkinter (GUI).

v3.55.0+: builda DOIS exes na mesma spec:
  - telador.exe      (console=True, entry=telador.py, CLI clássico)
  - telador-gui.exe  (console=False, entry=gui.py, janela sem console flash)

Motivo: `telador.exe --gui` mostrava um console preto por 1-2 seg antes da
janela abrir — feio e faz o suspeito desconfiar. Duplo-clique no
telador-gui.exe abre direto a janela, zero console.
"""
import glob
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# Enumera todo .py na raiz do projeto (excluindo testes e scripts)
_ROOT_MODULES = sorted({
    os.path.splitext(os.path.basename(p))[0]
    for p in glob.glob("*.py")
    if not os.path.basename(p).startswith(("_", "test_", "build_"))
    and os.path.basename(p) not in {"telador.py", "conftest.py", "gui.py"}
})

_STDLIB_HIDDEN = [
    "psutil", "winreg", "sqlite3", "zlib", "ctypes.wintypes",
    "concurrent.futures", "http.server", "urllib.request",
    "hashlib", "hmac",
    "tkinter", "tkinter.ttk", "tkinter.messagebox",
]

# CustomTkinter: precisa dos temas JSON + submodules.
_ctk_datas = []
_ctk_hidden = []
try:
    _ctk_datas = collect_data_files("customtkinter")
    _ctk_hidden = collect_submodules("customtkinter") + ["darkdetect"]
except Exception:
    pass

# ---- Analysis compartilhado (telador.py como entry principal) ----
a_cli = Analysis(
    ['telador.py'],
    pathex=['.'],
    binaries=[],
    datas=_ctk_datas,
    hiddenimports=_STDLIB_HIDDEN + _ROOT_MODULES + _ctk_hidden + ['gui'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# ---- Analysis pra GUI (gui.py como entry — sem console) ----
a_gui = Analysis(
    ['gui.py'],
    pathex=['.'],
    binaries=[],
    datas=_ctk_datas,
    hiddenimports=_STDLIB_HIDDEN + _ROOT_MODULES + _ctk_hidden + ['telador'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz_cli = PYZ(a_cli.pure)
pyz_gui = PYZ(a_gui.pure)

# telador.exe — CLI (console=True)
exe_cli = EXE(
    pyz_cli, a_cli.scripts, a_cli.binaries, a_cli.datas, [],
    name='telador',
    debug=False, bootloader_ignore_signals=False, strip=False,
    upx=False, upx_exclude=[], runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False, argv_emulation=False,
    target_arch=None, codesign_identity=None, entitlements_file=None,
    icon='icon.ico', version='version_info.txt',
)

# telador-gui.exe — GUI (console=False, janela sem terminal)
exe_gui = EXE(
    pyz_gui, a_gui.scripts, a_gui.binaries, a_gui.datas, [],
    name='telador-gui',
    debug=False, bootloader_ignore_signals=False, strip=False,
    upx=False, upx_exclude=[], runtime_tmpdir=None,
    console=False,  # windowed — SEM console flashing
    disable_windowed_traceback=False, argv_emulation=False,
    target_arch=None, codesign_identity=None, entitlements_file=None,
    icon='icon.ico', version='version_info.txt',
)
