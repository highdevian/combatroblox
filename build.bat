@echo off
REM ============================================================
REM   Build do Telador BR em executavel unico (.exe)
REM   Saida: dist\telador.exe
REM ============================================================

setlocal

echo.
echo [1/4] Verificando Python...
where python >nul 2>nul
if errorlevel 1 (
    echo ERRO: Python nao encontrado no PATH.
    pause
    exit /b 1
)

echo.
echo [2/4] Verificando dependencias...
python -c "import psutil" >nul 2>nul
if errorlevel 1 (
    echo   - Instalando psutil...
    python -m pip install --no-cache-dir psutil
    if errorlevel 1 (
        echo ERRO: Falha ao instalar psutil.
        pause
        exit /b 1
    )
) else (
    echo   - psutil OK
)

python -c "import PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo   - Instalando PyInstaller...
    python -m pip install --no-cache-dir pyinstaller
    if errorlevel 1 (
        echo ERRO: Falha ao instalar PyInstaller.
        pause
        exit /b 1
    )
) else (
    echo   - PyInstaller OK
)

echo.
echo [3/4] Limpando builds antigos...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist telador.spec del /q telador.spec

echo.
echo [4/4] Gerando executavel...
python -m PyInstaller ^
    --onefile ^
    --console ^
    --name telador ^
    --hidden-import psutil ^
    --hidden-import winreg ^
    --hidden-import sqlite3 ^
    --hidden-import zlib ^
    --hidden-import ctypes.wintypes ^
    --hidden-import concurrent.futures ^
    --hidden-import live_analysis ^
    --hidden-import command_history ^
    --hidden-import peripherals ^
    --hidden-import fp_filter ^
    --hidden-import pe_analysis ^
    --hidden-import report_signing ^
    --hidden-import diff_tool ^
    --hidden-import redaction ^
    --hidden-import report_md ^
    --hidden-import hashlib ^
    --hidden-import hmac ^
    --collect-submodules psutil ^
    telador.py

if errorlevel 1 (
    echo.
    echo ERRO: Build falhou.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   BUILD COMPLETO
echo   Arquivo gerado: dist\telador.exe
echo ============================================================
echo.
pause
