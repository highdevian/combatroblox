@echo off
REM ============================================================
REM   Build do Telador BR em executavel unico (.exe)
REM   Saida: dist\telador.exe
REM
REM   Usa telador.spec (mesmo que o CI em release.yml) — nao
REM   duplica lista de hidden-imports, garantido reproducibilidade.
REM   Nunca apaga o .spec (ele e' commitado, nao gerado).
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

python -c "import customtkinter" >nul 2>nul
if errorlevel 1 (
    echo   - Instalando customtkinter (GUI)...
    python -m pip install --no-cache-dir customtkinter
    if errorlevel 1 (
        echo ERRO: Falha ao instalar customtkinter.
        pause
        exit /b 1
    )
) else (
    echo   - customtkinter OK
)

REM Sanity check pre-build: se import quebra local, quebra no CI tambem.
echo.
echo [2.5/4] Pre-flight check (import telador)...
python -c "import telador" >nul 2>nul
if errorlevel 1 (
    echo ERRO: import telador falhou. Rode 'python -c "import telador"' pra ver o erro.
    pause
    exit /b 1
) else (
    echo   - imports OK
)

echo.
echo [3/4] Limpando builds antigos...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
REM NAO deletar telador.spec — ele e' commitado (v3.50.5+) e o build depende dele.

echo.
echo [4/4] Gerando executavel via telador.spec...
python -m PyInstaller telador.spec

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
