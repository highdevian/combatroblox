@echo off
setlocal
cd /d "%~dp0"

REM ============================================================
REM   Telador - modo GUI (janela, sem terminal)
REM   Distribuidor: staff cola isso no zip pro suspeito.
REM
REM   Prefere telador-gui.exe (windowed, sem console flash).
REM   Fallback: telador.exe --gui (console flash antes da janela).
REM ============================================================

REM 1) telador-gui.exe (versao windowed, sem console) - preferido
if exist "dist\telador-gui.exe" (
    start "" "%~dp0dist\telador-gui.exe"
    exit /b 0
)
if exist "telador-gui.exe" (
    start "" "%~dp0telador-gui.exe"
    exit /b 0
)

REM 2) telador.exe --gui (fallback: mostra console por 1s antes da janela)
if exist "dist\telador.exe" (
    start "" "%~dp0dist\telador.exe" --gui
    exit /b 0
)
if exist "telador.exe" (
    start "" "%~dp0telador.exe" --gui
    exit /b 0
)

REM 2) Fallback: rodar via Python
where python >nul 2>nul
if errorlevel 1 (
    echo ERRO: Python nao encontrado no PATH.
    echo Instale Python 3.10+ e marque "Add Python to PATH".
    pause
    exit /b 1
)

python -c "import customtkinter" >nul 2>nul
if errorlevel 1 (
    echo Instalando customtkinter (GUI)...
    python -m pip install --disable-pip-version-check -q customtkinter
    if errorlevel 1 (
        echo ERRO: Falha ao instalar customtkinter.
        pause
        exit /b 1
    )
)

python -m pip install --disable-pip-version-check -q -r requirements.txt
python telador.py --gui

if errorlevel 1 (
    echo.
    echo GUI encerrou com erro.
    pause
    exit /b 1
)
exit /b 0
