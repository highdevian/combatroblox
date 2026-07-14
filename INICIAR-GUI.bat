@echo off
setlocal
cd /d "%~dp0"

REM ============================================================
REM   Telador — modo GUI (janela, sem terminal)
REM   Distribuidor: staff cola isso no zip pro suspeito.
REM ============================================================

REM 1) Se ja existe executavel, usa ele com --gui (2 cliques e pronto)
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
