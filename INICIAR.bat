@echo off
setlocal
cd /d "%~dp0"

echo ==============================================
echo   Combat Roblox - Inicializacao Rapida
echo ==============================================
echo.

REM 1) Se ja existe executavel, usa ele (2 cliques e acabou)
if exist "dist\telador.exe" (
    echo Iniciando versao executavel...
    start "" "%~dp0dist\telador.exe"
    exit /b 0
)

REM 2) Fallback para Python
where python >nul 2>nul
if errorlevel 1 (
    echo ERRO: Python nao encontrado no PATH.
    echo Instale o Python 3.10+ e marque "Add Python to PATH".
    pause
    exit /b 1
)

echo Instalando/atualizando dependencias...
python -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 (
    echo ERRO: Falha ao instalar dependencias.
    pause
    exit /b 1
)

echo Iniciando via Python...
python -m telador

if errorlevel 1 (
    echo.
    echo O programa encerrou com erro.
    pause
    exit /b 1
)

exit /b 0
