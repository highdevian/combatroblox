@echo off
setlocal
cd /d "%~dp0"

echo ==============================================
echo   Telador - Dashboard AO VIVO (--watch)
echo ==============================================
echo.
echo Abre um painel no navegador mostrando os scanners
echo e o veredito em tempo real. Tudo local, nada sai do PC.
echo.

REM 1) Se ja existe executavel, usa ele com --watch (2 cliques e acabou)
if exist "dist\telador.exe" (
    echo Iniciando dashboard ao vivo...
    start "" "%~dp0dist\telador.exe" --watch
    exit /b 0
)
if exist "telador.exe" (
    echo Iniciando dashboard ao vivo...
    start "" "%~dp0telador.exe" --watch
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

echo Iniciando dashboard ao vivo via Python...
python telador.py --watch

if errorlevel 1 (
    echo.
    echo O programa encerrou com erro.
    pause
    exit /b 1
)

exit /b 0
