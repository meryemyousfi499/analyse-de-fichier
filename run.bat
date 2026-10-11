@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

if not exist venv (
    echo Creation de l'environnement virtuel...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo Installation des dependances...
pip install --upgrade pip >nul

REM Installation paquet par paquet : un echec sur un paquet optionnel
REM (ex: yara-python ou py7zr qui necessitent parfois un compilateur C++)
REM n'empeche plus l'installation des autres. L'agent se degrade proprement
REM si un moteur optionnel manque.
for /f "usebackq delims=" %%p in ("requirements.txt") do (
    set "line=%%p"
    if not "!line!"=="" if not "!line:~0,1!"=="#" (
        echo   - installation de !line!
        pip install "!line!"
        if errorlevel 1 (
            echo     ATTENTION : echec pour !line! ^(optionnel, l'agent continuera sans^)
        )
    )
)

REM Cas particulier Windows : python-magic ne fonctionne pas nativement,
REM il faut la version "bin" qui embarque la DLL libmagic.
pip install python-magic-bin >nul 2>&1

echo.
echo Verification des modules critiques (Flask)...
python -c "import flask" 2>nul
if errorlevel 1 (
    echo ERREUR CRITIQUE : Flask n'a pas pu s'installer, l'agent ne peut pas demarrer.
    echo Verifiez votre connexion internet et relancez run.bat.
    pause
    exit /b 1
)

echo.
echo Lancement du dashboard sur http://127.0.0.1:5000
python app.py