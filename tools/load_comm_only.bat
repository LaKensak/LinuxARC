@echo off
echo ============================================
echo   ARC RAIDERS - CommDriver ONLY
echo   (sans Ophion pour le moment)
echo ============================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ADMIN REQUIRED - relance en admin
    pause
    exit /b 1
)

set "KDMAPPER=F:\Raid\pythonProject4\hypervisor\kdmapper.exe"
set "COMM=F:\Raid\pythonProject4\hypervisor\CommDriver\build\bin\Release\CommDriver.sys"

if not exist "%KDMAPPER%" (
    echo [!] kdmapper.exe non trouve
    pause
    exit /b 1
)
if not exist "%COMM%" (
    echo [!] CommDriver.sys non trouve
    pause
    exit /b 1
)

echo [*] Chargement de CommDriver via kdmapper...
"%KDMAPPER%" "%COMM%"

echo.
echo [*] Resultat: errorlevel=%errorLevel%
echo [*] Si tu vois "[+] success" ci-dessus, c'est bon.
echo.
echo Maintenant lance le jeu puis:
echo   python tools\radar_windows.py
echo.
pause
