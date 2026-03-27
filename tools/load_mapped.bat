@echo off
echo ============================================
echo   ARC RAIDERS - MAPPED DRIVER LOADER
echo   (pas besoin de test signing)
echo ============================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ADMIN REQUIRED
    pause
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"
set "KDMAPPER=%SCRIPT_DIR%..\hypervisor\kdmapper.exe"
set "OPHION=%SCRIPT_DIR%..\hypervisor\Ophion\build\bin\Release\Ophion.sys"
set "COMM=%SCRIPT_DIR%..\hypervisor\CommDriver\build\bin\Release\CommDriver.sys"

echo [*] Verification des fichiers...

if not exist "%KDMAPPER%" (
    echo [!] kdmapper.exe non trouve!
    echo     Telecharge-le depuis: https://github.com/TheCruZ/kdmapper
    echo     Place-le dans: hypervisor\kdmapper.exe
    pause
    exit /b 1
)
if not exist "%OPHION%" (
    echo [!] Ophion.sys non trouve!
    pause
    exit /b 1
)
if not exist "%COMM%" (
    echo [!] CommDriver.sys non trouve!
    pause
    exit /b 1
)

echo [+] Fichiers OK
echo.

echo [*] Chargement de Ophion (hyperviseur)...
"%KDMAPPER%" "%OPHION%"
if %errorLevel% neq 0 (
    echo [!] Ophion FAILED (erreur %errorLevel%)
    echo     Si erreur de blocklist, desactive:
    echo     Windows Security ^> Device Security ^> Core isolation
    echo     ^> Microsoft Vulnerable Driver Blocklist ^> OFF
    pause
    exit /b 1
)
echo [+] Ophion charge!
echo.

echo [*] Chargement de CommDriver...
"%KDMAPPER%" "%COMM%"
if %errorLevel% neq 0 (
    echo [!] CommDriver FAILED (erreur %errorLevel%)
    pause
    exit /b 1
)
echo [+] CommDriver charge!
echo.

echo ============================================
echo   DRIVERS CHARGES - PRETS
echo ============================================
echo   Maintenant lance le jeu puis:
echo   python tools\radar_windows.py
echo.
pause
