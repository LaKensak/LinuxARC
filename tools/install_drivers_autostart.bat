@echo off
echo ============================================
echo   ARC RAIDERS - INSTALL DRIVERS (AUTO-START)
echo ============================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ADMIN REQUIRED
    pause
    exit /b 1
)

bcdedit /enum {current} | findstr /i "testsigning.*Yes" >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Test Signing is NOT enabled
    echo     Run: bcdedit /set testsigning on
    pause
    exit /b 1
)
echo [+] Test Signing: OK

set "SCRIPT_DIR=%~dp0"
set "OPHION_PATH=%SCRIPT_DIR%..\hypervisor\Ophion\build\bin\Release\Ophion.sys"
set "COMM_PATH=%SCRIPT_DIR%..\hypervisor\CommDriver\build\bin\Release\CommDriver.sys"

if not exist "%OPHION_PATH%" (
    echo [!] Ophion.sys not found
    pause
    exit /b 1
)
if not exist "%COMM_PATH%" (
    echo [!] CommDriver.sys not found
    pause
    exit /b 1
)

echo.
echo [*] Installing Ophion (auto-start)...
sc stop Ophion >nul 2>&1
sc delete Ophion >nul 2>&1
sc create Ophion type= kernel start= auto binPath= "%OPHION_PATH%"
if %errorLevel% neq 0 (
    echo [!] OPHION INSTALL FAILED
    pause
    exit /b 1
)
sc start Ophion
echo [+] Ophion installed (auto-start)

echo.
echo [*] Installing ArcComm (auto-start)...
sc stop ArcComm >nul 2>&1
sc delete ArcComm >nul 2>&1
sc create ArcComm type= kernel start= auto binPath= "%COMM_PATH%"
if %errorLevel% neq 0 (
    echo [!] COMMDRIVER INSTALL FAILED
    pause
    exit /b 1
)
sc start ArcComm
echo [+] ArcComm installed (auto-start)

echo.
echo ============================================
echo   DRIVERS INSTALLED - AUTO-START ENABLED
echo ============================================
echo   Les drivers se chargeront automatiquement
echo   a chaque demarrage de Windows.
echo.
echo   Pour desinstaller:
echo     sc stop Ophion ^&^& sc delete Ophion
echo     sc stop ArcComm ^&^& sc delete ArcComm
echo.
pause
