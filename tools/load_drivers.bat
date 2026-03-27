@echo off
echo ============================================
echo   ARC RAIDERS - DRIVER LOADER
echo ============================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ADMIN REQUIRED
    pause
    exit /b 1
)

echo [*] Checking prerequisites...

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
echo [*] Loading Ophion hypervisor...
sc stop Ophion >nul 2>&1
sc delete Ophion >nul 2>&1
sc create Ophion type= kernel binPath= "%OPHION_PATH%"
sc start Ophion
if %errorLevel% neq 0 (
    echo [!] OPHION FAILED
    sc delete Ophion >nul 2>&1
    pause
    exit /b 1
)
echo [+] Ophion loaded

echo.
echo [*] Loading CommDriver...
sc stop ArcComm >nul 2>&1
sc delete ArcComm >nul 2>&1
sc create ArcComm type= kernel binPath= "%COMM_PATH%"
sc start ArcComm
if %errorLevel% neq 0 (
    echo [!] COMMDRIVER FAILED
    sc delete ArcComm >nul 2>&1
    pause
    exit /b 1
)
echo [+] CommDriver loaded

echo.
echo ============================================
echo   ALL DRIVERS LOADED
echo ============================================
echo   Now run: python tools\radar_windows.py
echo.
pause
