@echo off
setlocal

:: Use EWDK's own setup which handles all paths correctly
call "G:\BuildEnv\SetupBuildEnv.cmd" amd64

echo.
echo VCToolsInstallDir=%VCToolsInstallDir%
echo WDKContentRoot=%WDKContentRoot%
echo.

echo === Building Ophion ===
cd /d "F:\Raid\pythonProject4\hypervisor\Ophion"
MSBuild.exe Ophion.vcxproj /p:Configuration=Release /p:Platform=x64 /v:m
if %errorlevel% neq 0 (
    echo [FAIL] Ophion build failed
) else (
    echo [OK] Ophion built
)

echo.
echo === Building CommDriver ===
cd /d "F:\Raid\pythonProject4\hypervisor\CommDriver"
MSBuild.exe CommDriver.vcxproj /p:Configuration=Release /p:Platform=x64 /v:m
if %errorlevel% neq 0 (
    echo [FAIL] CommDriver build failed
) else (
    echo [OK] CommDriver built
)

echo.
echo === Building kdmapper ===
cd /d "F:\Raid\pythonProject4\hypervisor\kdmapper"
MSBuild.exe kdmapper.sln /p:Configuration=Release /p:Platform=x64 /v:m
if %errorlevel% neq 0 (
    echo [FAIL] kdmapper build failed
    echo     Essaye avec Visual Studio si EWDK echoue
) else (
    echo [OK] kdmapper built
    :: Copy to hypervisor root for easy access
    copy /y "kdmapper\x64\Release\kdmapper.exe" "F:\Raid\pythonProject4\hypervisor\kdmapper.exe" >nul 2>&1
    if exist "kdmapper\Release\kdmapper.exe" copy /y "kdmapper\Release\kdmapper.exe" "F:\Raid\pythonProject4\hypervisor\kdmapper.exe" >nul 2>&1
)

echo.
echo === Results ===
echo Drivers:
dir /b "F:\Raid\pythonProject4\hypervisor\Ophion\build\bin\Release\*.sys" 2>nul
dir /b "F:\Raid\pythonProject4\hypervisor\CommDriver\build\bin\Release\*.sys" 2>nul
echo.
echo kdmapper:
if exist "F:\Raid\pythonProject4\hypervisor\kdmapper.exe" (
    echo [OK] kdmapper.exe ready
) else (
    echo [!] kdmapper.exe not found
)
echo.
pause
