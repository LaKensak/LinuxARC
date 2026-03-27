@echo off
call "G:\BuildEnv\SetupBuildEnv.cmd" amd64
echo MSBUILD CHECK:
where MSBuild.exe 2>nul
echo.
echo === Building CommDriver ===
cd /d "F:\Raid\pythonProject4\hypervisor\CommDriver"
MSBuild.exe CommDriver.vcxproj /p:Configuration=Release /p:Platform=x64 /v:m
if %errorlevel% neq 0 (
    echo [FAIL] CommDriver build failed with error %errorlevel%
) else (
    echo [OK] CommDriver built successfully
)
echo.
echo === Output ===
dir /b "F:\Raid\pythonProject4\hypervisor\CommDriver\build\bin\Release\*.sys" 2>nul
if not exist "F:\Raid\pythonProject4\hypervisor\CommDriver\build\bin\Release\CommDriver.sys" (
    echo [!] CommDriver.sys NOT found
) else (
    echo [OK] CommDriver.sys exists
)
