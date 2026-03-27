@echo off
call "G:\BuildEnv\SetupBuildEnv.cmd" amd64 >nul 2>&1
cd /d "F:\Raid\pythonProject4\hypervisor\CommDriver"
MSBuild.exe CommDriver.vcxproj /p:Configuration=Release /p:Platform=x64 /v:m > "F:\Raid\pythonProject4\hypervisor\_build_output.txt" 2>&1
echo EXITCODE=%errorlevel% >> "F:\Raid\pythonProject4\hypervisor\_build_output.txt"
dir /b "F:\Raid\pythonProject4\hypervisor\CommDriver\build\bin\Release\*.sys" >> "F:\Raid\pythonProject4\hypervisor\_build_output.txt" 2>&1
