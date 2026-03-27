@echo off
set "LOGFILE=F:\Raid\pythonProject4\hypervisor\_build_log.txt"
echo BUILD START > "%LOGFILE%"

call "G:\BuildEnv\SetupBuildEnv.cmd" amd64 >> "%LOGFILE%" 2>&1

echo MSBuild location: >> "%LOGFILE%"
where MSBuild.exe >> "%LOGFILE%" 2>&1

echo. >> "%LOGFILE%"
echo === Compiling CommDriver === >> "%LOGFILE%"
cd /d "F:\Raid\pythonProject4\hypervisor\CommDriver"
MSBuild.exe CommDriver.vcxproj /p:Configuration=Release /p:Platform=x64 /v:n >> "%LOGFILE%" 2>&1
echo EXIT_CODE=%errorlevel% >> "%LOGFILE%"

echo. >> "%LOGFILE%"
echo === Output files === >> "%LOGFILE%"
dir "F:\Raid\pythonProject4\hypervisor\CommDriver\build\bin\Release\*.*" >> "%LOGFILE%" 2>&1

echo BUILD DONE >> "%LOGFILE%"
