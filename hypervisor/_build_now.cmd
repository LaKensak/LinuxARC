@echo off
call G:\BuildEnv\SetupBuildEnv.cmd amd64

cd /d "F:\Raid\pythonProject4\hypervisor\CommDriver"
MSBuild.exe CommDriver.vcxproj /p:Configuration=Release /p:Platform=x64 /v:n
echo EXIT_CODE=%errorlevel%
