@echo off
setlocal

set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
set "MAKECERT=C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\x64\makecert.exe"
set "CERTMGR=C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\x64\certmgr.exe"
set "OPHION=F:\Raid\pythonProject4\hypervisor\Ophion\build\bin\Release\Ophion.sys"
set "COMM=F:\Raid\pythonProject4\hypervisor\CommDriver\build\bin\Release\CommDriver.sys"

echo === Creating test certificate ===

:: Create self-signed test cert
"%MAKECERT%" -r -pe -ss PrivateCertStore -n "CN=ArcRadar Test" "F:\Raid\pythonProject4\hypervisor\ArcRadar.cer"
if %errorlevel% neq 0 (
    echo [!] makecert failed, trying New-SelfSignedCertificate...
    powershell -Command "New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=ArcRadar Test' -CertStoreLocation 'Cert:\CurrentUser\My' -TestRoot"
)

:: Sign Ophion.sys
echo.
echo === Signing Ophion.sys ===
"%SIGNTOOL%" sign /a /v /s PrivateCertStore /n "ArcRadar Test" /t http://timestamp.digicert.com "%OPHION%"
if %errorlevel% neq 0 (
    echo Trying alternate sign method...
    "%SIGNTOOL%" sign /a /v /fd sha256 /s PrivateCertStore /n "ArcRadar Test" "%OPHION%"
)
if %errorlevel% neq 0 (
    echo Trying with My store...
    "%SIGNTOOL%" sign /a /v /fd sha256 /s My /n "ArcRadar Test" "%OPHION%"
)

:: Sign CommDriver.sys
echo.
echo === Signing CommDriver.sys ===
"%SIGNTOOL%" sign /a /v /s PrivateCertStore /n "ArcRadar Test" /t http://timestamp.digicert.com "%COMM%"
if %errorlevel% neq 0 (
    "%SIGNTOOL%" sign /a /v /fd sha256 /s PrivateCertStore /n "ArcRadar Test" "%COMM%"
)
if %errorlevel% neq 0 (
    "%SIGNTOOL%" sign /a /v /fd sha256 /s My /n "ArcRadar Test" "%COMM%"
)

echo.
echo === Verifying signatures ===
"%SIGNTOOL%" verify /v /pa "%OPHION%"
"%SIGNTOOL%" verify /v /pa "%COMM%"

echo.
echo Done!
pause
