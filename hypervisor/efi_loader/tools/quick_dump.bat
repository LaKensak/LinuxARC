@echo off
echo ============================================
echo   QUICK SIGNATURE DUMP - Win11 25H2
echo ============================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ADMIN REQUIRED
    pause
    exit /b 1
)

set "WORK=%TEMP%\arc_sig_dump"
mkdir "%WORK%" 2>nul

echo [*] Mounting EFI partition...
mountvol Z: /s 2>nul

echo [*] Copying boot files...
if exist "Z:\EFI\Microsoft\Boot\bootmgfw.efi" (
    copy /Y "Z:\EFI\Microsoft\Boot\bootmgfw.efi" "%WORK%\bootmgfw.efi" >nul
    echo [+] bootmgfw.efi copied
) else (
    echo [!] bootmgfw.efi not found on EFI partition
)

if exist "%SystemRoot%\System32\winload.efi" (
    copy /Y "%SystemRoot%\System32\winload.efi" "%WORK%\winload.efi" >nul
    echo [+] winload.efi copied
)

mountvol Z: /d 2>nul

echo.
echo [*] Running signature extractor...
python "%~dp0dump_signatures.py"

echo.
echo [*] Boot files saved in: %WORK%
echo     You can also analyze them manually with:
echo     - IDA Pro / Ghidra
echo     - WinDbg: .reload /f bootmgfw.efi; x bootmgfw!ImgArch*
echo.
pause
