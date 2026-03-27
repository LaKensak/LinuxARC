@echo off
echo ============================================
echo   ARC RAIDERS - CREATE BOOTABLE USB
echo ============================================
echo.
echo   This will format the selected USB drive!
echo   All data on the drive will be LOST!
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ADMIN REQUIRED - relance en admin
    pause
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"
set "EFI_FILE=%SCRIPT_DIR%target\x86_64-unknown-uefi\release\arc-efi-loader.efi"

if not exist "%EFI_FILE%" (
    echo [!] EFI loader not built! Run build.bat first.
    pause
    exit /b 1
)

echo Available disks:
echo.
wmic diskdrive get Index,Caption,Size /format:list 2>nul
echo.
echo ============================================
echo Type the USB disk number (e.g. 1, 2, 3...)
echo DO NOT select your main system disk (usually 0)!
echo ============================================
set /p DISK_NUM="Disk number: "

if "%DISK_NUM%"=="0" (
    echo [!] Refusing to format disk 0 - this is usually your system disk!
    echo     If you really want disk 0, edit this script.
    pause
    exit /b 1
)

echo.
echo [!] LAST WARNING: This will ERASE ALL DATA on disk %DISK_NUM%!
echo Press Ctrl+C to cancel, or...
pause

:: Create diskpart script
set "DISKPART_SCRIPT=%TEMP%\arc_diskpart.txt"
(
    echo select disk %DISK_NUM%
    echo clean
    echo convert gpt
    echo create partition efi size=512
    echo format fs=fat32 quick label="ARC_EFI"
    echo assign
) > "%DISKPART_SCRIPT%"

echo [*] Formatting USB drive (GPT + FAT32 EFI partition)...
diskpart /s "%DISKPART_SCRIPT%"
del "%DISKPART_SCRIPT%"

if %errorLevel% neq 0 (
    echo [!] Diskpart failed!
    pause
    exit /b 1
)

:: Find the drive letter assigned
echo [*] Looking for ARC_EFI volume...
for /f "tokens=2 delims==" %%a in ('wmic volume where "Label='ARC_EFI'" get DriveLetter /value 2^>nul ^| findstr "="') do set "USB_DRIVE=%%a"

if "%USB_DRIVE%"=="" (
    echo [!] Could not find the USB drive letter.
    echo     Manually copy the EFI file to: USB:\EFI\BOOT\bootx64.efi
    pause
    exit /b 1
)

echo [+] USB drive at %USB_DRIVE%

:: Create EFI boot structure
echo [*] Creating EFI boot structure...
mkdir "%USB_DRIVE%\EFI\BOOT" 2>nul

:: Copy the EFI loader as bootx64.efi (default UEFI boot path)
copy /Y "%EFI_FILE%" "%USB_DRIVE%\EFI\BOOT\bootx64.efi"

echo.
echo ============================================
echo   USB BOOT DRIVE READY
echo ============================================
echo   Drive: %USB_DRIVE%
echo   File:  %USB_DRIVE%\EFI\BOOT\bootx64.efi
echo.
echo   HOW TO USE:
echo   1. Restart your PC
echo   2. Enter BIOS/UEFI (usually F2, F12, or DEL)
echo   3. Disable Secure Boot
echo   4. Boot from the USB drive
echo   5. The loader will start Windows with the driver injected
echo   6. Once Windows is booted, run: python tools\radar_windows.py
echo.
echo   IMPORTANT:
echo   - Secure Boot must be DISABLED
echo   - CSM/Legacy boot must be DISABLED (UEFI only)
echo   - The USB must be plugged in BEFORE you start the PC
echo.
pause
