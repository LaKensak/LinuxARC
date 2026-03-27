@echo off
echo ============================================
echo   ARC RAIDERS - EFI LOADER BUILD
echo ============================================
echo.

:: Check Rust nightly toolchain
rustup show active-toolchain 2>nul | findstr "nightly" >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Installing nightly toolchain + UEFI target...
    rustup toolchain install nightly
    rustup component add rust-src --toolchain nightly
)

:: Check UEFI target
rustup target list --installed --toolchain nightly | findstr "x86_64-unknown-uefi" >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Adding x86_64-unknown-uefi target...
    rustup target add x86_64-unknown-uefi --toolchain nightly
)

:: Ensure driver directory and file exist
set "SCRIPT_DIR=%~dp0"
if not exist "%SCRIPT_DIR%driver" mkdir "%SCRIPT_DIR%driver"

set "COMM_SRC=%SCRIPT_DIR%..\CommDriver\build\bin\Release\CommDriver.sys"
set "COMM_DST=%SCRIPT_DIR%driver\CommDriver.sys"

if exist "%COMM_SRC%" (
    copy /Y "%COMM_SRC%" "%COMM_DST%" >nul
    echo [+] CommDriver.sys copied to driver/
) else (
    echo [!] WARNING: CommDriver.sys not found at %COMM_SRC%
    echo     Build CommDriver first, or place CommDriver.sys in:
    echo     %SCRIPT_DIR%driver\CommDriver.sys
    echo.
    if not exist "%COMM_DST%" (
        echo [!] No driver to embed - build will fail!
        pause
        exit /b 1
    )
)

echo.
echo [*] Building EFI loader (release)...
cd /d "%SCRIPT_DIR%"
set "CARGO_HOME=%USERPROFILE%\.cargo"
set "RUSTUP_HOME=%USERPROFILE%\.rustup"
cargo +nightly build --release --target x86_64-unknown-uefi -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem

if %errorLevel% neq 0 (
    echo.
    echo [!] BUILD FAILED
    pause
    exit /b 1
)

set "EFI_OUT=%SCRIPT_DIR%target\x86_64-unknown-uefi\release\arc-efi-loader.efi"
if exist "%EFI_OUT%" (
    echo.
    echo ============================================
    echo   BUILD SUCCESSFUL
    echo ============================================
    echo   Output: %EFI_OUT%
    echo.
    echo   Next steps:
    echo   1. Run create_usb.bat to create a bootable USB
    echo   2. Or run create_iso.ps1 to create a bootable ISO
    echo.
) else (
    echo [!] EFI file not found at expected path
)

pause
