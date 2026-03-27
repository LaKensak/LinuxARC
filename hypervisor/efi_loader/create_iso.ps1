# Arc Raiders - Create Bootable EFI ISO
# Requires: oscdimg.exe (from Windows ADK) or mkisofs
#
# This creates a bootable ISO that can be written to USB with Rufus
# or mounted in a VM for testing.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EfiFile = Join-Path $ScriptDir "target\x86_64-unknown-uefi\release\arc-efi-loader.efi"
$OutputIso = Join-Path $ScriptDir "arc_efi_boot.iso"
$TempDir = Join-Path $env:TEMP "arc_efi_iso"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ARC RAIDERS - CREATE BOOTABLE ISO" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check EFI file exists
if (-not (Test-Path $EfiFile)) {
    Write-Host "[!] EFI loader not built! Run build.bat first." -ForegroundColor Red
    Write-Host "    Expected: $EfiFile" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Found EFI loader: $EfiFile" -ForegroundColor Green

# Create temp directory structure
Write-Host "[*] Creating ISO structure..."
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path "$TempDir\EFI\BOOT" -Force | Out-Null

# Copy EFI file
Copy-Item $EfiFile "$TempDir\EFI\BOOT\bootx64.efi"
Write-Host "[+] Copied bootx64.efi"

# Try to find oscdimg.exe (Windows ADK)
$OscdImg = $null
$AdkPaths = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe",
    "${env:ProgramFiles}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
)

foreach ($path in $AdkPaths) {
    if (Test-Path $path) {
        $OscdImg = $path
        break
    }
}

if ($OscdImg) {
    Write-Host "[*] Using oscdimg.exe from Windows ADK..."

    # Create a FAT12 EFI boot image (efisys.bin)
    # oscdimg can handle UEFI boot directly
    & $OscdImg -l"ARC_EFI" -o -u2 -udfver102 `
        -bootdata:"1#pEF,e,b$TempDir\EFI\BOOT\bootx64.efi" `
        $TempDir $OutputIso

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] oscdimg failed, trying alternative method..." -ForegroundColor Yellow
        # Alternative: create without boot sector, user must use Rufus
        & $OscdImg -l"ARC_EFI" -o -u2 $TempDir $OutputIso
    }
} else {
    Write-Host "[!] oscdimg.exe not found (install Windows ADK for bootable ISO)" -ForegroundColor Yellow
    Write-Host "[*] Creating directory structure for manual USB creation instead..."

    $ManualDir = Join-Path $ScriptDir "usb_files"
    if (Test-Path $ManualDir) { Remove-Item $ManualDir -Recurse -Force }
    Copy-Item $TempDir $ManualDir -Recurse

    Write-Host ""
    Write-Host "[+] Files prepared in: $ManualDir" -ForegroundColor Green
    Write-Host "    Copy the EFI folder to the root of a FAT32 USB drive."
    Write-Host ""
    Write-Host "    Or install Windows ADK for ISO creation:"
    Write-Host "    https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install"
}

# Cleanup temp
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }

if (Test-Path $OutputIso) {
    $size = (Get-Item $OutputIso).Length / 1MB
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  ISO CREATED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  File: $OutputIso"
    Write-Host "  Size: $([math]::Round($size, 2)) MB"
    Write-Host ""
    Write-Host "  HOW TO USE:"
    Write-Host "  Option A: Write to USB with Rufus (rufus.ie)"
    Write-Host "            - Select GPT + UEFI"
    Write-Host "  Option B: Mount in VM (VMware/VirtualBox)"
    Write-Host "            - Enable EFI firmware in VM settings"
    Write-Host ""
}

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
