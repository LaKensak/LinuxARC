"""
Arc Raiders EFI Loader - Signature Dumper for Windows Boot Files

Downloads PDB symbols from Microsoft Symbol Server for bootmgfw.efi
and winload.efi, then extracts the byte patterns needed for the EFI loader.

Usage (run as admin):
    python dump_signatures.py

Output: updated signature patterns for scanner.rs
"""

import os
import sys
import struct
import shutil
import hashlib
import subprocess
import ctypes
import urllib.request
import tempfile
from pathlib import Path

# Functions we need to find
TARGET_FUNCTIONS = {
    "bootmgfw.efi": [
        "ImgArchStartBootApplication",
    ],
    "winload.efi": [
        "BlImgAllocateImageBuffer",
        "OslFwpKernelSetupPhase1",
        "OslExecuteTransition",
        "BlpArchSwitchContext",
    ],
}

SIGNATURE_LENGTH = 24  # bytes to extract per function
SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def mount_efi_partition():
    """Mount the EFI System Partition to a drive letter."""
    # Try common letters
    for letter in "ZYXWVU":
        drive = f"{letter}:"
        # Check if letter is free
        if not os.path.exists(drive + "\\"):
            print(f"[*] Mounting EFI partition to {drive}")
            ret = subprocess.run(
                ["mountvol", drive, "/s"],
                capture_output=True, text=True
            )
            if ret.returncode == 0:
                return drive
            # Try with diskpart as fallback

    # Fallback: use mountvol
    print("[!] Could not mount EFI partition automatically")
    print("    Run: mountvol S: /s")
    return None


def unmount_efi(drive_letter):
    """Unmount the EFI partition."""
    subprocess.run(["mountvol", drive_letter, "/d"], capture_output=True)


def find_boot_files(efi_drive):
    """Locate bootmgfw.efi and winload.efi."""
    files = {}

    # bootmgfw.efi is on the EFI partition
    bootmgfw = os.path.join(efi_drive, "EFI", "Microsoft", "Boot", "bootmgfw.efi")
    if os.path.exists(bootmgfw):
        files["bootmgfw.efi"] = bootmgfw
        print(f"[+] Found bootmgfw.efi: {bootmgfw}")

    # winload.efi is in System32
    winload = os.path.join(os.environ["SystemRoot"], "System32", "winload.efi")
    if os.path.exists(winload):
        files["winload.efi"] = winload
        print(f"[+] Found winload.efi: {winload}")

    return files


def get_pe_debug_info(filepath):
    """Extract PDB GUID and age from PE debug directory."""
    with open(filepath, "rb") as f:
        data = f.read()

    # Parse DOS header
    if data[:2] != b"MZ":
        return None

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

    # Parse NT headers
    if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        return None

    # COFF header
    coff_offset = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
    opt_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]

    # Optional header
    opt_offset = coff_offset + 20
    magic = struct.unpack_from("<H", data, opt_offset)[0]

    if magic == 0x20B:  # PE32+
        num_rva_sizes = struct.unpack_from("<I", data, opt_offset + 108)[0]
        data_dir_offset = opt_offset + 112
    else:  # PE32
        num_rva_sizes = struct.unpack_from("<I", data, opt_offset + 92)[0]
        data_dir_offset = opt_offset + 96

    if num_rva_sizes < 7:
        return None

    # Debug directory (index 6)
    debug_rva = struct.unpack_from("<I", data, data_dir_offset + 6 * 8)[0]
    debug_size = struct.unpack_from("<I", data, data_dir_offset + 6 * 8 + 4)[0]

    if debug_rva == 0 or debug_size == 0:
        return None

    # Convert RVA to file offset
    sections_offset = opt_offset + opt_header_size
    debug_file_offset = None

    for i in range(num_sections):
        sec_offset = sections_offset + i * 40
        sec_va = struct.unpack_from("<I", data, sec_offset + 12)[0]
        sec_size = struct.unpack_from("<I", data, sec_offset + 8)[0]
        sec_raw = struct.unpack_from("<I", data, sec_offset + 20)[0]

        if sec_va <= debug_rva < sec_va + sec_size:
            debug_file_offset = sec_raw + (debug_rva - sec_va)
            break

    if debug_file_offset is None:
        return None

    # Parse IMAGE_DEBUG_DIRECTORY entries
    num_entries = debug_size // 28
    for i in range(num_entries):
        entry_offset = debug_file_offset + i * 28
        debug_type = struct.unpack_from("<I", data, entry_offset + 12)[0]

        if debug_type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            raw_data_offset = struct.unpack_from("<I", data, entry_offset + 24)[0]

            # CV_INFO_PDB70
            sig = data[raw_data_offset:raw_data_offset+4]
            if sig == b"RSDS":
                guid_bytes = data[raw_data_offset+4:raw_data_offset+20]
                age = struct.unpack_from("<I", data, raw_data_offset + 20)[0]
                pdb_name = data[raw_data_offset+24:].split(b"\x00")[0].decode("ascii")

                # Format GUID
                d1, d2, d3 = struct.unpack_from("<IHH", guid_bytes, 0)
                d4 = guid_bytes[8:16]
                guid_str = f"{d1:08X}{d2:04X}{d3:04X}" + d4.hex().upper()

                return {
                    "pdb_name": os.path.basename(pdb_name),
                    "guid": guid_str,
                    "age": age,
                }

    return None


def download_pdb(pdb_info, output_dir):
    """Download PDB from Microsoft Symbol Server."""
    pdb_name = pdb_info["pdb_name"]
    guid = pdb_info["guid"]
    age = pdb_info["age"]

    # Symbol server path format: <pdb_name>/<GUID><age>/<pdb_name>
    url = f"{SYMBOL_SERVER}/{pdb_name}/{guid}{age:X}/{pdb_name}"
    output_path = os.path.join(output_dir, pdb_name)

    print(f"[*] Downloading {pdb_name}...")
    print(f"    URL: {url}")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Microsoft-Symbol-Server/10.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            with open(output_path, "wb") as f:
                f.write(resp.read())
        print(f"[+] Downloaded: {output_path}")
        return output_path
    except Exception as e:
        # Try compressed version (_)
        url_compressed = f"{SYMBOL_SERVER}/{pdb_name}/{guid}{age:X}/{pdb_name[:-1]}_"
        try:
            req = urllib.request.Request(url_compressed, headers={"User-Agent": "Microsoft-Symbol-Server/10.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                compressed_path = output_path + "_"
                with open(compressed_path, "wb") as f:
                    f.write(resp.read())
                # Decompress with expand.exe
                subprocess.run(["expand", compressed_path, output_path], capture_output=True)
                os.remove(compressed_path)
                print(f"[+] Downloaded and decompressed: {output_path}")
                return output_path
        except Exception as e2:
            print(f"[!] Failed to download PDB: {e2}")
            return None


def get_function_offset_from_pdb(pdb_path, function_name):
    """
    Get function RVA from PDB using dbh.exe or pdbparse.
    Falls back to string search in the binary if PDB tools unavailable.
    """
    # Try using dbh.exe (from Debugging Tools for Windows)
    dbh_paths = [
        os.path.join(os.environ.get("ProgramFiles", ""), "Windows Kits", "10", "Debuggers", "x64", "dbh.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Windows Kits", "10", "Debuggers", "x64", "dbh.exe"),
    ]

    dbh = None
    for p in dbh_paths:
        if os.path.exists(p):
            dbh = p
            break

    if dbh:
        try:
            result = subprocess.run(
                [dbh, "-d", pdb_path, "addr", function_name],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if "addr" in line.lower():
                    parts = line.strip().split()
                    for part in parts:
                        try:
                            return int(part, 16)
                        except ValueError:
                            continue
        except Exception:
            pass

    # Try symchk / dumpbin
    dumpbin = shutil.which("dumpbin")
    if dumpbin:
        try:
            result = subprocess.run(
                [dumpbin, "/symbols", pdb_path],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.splitlines():
                if function_name in line:
                    parts = line.strip().split()
                    for part in parts:
                        try:
                            return int(part, 16)
                        except ValueError:
                            continue
        except Exception:
            pass

    return None


def extract_bytes_at_rva(filepath, rva, count):
    """Read `count` bytes at the given RVA from a PE file."""
    with open(filepath, "rb") as f:
        data = f.read()

    # Parse sections to convert RVA to file offset
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff_offset = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
    opt_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    sections_offset = coff_offset + 20 + opt_header_size

    for i in range(num_sections):
        sec_offset = sections_offset + i * 40
        sec_va = struct.unpack_from("<I", data, sec_offset + 12)[0]
        sec_vsize = struct.unpack_from("<I", data, sec_offset + 8)[0]
        sec_raw = struct.unpack_from("<I", data, sec_offset + 20)[0]
        sec_rawsize = struct.unpack_from("<I", data, sec_offset + 16)[0]

        if sec_va <= rva < sec_va + sec_vsize:
            file_offset = sec_raw + (rva - sec_va)
            if file_offset + count <= len(data):
                return data[file_offset:file_offset + count]

    return None


def format_rust_pattern(name, byte_data):
    """Format bytes as Rust array literal for scanner.rs."""
    hex_bytes = ", ".join(f"0x{b:02X}" for b in byte_data)
    return f"        // Win11 25H2\n        &[{hex_bytes}],"


def scan_for_known_patterns(filepath, pe_data=None):
    """
    Fallback: scan the binary for known instruction prologues
    that are characteristic of our target functions.
    """
    with open(filepath, "rb") as f:
        data = f.read()

    results = {}
    basename = os.path.basename(filepath).lower()

    if "bootmgfw" in basename:
        # ImgArchStartBootApplication typically starts with:
        # mov rax, rsp / mov [rsp+xx], rbx / ...
        # 48 8B C4 48 89 58 20 is very common
        pattern = bytes([0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x20])
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            # Extract more bytes for a full signature
            candidate = data[idx:idx + SIGNATURE_LENGTH]
            if len(candidate) == SIGNATURE_LENGTH:
                results.setdefault("ImgArchStartBootApplication", []).append(
                    (idx, candidate)
                )
            offset = idx + 1

    if "winload" in basename:
        # BlImgAllocateImageBuffer: called via CALL rel32, look for typical prologue
        # sub rsp, XX / mov [rsp+..], ...
        # OslFwpKernelSetupPhase1: mov [rsp+8], rbx / mov [rsp+10h], rsi / push rdi
        pattern = bytes([0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57])
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            candidate = data[idx:idx + SIGNATURE_LENGTH]
            if len(candidate) == SIGNATURE_LENGTH:
                results.setdefault("OslFwpKernelSetupPhase1_candidates", []).append(
                    (idx, candidate)
                )
            offset = idx + 1

        # BlpArchSwitchContext: push rbx / sub rsp, 20h / lea rax, [rip+...]
        pattern = bytes([0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8D, 0x05])
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            candidate = data[idx:idx + SIGNATURE_LENGTH]
            if len(candidate) == SIGNATURE_LENGTH:
                results.setdefault("BlpArchSwitchContext_candidates", []).append(
                    (idx, candidate)
                )
            offset = idx + 1

    return results


def main():
    print("============================================")
    print("  ARC RAIDERS - BOOT SIGNATURE DUMPER")
    print("  Target: Windows 11 25H2")
    print("============================================")
    print()

    # Get Windows version
    ver = sys.getwindowsversion()
    print(f"[*] Windows version: {ver.major}.{ver.minor}.{ver.build}")
    print()

    # Allow specifying EFI drive via command line or use D: as default
    efi_drive = sys.argv[1] if len(sys.argv) > 1 else "D:"
    print(f"[*] Using EFI drive: {efi_drive}")

    if not os.path.exists(efi_drive + "\\"):
        print(f"[!] Drive {efi_drive} not accessible")
        if not is_admin():
            print("    Trying to mount EFI partition (needs admin)...")
            efi_drive = mount_efi_partition()
        else:
            efi_drive = mount_efi_partition()

    # Find boot files
    boot_files = {}
    if efi_drive:
        boot_files = find_boot_files(efi_drive)

    # winload.efi fallback
    if "winload.efi" not in boot_files:
        winload_sys32 = os.path.join(os.environ["SystemRoot"], "System32", "winload.efi")
        if os.path.exists(winload_sys32):
            boot_files["winload.efi"] = winload_sys32
            print(f"[+] Found winload.efi: {winload_sys32}")

    if not boot_files:
        print("[!] No boot files found!")
        if efi_drive:
            unmount_efi(efi_drive)
        print("Done.")
        sys.exit(1)

    # Use project directory for temp files (avoid disk space issues on C:)
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_dump_temp")
    os.makedirs(temp_dir, exist_ok=True)
    print(f"[*] Work directory: {temp_dir}")
    print()

    all_signatures = {}

    for boot_file_name, boot_file_path in boot_files.items():
        print(f"{'='*50}")
        print(f"  Analyzing: {boot_file_name}")
        print(f"{'='*50}")

        # Copy to temp (in case of permission issues)
        temp_copy = os.path.join(temp_dir, boot_file_name)
        shutil.copy2(boot_file_path, temp_copy)

        # Get PDB info
        pdb_info = get_pe_debug_info(temp_copy)
        if pdb_info:
            print(f"[+] PDB: {pdb_info['pdb_name']}")
            print(f"    GUID: {pdb_info['guid']}")
            print(f"    Age: {pdb_info['age']}")

            # Download PDB
            pdb_path = download_pdb(pdb_info, temp_dir)

            if pdb_path:
                # Extract function offsets from PDB
                functions = TARGET_FUNCTIONS.get(boot_file_name, [])
                for func_name in functions:
                    print(f"\n[*] Looking for {func_name}...")
                    rva = get_function_offset_from_pdb(pdb_path, func_name)

                    if rva:
                        print(f"[+] {func_name} RVA: {rva:#X}")
                        sig_bytes = extract_bytes_at_rva(temp_copy, rva, SIGNATURE_LENGTH)
                        if sig_bytes:
                            all_signatures[func_name] = sig_bytes
                            hex_str = " ".join(f"{b:02X}" for b in sig_bytes)
                            print(f"[+] Signature: {hex_str}")
                        else:
                            print(f"[!] Could not read bytes at RVA {rva:#X}")
                    else:
                        print(f"[!] {func_name} not found in PDB")
                        print(f"    Trying pattern scan fallback...")
        else:
            print(f"[!] No debug info in {boot_file_name}")

        # Fallback: pattern scan
        if boot_file_name == "bootmgfw.efi" and "ImgArchStartBootApplication" not in all_signatures:
            print(f"\n[*] Fallback pattern scan for {boot_file_name}...")
            candidates = scan_for_known_patterns(temp_copy)
            for name, hits in candidates.items():
                print(f"    {name}: {len(hits)} candidates found")
                if hits:
                    # Take the first match
                    offset, sig_bytes = hits[0]
                    all_signatures[name.replace("_candidates", "")] = sig_bytes
                    hex_str = " ".join(f"{b:02X}" for b in sig_bytes)
                    print(f"    -> Best match at offset {offset:#X}: {hex_str}")

        if boot_file_name == "winload.efi":
            for func in TARGET_FUNCTIONS["winload.efi"]:
                if func not in all_signatures:
                    print(f"\n[*] Fallback pattern scan for {func}...")
                    candidates = scan_for_known_patterns(temp_copy)
                    for name, hits in candidates.items():
                        clean_name = name.replace("_candidates", "")
                        if clean_name not in all_signatures and hits:
                            offset, sig_bytes = hits[0]
                            all_signatures[clean_name] = sig_bytes
                            hex_str = " ".join(f"{b:02X}" for b in sig_bytes)
                            print(f"    -> {clean_name} at offset {offset:#X}: {hex_str}")

    # Unmount EFI
    if efi_drive:
        unmount_efi(efi_drive)

    # Output results
    print()
    print("=" * 60)
    print("  RESULTS - Paste these into scanner.rs")
    print("=" * 60)
    print()

    if not all_signatures:
        print("[!] No signatures found!")
        print("    You may need to install Debugging Tools for Windows (WinDbg)")
        print("    from the Windows SDK to enable PDB symbol parsing.")
        print()
        print("    Alternative: use WinDbg to find the functions manually:")
        print("    1. Open bootmgfw.efi in WinDbg")
        print("    2. Run: x bootmgfw!ImgArchStartBootApplication")
        print("    3. Run: db <address> L18")
        print("    4. Copy the byte pattern into scanner.rs")
    else:
        output_lines = []
        for func_name, sig_bytes in all_signatures.items():
            rust_line = format_rust_pattern(func_name, sig_bytes)
            output_lines.append(f"// {func_name}:")
            output_lines.append(rust_line)
            output_lines.append("")

        result_text = "\n".join(output_lines)
        print(result_text)

        # Save to file
        output_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "signatures_25h2.txt"
        )
        with open(output_file, "w") as f:
            f.write(f"// Windows 11 25H2 (Build {ver.build})\n")
            f.write(f"// Generated by dump_signatures.py\n\n")
            f.write(result_text)

        print(f"\n[+] Saved to: {output_file}")

    # Cleanup
    print(f"\n[*] Temp files in: {temp_dir}")
    print("    (delete manually when done)")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
