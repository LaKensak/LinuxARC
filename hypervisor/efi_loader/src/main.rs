//! Arc Raiders EFI Loader
//!
//! UEFI pre-boot driver mapper inspired by Valthrun.
//! Hooks the Windows boot chain to inject CommDriver.sys into kernel memory
//! before any anti-cheat or OS security mechanisms are active.
//!
//! Boot flow (Win11 25H2 / Build 26200):
//! 1. UEFI firmware loads this EFI application
//! 2. We locate bootmgfw.efi on the EFI system partition
//! 3. Load and start bootmgfw.efi — it loads winload.efi internally
//! 4. Hook ImgArchStartBootApplication to intercept winload loading
//! 5. Scan winload for BlImgAllocateImageBuffer, OslFwpKernelSetupPhase1
//! 6. At OslFwpKernelSetupPhase1, map our driver + hijack acpiex.sys entry
//! 7. Windows boots normally with our driver already in kernel memory

#![no_main]
#![no_std]

extern crate alloc;

mod hook;
mod mapper;
mod scanner;
mod winload;

use alloc::vec;
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::ptr;
use hook::Trampoline;
use log::{error, info, warn};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode, RegularFile};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::device_path::DevicePath;
use uefi::proto::device_path::build::{self, DevicePathBuilder};
use uefi::proto::BootPolicy;
use uefi::boot::{self, LoadImageSource};

// ── Embedded driver ──
static DRIVER_DATA: &[u8] = include_bytes!("../driver/CommDriver.sys");

// Name of the legitimate driver whose entry point we hijack.
const HIJACK_DRIVER_NAME: &[u8] = b"acpiex.sys";

// ── Global hook state ──
static mut HOOK_IMG_ARCH: Trampoline = Trampoline::empty();
static mut HOOK_BL_ALLOC: Trampoline = Trampoline::empty();
static mut HOOK_OSL_SETUP: Trampoline = Trampoline::empty();

// State tracking
static mut DRIVER_MAPPED: bool = false;
static mut DRIVER_ENTRY: *const u8 = ptr::null();
static mut HIJACK_ORIGINAL_BYTES: [u8; 32] = [0u8; 32];
static mut HOOKS_INSTALLED: bool = false;

// ── UEFI Entry Point ──

#[entry]
fn efi_main() -> Status {
    uefi::helpers::init().unwrap();

    info!("============================================");
    info!("  ARC RAIDERS - EFI LOADER v0.2");
    info!("  Target: Win11 25H2 (Build 26200)");
    info!("============================================");
    info!("");
    info!("Press any key to start boot chain...");
    wait_key();

    // Step 1: Verify embedded driver
    info!("[*] Verifying embedded driver ({} bytes)...", DRIVER_DATA.len());
    unsafe {
        match mapper::parse_driver_pe(DRIVER_DATA) {
            Some(pe_info) => {
                info!(
                    "[+] Driver PE valid: entry_rva={:#X}, image_size={:#X}",
                    pe_info.entry_point_rva, pe_info.size_of_image
                );
            }
            None => {
                error!("[!] Embedded driver is not a valid PE!");
                wait_key();
                return Status::INVALID_PARAMETER;
            }
        }
    }

    // Step 2: Locate and load bootmgfw.efi
    info!("[*] Locating Windows Boot Manager...");

    let bootmgfw_handle = match find_and_load_bootmgfw() {
        Some(handle) => {
            info!("[+] bootmgfw.efi loaded");
            handle
        }
        None => {
            error!("[!] Could not find or load bootmgfw.efi!");
            wait_key();
            return Status::NOT_FOUND;
        }
    };

    // Step 3: Get bootmgfw image info
    let (bootmgfw_base, bootmgfw_size) = {
        let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(bootmgfw_handle)
            .expect("Failed to get LoadedImage protocol");
        let (base, size) = loaded_image.info();
        (base as *const u8, size as usize)
    };

    info!(
        "[*] bootmgfw base: {:#X}, size: {:#X}",
        bootmgfw_base as u64, bootmgfw_size
    );

    // Step 4: Hook ImgArchStartBootApplication in bootmgfw
    info!("[*] Scanning for ImgArchStartBootApplication...");
    unsafe {
        let target = scanner::pattern_scan_multi(
            bootmgfw_base,
            bootmgfw_size,
            &scanner::SIG_IMG_ARCH_START_BOOT_APP,
        );

        match target {
            Some(addr) => {
                info!(
                    "[+] ImgArchStartBootApplication at {:#X} (+{:#X})",
                    addr as u64,
                    addr as u64 - bootmgfw_base as u64
                );
                HOOK_IMG_ARCH.install(addr as *mut u8, hooked_img_arch_start as *const u8);
                info!("[+] Hook installed");
            }
            None => {
                error!("[!] ImgArchStartBootApplication NOT FOUND!");
                error!("    Run pdb_extract.py to update signatures.");
                wait_key();
                return Status::NOT_FOUND;
            }
        }
    }

    // Step 5: Start Windows Boot Manager
    info!("");
    info!("[+] ALL HOOKS READY — starting Windows Boot Manager...");
    info!("[*] If boot fails, reboot without USB to recover.");
    info!("");
    info!("Press any key to boot Windows...");
    wait_key();

    match boot::start_image(bootmgfw_handle) {
        Ok(_) => Status::SUCCESS,
        Err(e) => {
            error!("[!] Boot failed: {:?}", e);
            wait_key();
            e.status()
        }
    }
}

// ── Boot file discovery ──

/// Find bootmgfw.efi on any filesystem and load it.
fn find_and_load_bootmgfw() -> Option<Handle> {
    let handles = boot::find_handles::<SimpleFileSystem>().ok()?;

    for handle in handles {
        let Ok(mut fs) = boot::open_protocol_exclusive::<SimpleFileSystem>(handle) else {
            continue;
        };
        let Ok(mut root) = fs.open_volume() else {
            continue;
        };

        let path = cstr16!("\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
        let Ok(file_handle) = root.open(path, FileMode::Read, FileAttribute::empty()) else {
            continue;
        };

        info!("[+] Found bootmgfw.efi on volume");

        // Build device path: device path of the volume + file path node
        let Ok(dev_path) = boot::open_protocol_exclusive::<DevicePath>(handle) else {
            continue;
        };

        let file_path_str = cstr16!("\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
        let mut buf = vec![MaybeUninit::uninit(); 1024];

        let full_path = {
            let mut builder = DevicePathBuilder::with_buf(&mut buf);
            // Copy existing device path nodes
            for node in dev_path.node_iter() {
                builder = builder.push(&node).ok()?;
            }
            // Add file path node
            builder = builder
                .push(&build::media::FilePath { path_name: file_path_str })
                .ok()?;
            builder.finalize().ok()?
        };

        let my_handle = boot::image_handle();
        match boot::load_image(
            my_handle,
            LoadImageSource::FromDevicePath {
                device_path: full_path,
                boot_policy: BootPolicy::BootSelection,
            },
        ) {
            Ok(h) => return Some(h),
            Err(e) => {
                warn!("[!] Failed to load bootmgfw: {:?}", e);
            }
        }
    }

    None
}

// ── Hook Handlers ──

/// Hook 1: ImgArchStartBootApplication
///
/// Intercepted when bootmgfw launches winload.efi.
/// image_base = freshly loaded winload.efi.
unsafe extern "efiapi" fn hooked_img_arch_start(
    app_entry: *mut u8,
    image_base: *mut u8,
    image_size: u32,
    boot_option: u8,
    return_args: *mut u8,
) -> u64 {
    info!("[HOOK] ImgArchStartBootApplication intercepted!");
    info!(
        "       Image base: {:#X}, size: {:#X}",
        image_base as u64, image_size
    );

    if !HOOKS_INSTALLED {
        install_winload_hooks(image_base as *const u8, image_size as usize);
        HOOKS_INSTALLED = true;
    }

    // Call original
    type FnImgArch = unsafe extern "efiapi" fn(*mut u8, *mut u8, u32, u8, *mut u8) -> u64;
    let original: FnImgArch = core::mem::transmute(HOOK_IMG_ARCH.hook.target);
    HOOK_IMG_ARCH.call_original(|| original(app_entry, image_base, image_size, boot_option, return_args))
}

/// Install all hooks in winload.efi.
unsafe fn install_winload_hooks(base: *const u8, size: usize) {
    info!("[*] Scanning winload for hook targets...");

    // BlpArchSwitchContext
    if let Some(addr) = scanner::pattern_scan_multi(base, size, &scanner::SIG_BLP_ARCH_SWITCH_CONTEXT) {
        info!("[+] BlpArchSwitchContext at {:#X}", addr as u64);
        winload::init(addr);
    } else {
        warn!("[!] BlpArchSwitchContext not found");
    }

    // BlImgAllocateImageBuffer
    if let Some(addr) = scanner::pattern_scan_multi(base, size, &scanner::SIG_BL_IMG_ALLOCATE_IMAGE_BUFFER) {
        info!("[+] BlImgAllocateImageBuffer at {:#X}", addr as u64);
        HOOK_BL_ALLOC.install(addr as *mut u8, hooked_bl_alloc as *const u8);
    } else {
        warn!("[!] BlImgAllocateImageBuffer not found");
    }

    // OslFwpKernelSetupPhase1 — this is where injection happens
    if let Some(addr) = scanner::pattern_scan_multi(base, size, &scanner::SIG_OSL_FWP_KERNEL_SETUP_PHASE1) {
        info!("[+] OslFwpKernelSetupPhase1 at {:#X}", addr as u64);
        HOOK_OSL_SETUP.install(addr as *mut u8, hooked_osl_setup as *const u8);
    } else {
        error!("[!] OslFwpKernelSetupPhase1 NOT FOUND — injection will fail!");
    }

    info!("[*] Winload hooks installed");
    info!("[*] Press any key to continue winload execution...");
    wait_key();
}

/// Hook 2: BlImgAllocateImageBuffer
unsafe extern "efiapi" fn hooked_bl_alloc(
    image_buffer: *mut *mut u8,
    memory_type: u32,
    image_size: u64,
    flags: u32,
) -> u64 {
    type FnBlAlloc = unsafe extern "efiapi" fn(*mut *mut u8, u32, u64, u32) -> u64;
    let original: FnBlAlloc = core::mem::transmute(HOOK_BL_ALLOC.hook.target);
    let status = HOOK_BL_ALLOC.call_original(|| original(image_buffer, memory_type, image_size, flags));

    if status == 0 && !DRIVER_MAPPED && (memory_type == 0xE0000012 || memory_type == 0xE0000014) {
        if let Some(pe_info) = mapper::parse_driver_pe(DRIVER_DATA) {
            if image_size >= pe_info.size_of_image as u64 {
                info!(
                    "[HOOK] Driver alloc: type={:#X} size={:#X} buf={:#X}",
                    memory_type, image_size, (*image_buffer) as u64
                );
            }
        }
    }

    status
}

/// Hook 3: OslFwpKernelSetupPhase1
///
/// Final injection point. All boot drivers are loaded.
/// We find acpiex.sys and hijack its entry point.
unsafe extern "efiapi" fn hooked_osl_setup(loader_block: *mut u8) -> u64 {
    info!("[HOOK] OslFwpKernelSetupPhase1 — injection phase!");
    info!("       loader_block = {:#X}", loader_block as u64);

    // Dump first few entries from LoadOrderListHead for diagnostics
    dump_loader_entries(loader_block);

    if !DRIVER_MAPPED {
        // First, find ntoskrnl.exe for import resolution
        let ntoskrnl_base = find_loaded_driver(loader_block, b"ntoskrnl.exe")
            .map(|(base, _, _)| base);

        if ntoskrnl_base.is_none() {
            error!("[!] ntoskrnl.exe not found in loader block!");
        } else {
            info!("[+] ntoskrnl.exe base = {:#X}", ntoskrnl_base.unwrap() as u64);
        }

        if let Some((dll_base, entry_point, image_size)) =
            find_loaded_driver(loader_block, HIJACK_DRIVER_NAME)
        {
            info!(
                "[+] {} : base={:#X} entry={:#X} size={:#X}",
                core::str::from_utf8_unchecked(HIJACK_DRIVER_NAME),
                dll_base as u64,
                entry_point as u64,
                image_size
            );

            match mapper::map_driver(DRIVER_DATA, dll_base as *mut u8, image_size) {
                Some(our_entry) => {
                    DRIVER_ENTRY = our_entry;
                    info!("[+] Driver mapped at {:#X}", our_entry as u64);

                    // Resolve imports — find modules by walking loader block
                    let resolve_ok = mapper::resolve_imports(
                        dll_base as *mut u8,
                        &|dll_name| {
                            // Try ntoskrnl first (most imports come from there)
                            if mapper::dll_name_matches(dll_name, b"ntoskrnl")
                                || mapper::dll_name_matches(dll_name, b"ntoskrnl.exe")
                                || mapper::dll_name_matches(dll_name, b"NTOSKRNL")
                            {
                                return ntoskrnl_base;
                            }
                            // HAL
                            if mapper::dll_name_matches(dll_name, b"hal")
                                || mapper::dll_name_matches(dll_name, b"hal.dll")
                                || mapper::dll_name_matches(dll_name, b"HAL")
                            {
                                return find_loaded_driver(loader_block, b"hal.dll")
                                    .map(|(base, _, _)| base);
                            }
                            // ntifs/ntddk imports also come from ntoskrnl
                            ntoskrnl_base
                        },
                    );

                    if !resolve_ok {
                        error!("[!] Some imports could not be resolved!");
                    } else {
                        info!("[+] All imports resolved");
                    }

                    mapper::hijack_entry_point(
                        entry_point as *mut u8,
                        our_entry,
                        HIJACK_ORIGINAL_BYTES.as_mut_ptr(),
                        32,
                    );

                    DRIVER_MAPPED = true;
                    info!("[+] INJECTION COMPLETE — acpiex.sys entry hijacked!");
                    info!("[+] Driver will start when Windows loads acpiex.sys");
                    info!("    Press any key to continue boot...");
                    // Note: wait_key may not work here (post-ExitBootServices)
                    // but the info! messages should still be visible briefly
                }
                None => {
                    error!("[!] Failed to map driver!");
                }
            }
        } else {
            error!("[!] {} not found in loaded modules!",
                core::str::from_utf8_unchecked(HIJACK_DRIVER_NAME));
        }
    }

    type FnOslSetup = unsafe extern "efiapi" fn(*mut u8) -> u64;
    let original: FnOslSetup = core::mem::transmute(HOOK_OSL_SETUP.hook.target);
    HOOK_OSL_SETUP.call_original(|| original(loader_block))
}

// ── Diagnostic dump ──

/// Dump the first entries from both list heads for debugging.
unsafe fn dump_loader_entries(loader_block: *mut u8) {
    if loader_block.is_null() {
        return;
    }

    // Try both LoadOrderListHead (0x10) and BootDriverListHead (0x30)
    for &(list_offset, list_name) in &[
        (0x10usize, "LoadOrderList(0x10)"),
        (0x30usize, "BootDriverList(0x30)"),
    ] {
        info!("[DUMP] Walking {} ...", list_name);
        let list_head = loader_block.add(list_offset) as *const ListEntry;
        let mut entry = (*list_head).flink;
        let mut count = 0u32;

        while entry != list_head as *mut ListEntry && count < 8 {
            if entry.is_null() {
                break;
            }

            let ldr = entry as *const u8;
            // Read BaseDllName at the expected KLDR_DATA_TABLE_ENTRY offset
            let name_len = *(ldr.add(0x58) as *const u16) as usize;
            let name_buf = *(ldr.add(0x60) as *const *const u16);
            let dll_base_val = *(ldr.add(0x30) as *const u64);

            if !name_buf.is_null() && name_len > 0 && name_len < 520 {
                let char_count = core::cmp::min(name_len / 2, 32);
                let mut name_ascii = [0u8; 32];
                for i in 0..char_count {
                    name_ascii[i] = (*name_buf.add(i) & 0x7F) as u8;
                }
                if let Ok(s) = core::str::from_utf8(&name_ascii[..char_count]) {
                    info!("  [{}] '{}' base={:#X}", count, s, dll_base_val);
                }
            } else {
                info!("  [{}] <unreadable name> name_len={} buf={:#X} base_val={:#X}",
                    count, name_len, name_buf as u64, dll_base_val);
            }

            count += 1;
            entry = (*entry).flink;
        }

        if count == 0 {
            info!("  (empty or invalid list)");
        }
    }
}

// ── Loader Parameter Block traversal ──

/// Walk LOADER_PARAMETER_BLOCK -> LoadOrderListHead to find a driver by name.
///
/// LOADER_PARAMETER_BLOCK layout (x64, Win11 25H2):
///   +0x10  LoadOrderListHead   (KLDR_DATA_TABLE_ENTRY via InLoadOrderLinks)
///   +0x20  MemoryDescriptorListHead
///   +0x30  BootDriverListHead  (BOOT_DRIVER_LIST_ENTRY — different struct!)
///
/// We walk LoadOrderListHead (0x10). Entries are KLDR_DATA_TABLE_ENTRY:
///   +0x00  InLoadOrderLinks (LIST_ENTRY)
///   +0x30  DllBase
///   +0x38  EntryPoint
///   +0x40  SizeOfImage
///   +0x58  BaseDllName (UNICODE_STRING)
unsafe fn find_loaded_driver(
    loader_block: *mut u8,
    name: &[u8],
) -> Option<(*const u8, *const u8, usize)> {
    if loader_block.is_null() {
        return None;
    }

    // Try LoadOrderListHead (0x10) first, then BootDriverListHead (0x30) as fallback
    let offsets_to_try: [usize; 2] = [0x10, 0x30];

    for &list_offset in &offsets_to_try {
        let list_head = loader_block.add(list_offset) as *const ListEntry;
        let mut entry = (*list_head).flink;
        let mut count = 0u32;

        while entry != list_head as *mut ListEntry {
            if entry.is_null() || count > 512 {
                break;
            }
            count += 1;

            let ldr = entry as *const u8;
            let dll_base = *(ldr.add(0x30) as *const *const u8);
            let entry_point = *(ldr.add(0x38) as *const *const u8);
            let size_of_image = *(ldr.add(0x40) as *const u32) as usize;

            let name_len = *(ldr.add(0x58) as *const u16) as usize;
            let name_buf = *(ldr.add(0x58 + 8) as *const *const u16);

            if !name_buf.is_null() && name_len > 0 && name_len < 520 {
                let char_count = name_len / 2;
                if char_count == name.len() {
                    let mut matches = true;
                    for i in 0..char_count {
                        let wc = *name_buf.add(i) as u8;
                        let tc = name[i];
                        if wc.to_ascii_lowercase() != tc.to_ascii_lowercase() {
                            matches = false;
                            break;
                        }
                    }
                    if matches {
                        info!(
                            "[+] Found '{}' via list offset {:#X}: base={:#X} entry={:#X} size={:#X}",
                            core::str::from_utf8_unchecked(name),
                            list_offset,
                            dll_base as u64,
                            entry_point as u64,
                            size_of_image
                        );
                        return Some((dll_base, entry_point, size_of_image));
                    }
                }
            }

            entry = (*entry).flink;
        }
    }

    None
}

#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

/// Wait for a keypress.
fn wait_key() {
    info!("Press any key to continue...");
    uefi::system::with_stdin(|stdin| {
        loop {
            if let Ok(Some(_)) = stdin.read_key() {
                break;
            }
        }
    });
}
