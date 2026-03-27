/// Pattern scanner for locating functions in bootmgfw.efi / winload.efi
/// Supports wildcard bytes (0xFF = wildcard) in signature patterns.

#[derive(Clone, Copy, Debug)]
pub enum ResolveType {
    /// Raw address where pattern was found + offset
    Pattern(isize),
    /// Resolve RIP-relative address (for CALL/JMP instructions)
    /// offset = offset to the rel32 from pattern start, extra = additional offset after resolve
    RelativeAddress { offset: isize, extra: isize },
}

#[derive(Clone)]
pub struct Signature {
    pub name: &'static str,
    pub patterns: &'static [&'static [u8]],
    pub mask: &'static [u8], // 0xFF = wildcard, 0x00 = exact match
    pub resolve: ResolveType,
}

/// Scan a memory region for a byte pattern with mask.
/// mask[i] == 0xFF means wildcard (any byte), 0x00 means exact match.
pub unsafe fn pattern_scan(base: *const u8, size: usize, pattern: &[u8], mask: &[u8]) -> Option<*const u8> {
    if pattern.len() != mask.len() || pattern.is_empty() || size < pattern.len() {
        return None;
    }

    let end = size - pattern.len();
    for i in 0..=end {
        let mut found = true;
        for j in 0..pattern.len() {
            if mask[j] != 0xFF && *base.add(i + j) != pattern[j] {
                found = false;
                break;
            }
        }
        if found {
            return Some(base.add(i));
        }
    }
    None
}

/// Scan with multiple pattern variants (for different Windows versions).
/// Returns the first match found.
pub unsafe fn pattern_scan_multi(
    base: *const u8,
    size: usize,
    sig: &Signature,
) -> Option<*const u8> {
    for pattern in sig.patterns {
        if let Some(addr) = pattern_scan(base, size, pattern, sig.mask) {
            return Some(resolve_address(addr, &sig.resolve));
        }
    }
    None
}

/// Resolve the final address based on the resolve type.
unsafe fn resolve_address(found: *const u8, resolve: &ResolveType) -> *const u8 {
    match *resolve {
        ResolveType::Pattern(offset) => found.offset(offset),
        ResolveType::RelativeAddress { offset, extra } => {
            let rip = found.offset(offset);
            let rel = *(rip as *const i32);
            // RIP-relative: target = rip + 4 + rel32 + extra
            rip.offset(4).offset(rel as isize).offset(extra)
        }
    }
}

// ── Boot chain signatures ──
// Extracted from Win11 25H2 (Build 26200) via PDB symbols.
// Re-run tools/pdb_extract.py after Windows updates to refresh.

/// ImgArchStartBootApplication in bootmgfw.efi
/// Called when bootmgfw launches winload.efi
/// RVA: 0x1C52BC (Build 26200)
pub static SIG_IMG_ARCH_START_BOOT_APP: Signature = Signature {
    name: "ImgArchStartBootApplication",
    patterns: &[
        // Win11 25H2 (Build 26200) — mov rax,rsp / mov [rsp+20h],rbx / mov [rax+18h],r8d / .../ push rbp / push rsi / push rdi / push r12
        &[0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x20, 0x44, 0x89, 0x40, 0x18, 0x48, 0x89, 0x50, 0x10, 0x48, 0x89, 0x48, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54],
    ],
    mask: &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    resolve: ResolveType::Pattern(0),
};

/// BlImgAllocateImageBuffer in winload.efi
/// Intercepts driver memory allocation to inject our driver
/// RVA: 0x192878 (Build 26200)
pub static SIG_BL_IMG_ALLOCATE_IMAGE_BUFFER: Signature = Signature {
    name: "BlImgAllocateImageBuffer",
    patterns: &[
        // Win11 25H2 (Build 26200) — mov [rsp+18h],rbx / push rbp / push rsi / push rdi / push r12 / push r13 / push r14 / push r15 / mov rbp,rsp / sub rsp,50h
        &[0x48, 0x89, 0x5C, 0x24, 0x18, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x50],
    ],
    mask: &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF],
    resolve: ResolveType::Pattern(0),
};

/// OslFwpKernelSetupPhase1 in winload.efi
/// Final hook: processes the loader parameter block
/// RVA: 0x100EC (Build 26200)
pub static SIG_OSL_FWP_KERNEL_SETUP_PHASE1: Signature = Signature {
    name: "OslFwpKernelSetupPhase1",
    patterns: &[
        // Win11 25H2 (Build 26200) — mov [rsp+8],rcx / push rbp / push rbx / push rsi / push rdi / push r12 / push r13 / push r14 / push r15 / lea rbp,[rsp-1Fh]
        &[0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24],
    ],
    mask: &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF],
    resolve: ResolveType::Pattern(0),
};

/// OslExecuteTransition in winload.efi
/// Used to find ExitBootServices
/// RVA: 0x1AF60 (Build 26200)
pub static SIG_OSL_EXECUTE_TRANSITION: Signature = Signature {
    name: "OslExecuteTransition",
    patterns: &[
        // Win11 25H2 (Build 26200) — mov [rsp+10h],rbx / mov [rsp+18h],rsi / push rdi / sub rsp,30h / call xxx
        &[0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x30],
    ],
    mask: &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF],
    resolve: ResolveType::Pattern(0),
};

/// BlpArchSwitchContext in winload.efi
/// Used for address space context switching (application <-> firmware)
/// RVA: 0x43458 (Build 26200)
pub static SIG_BLP_ARCH_SWITCH_CONTEXT: Signature = Signature {
    name: "BlpArchSwitchContext",
    patterns: &[
        // Win11 25H2 (Build 26200) — mov [rsp+8],rbx / push rdi / sub rsp,20h / mov edx,[rip+xxxx] / mov edi,ecx
        &[0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0x15],
    ],
    mask: &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    resolve: ResolveType::Pattern(0),
};

/// Get PE image base and size from a loaded image
pub unsafe fn get_image_info(base: *const u8) -> Option<(*const u8, usize)> {
    // Check MZ signature
    if *(base as *const u16) != 0x5A4D {
        return None;
    }
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    let nt_headers = base.add(e_lfanew);
    // Check PE signature
    if *(nt_headers as *const u32) != 0x00004550 {
        return None;
    }
    let size_of_image = *(nt_headers.add(0x18 + 0x38) as *const u32) as usize;
    Some((base, size_of_image))
}
