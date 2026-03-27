/// 14-byte inline detour implementation for x86_64.
///
/// Overwrites the first 14 bytes of the target function with:
///   FF 25 00 00 00 00       jmp QWORD PTR [rip+0]
///   XX XX XX XX XX XX XX XX  absolute 64-bit address
///
/// Original bytes are saved for unhooking.

use core::ptr;

const DETOUR_SIZE: usize = 14;

/// Stored hook state — keeps original bytes for unhooking.
#[derive(Clone)]
pub struct InlineHook {
    /// Address of the hooked function
    pub target: *mut u8,
    /// Original bytes that were overwritten
    pub original_bytes: [u8; DETOUR_SIZE],
    /// Whether the hook is currently active
    pub active: bool,
}

impl InlineHook {
    pub const fn empty() -> Self {
        Self {
            target: ptr::null_mut(),
            original_bytes: [0u8; DETOUR_SIZE],
            active: false,
        }
    }
}

/// Install a 14-byte inline detour at `target`, redirecting to `detour`.
/// Returns the hook state containing original bytes.
///
/// # Safety
/// - `target` must be a valid, writable code pointer
/// - `detour` must be a valid function pointer
/// - The first 14 bytes of `target` must be safe to overwrite
pub unsafe fn install_hook(target: *mut u8, detour: *const u8) -> InlineHook {
    let mut hook = InlineHook {
        target,
        original_bytes: [0u8; DETOUR_SIZE],
        active: false,
    };

    // Save original bytes
    ptr::copy_nonoverlapping(target, hook.original_bytes.as_mut_ptr(), DETOUR_SIZE);

    // Write: FF 25 00 00 00 00 [8-byte absolute address]
    let jmp_stub: [u8; 6] = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    ptr::copy_nonoverlapping(jmp_stub.as_ptr(), target, 6);
    ptr::copy_nonoverlapping(
        &(detour as u64) as *const u64 as *const u8,
        target.add(6),
        8,
    );

    hook.active = true;
    hook
}

/// Remove a previously installed hook by restoring original bytes.
///
/// # Safety
/// - The hook must have been installed with `install_hook`
/// - `target` must still be valid and writable
pub unsafe fn remove_hook(hook: &mut InlineHook) {
    if !hook.active || hook.target.is_null() {
        return;
    }
    ptr::copy_nonoverlapping(hook.original_bytes.as_ptr(), hook.target, DETOUR_SIZE);
    hook.active = false;
}

/// Call the original function by temporarily removing the hook.
/// This is used inside hook handlers to call the real function.
///
/// # Safety
/// - Must only be called from within a hook handler
/// - Not thread-safe — assumes single-threaded boot environment
pub unsafe fn call_original<F, R>(hook: &mut InlineHook, f: F) -> R
where
    F: FnOnce() -> R,
{
    // Restore original bytes
    ptr::copy_nonoverlapping(hook.original_bytes.as_ptr(), hook.target, DETOUR_SIZE);

    // Call original
    let result = f();

    result
}

/// Trampoline: save original bytes, execute them, then jump back.
/// This is the clean way to call the original function.
///
/// For the boot chain, we use a simpler approach:
/// 1. Remove hook
/// 2. Call original
/// 3. Re-install hook (if needed)
///
/// This works because the boot environment is single-threaded.
pub struct Trampoline {
    pub hook: InlineHook,
    pub detour_addr: *const u8,
}

impl Trampoline {
    pub const fn empty() -> Self {
        Self {
            hook: InlineHook::empty(),
            detour_addr: ptr::null(),
        }
    }

    /// Install hook and remember detour address for re-hooking.
    pub unsafe fn install(&mut self, target: *mut u8, detour: *const u8) {
        self.detour_addr = detour;
        self.hook = install_hook(target, detour);
    }

    /// Temporarily remove hook, call original, re-install hook.
    pub unsafe fn call_original<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        remove_hook(&mut self.hook);
        let result = f();
        self.hook = install_hook(self.hook.target, self.detour_addr);
        result
    }

    /// Permanently remove the hook.
    pub unsafe fn unhook(&mut self) {
        remove_hook(&mut self.hook);
        self.detour_addr = core::ptr::null();
    }
}
