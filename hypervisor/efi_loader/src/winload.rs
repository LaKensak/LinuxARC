/// Boot context switching between Application and Firmware address spaces.
///
/// During the Windows boot process, winload.efi operates in two contexts:
/// - Application context (ID 0): virtual address space for winload/kernel
/// - Firmware context (ID 1): physical address space for UEFI runtime
///
/// Our hooks execute in Application context but some operations need
/// Firmware context (e.g., UEFI console output). BlpArchSwitchContext
/// toggles between them.

/// Context identifiers
pub const CONTEXT_APPLICATION: i32 = 0;
pub const CONTEXT_FIRMWARE: i32 = 1;

/// Function pointer type for BlpArchSwitchContext
type FnSwitchContext = unsafe extern "efiapi" fn(context_id: i32) -> i32;

/// Global pointer to BlpArchSwitchContext — set during hook installation
static mut SWITCH_CONTEXT_FN: Option<FnSwitchContext> = None;

/// Initialize with the resolved BlpArchSwitchContext address.
pub unsafe fn init(switch_ctx_addr: *const u8) {
    SWITCH_CONTEXT_FN = Some(core::mem::transmute(switch_ctx_addr));
}

/// Switch to the specified context. Returns the previous context ID.
pub unsafe fn switch_context(context_id: i32) -> i32 {
    if let Some(switch_fn) = SWITCH_CONTEXT_FN {
        switch_fn(context_id)
    } else {
        -1
    }
}

/// RAII guard that switches to Firmware context on creation
/// and restores Application context on drop.
/// Use this when you need UEFI services from within a boot hook.
pub struct FirmwareContextGuard {
    previous: i32,
}

impl FirmwareContextGuard {
    /// Switch to firmware context. Returns a guard that will restore
    /// the previous context when dropped.
    pub unsafe fn enter() -> Self {
        let previous = switch_context(CONTEXT_FIRMWARE);
        Self { previous }
    }
}

impl Drop for FirmwareContextGuard {
    fn drop(&mut self) {
        unsafe {
            switch_context(self.previous);
        }
    }
}

/// RAII guard for Application context.
pub struct ApplicationContextGuard {
    previous: i32,
}

impl ApplicationContextGuard {
    pub unsafe fn enter() -> Self {
        let previous = switch_context(CONTEXT_APPLICATION);
        Self { previous }
    }
}

impl Drop for ApplicationContextGuard {
    fn drop(&mut self) {
        unsafe {
            switch_context(self.previous);
        }
    }
}
