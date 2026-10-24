//! COM setup. Task Scheduler, WMI and shortcut reading all go through COM.

use std::cell::Cell;
use std::sync::Once;
use windows::Win32::System::Com::{
    CoInitializeEx, CoInitializeSecurity, COINIT_MULTITHREADED, EOAC_NONE,
    RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
};

static SECURITY: Once = Once::new();

thread_local! {
    static INIT: Cell<bool> = const { Cell::new(false) };
}

/// Make COM usable on this thread (multithreaded apartment). Safe to call repeatedly.
/// The thread keeps COM for its whole life; Hideout's scan threads are short-lived.
pub fn init() {
    INIT.with(|done| {
        if done.get() {
            return;
        }
        // SAFETY: plain COM initialisation of the calling thread.
        let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        done.set(true);
    });
    SECURITY.call_once(|| {
        // Process-wide default security, so WMI calls can impersonate us (and only us).
        // If something else in the process already set it, Windows says so and we go on.
        // SAFETY: called once, before any proxies are handed out by this crate.
        let _ = unsafe {
            CoInitializeSecurity(None, -1, None, None, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, None, EOAC_NONE, None)
        };
    });
}
