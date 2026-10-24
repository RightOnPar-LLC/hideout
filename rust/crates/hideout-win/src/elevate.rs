//! Run a program with admin rights: Windows shows its own consent prompt and the
//! person clicks Yes (or not). Used for exactly one thing - Hideout re-running its own,
//! read-only deep check elevated. Waits for it to finish and returns its exit code.

use crate::wide::Wide;
use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

#[derive(Debug, PartialEq, Eq)]
pub enum Elevated {
    Exited(u32),
    /// The person said no to Windows' prompt (or it was dismissed).
    Declined,
    Failed(String),
    TimedOut,
}

pub fn run_as_admin(exe: &str, params: &str, timeout_ms: u32) -> Elevated {
    let (verb, file, args) = (Wide::new("runas"), Wide::new(exe), Wide::new(params));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: verb.pcwstr(),
        lpFile: file.pcwstr(),
        lpParameters: args.pcwstr(),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: a fully initialised struct whose strings outlive the call.
    if let Err(e) = unsafe { ShellExecuteExW(&mut info) } {
        // ERROR_CANCELLED: the consent prompt was declined.
        if e.code().0 as u32 == 0x8007_04C7 {
            return Elevated::Declined;
        }
        return Elevated::Failed(e.to_string());
    }
    if info.hProcess.is_invalid() {
        return Elevated::Failed("Windows did not hand back the process".into());
    }
    // SAFETY: we own hProcess (NOCLOSEPROCESS) and close it once.
    unsafe {
        let r = WaitForSingleObject(info.hProcess, timeout_ms);
        let out = if r != WAIT_OBJECT_0 {
            Elevated::TimedOut
        } else {
            let mut code = 0u32;
            match GetExitCodeProcess(info.hProcess, &mut code) {
                Ok(()) => Elevated::Exited(code),
                Err(e) => Elevated::Failed(e.to_string()),
            }
        };
        let _ = CloseHandle(info.hProcess);
        out
    }
}
