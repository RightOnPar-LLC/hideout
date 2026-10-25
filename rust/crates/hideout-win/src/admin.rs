//! Is this process running with admin rights right now?
//!
//! Same answer as PowerShell's IsInRole(Administrator): true only when the token is
//! elevated. An admin account running un-elevated is "not admin" here, because what
//! matters is what this process can actually read.

use windows::core::BOOL;
use windows::Win32::Security::{CheckTokenMembership, CreateWellKnownSid, WinBuiltinAdministratorsSid, PSID};

pub fn is_elevated() -> bool {
    let mut sid = [0u8; 68]; // SECURITY_MAX_SID_SIZE
    let mut len = sid.len() as u32;
    let psid = PSID(sid.as_mut_ptr() as *mut _);
    // SAFETY: a buffer big enough for any SID; CheckTokenMembership(None) checks the
    // calling thread's effective token.
    unsafe {
        if CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(psid), &mut len).is_err() {
            return false;
        }
        let mut member = BOOL(0);
        CheckTokenMembership(None, psid, &mut member).is_ok() && member.as_bool()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn answers_without_crashing() {
        let _ = super::is_elevated();
    }
}
