//! Who this PC belongs to, so the guide never hears it: the Windows account names, every
//! profile folder on the machine (scan data names other accounts' paths too), the
//! signed-in person's display name, and the PC's name. The same list redact.mjs's
//! collectIdentity() builds, plus the display name. Read-only.

use crate::wide::{from_pwstr, Wide};
use windows::Win32::NetworkManagement::NetManagement::{NetApiBufferFree, NetUserGetInfo, USER_INFO_10};

pub struct Who {
    pub names: Vec<String>,
    pub computer: String,
}

/// The display ("full") name Windows keeps for an account, e.g. "Jane Doe".
pub fn full_name(user: &str) -> Option<String> {
    let u = Wide::new(user);
    let mut buf: *mut u8 = std::ptr::null_mut();
    // SAFETY: local machine, level 10, out-pointer to a local; the buffer is freed below.
    let rc = unsafe { NetUserGetInfo(windows::core::PCWSTR::null(), u.pcwstr(), 10, &mut buf) };
    if rc != 0 || buf.is_null() {
        return None;
    }
    // SAFETY: Windows wrote one USER_INFO_10 at `buf`; read it, then free the buffer.
    let name = unsafe {
        let info = &*(buf as *const USER_INFO_10);
        let n = from_pwstr(info.usri10_full_name.0);
        let _ = NetApiBufferFree(Some(buf as *const _));
        n
    };
    let n = name.trim().to_string();
    (!n.is_empty()).then_some(n)
}

pub fn collect() -> Who {
    let mut names: Vec<String> = Vec::new();
    let mut add = |n: &str| {
        let n = n.trim();
        if n.chars().count() >= 3 && !names.iter().any(|x| x == n) {
            names.push(n.to_string());
        }
    };
    let user = std::env::var("USERNAME").unwrap_or_default();
    add(&user);
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let home_path = std::path::Path::new(&home);
    if let Some(b) = home_path.file_name() {
        add(&b.to_string_lossy());
    }
    // Every profile folder beside this one.
    if let Some(users) = home_path.parent() {
        if let Ok(rd) = std::fs::read_dir(users) {
            for e in rd.flatten() {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let n = e.file_name().to_string_lossy().to_string();
                    if !["public", "default", "default user", "all users"].contains(&n.to_lowercase().as_str()) {
                        add(&n);
                    }
                }
            }
        }
    }
    if let Some(full) = full_name(&user) {
        add(&full);
        for part in full.split_whitespace() {
            add(part.trim_matches(|c: char| !c.is_alphanumeric()));
        }
    }
    Who { names, computer: std::env::var("COMPUTERNAME").unwrap_or_default() }
}

#[cfg(test)]
mod tests {
    #[test]
    fn this_pc_has_an_identity() {
        let w = super::collect();
        assert!(!w.computer.is_empty());
        let user = std::env::var("USERNAME").unwrap();
        if user.len() >= 3 {
            assert!(w.names.contains(&user));
        }
    }
}
