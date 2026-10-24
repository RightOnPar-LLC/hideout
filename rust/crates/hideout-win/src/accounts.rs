//! Local user accounts and who is in the Administrators group (NetUserEnum,
//! NetLocalGroupGetMembers). Read-only: nothing here can create, change or remove an
//! account or a group member.

use crate::wide::{from_pwstr, Wide};
use windows::core::PWSTR;
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupGetMembers, NetUserEnum, FILTER_NORMAL_ACCOUNT, LOCALGROUP_MEMBERS_INFO_2,
    MAX_PREFERRED_LENGTH, UF_ACCOUNTDISABLE, USER_INFO_2,
};
use windows::Win32::Security::{CreateWellKnownSid, LookupAccountSidW, WinBuiltinAdministratorsSid, PSID, SID_NAME_USE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub enabled: bool,
    /// Seconds since 1970 (UTC) of the last sign-in; None if never.
    pub last_logon: Option<i64>,
    /// Seconds since the password was set.
    pub password_age: u32,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// DOMAIN\name as Windows reports it.
    pub name: String,
    pub sid_usage: i32,
    /// Where the account lives, in Get-LocalGroupMember's words: Local, MicrosoftAccount,
    /// AzureAD, ActiveDirectory, or "" when Windows would not say.
    pub source: String,
}

// Documented in ntsecapi.h (Windows 10+), not in the generated bindings and not in the
// SDK's import libraries; PowerShell's LocalAccounts module binds it through this API
// set (implemented by sechost.dll), and so does Hideout.
#[link(name = "api-ms-win-security-lsalookup-l1-1-2", kind = "raw-dylib")]
unsafe extern "system" {
    fn LsaLookupUserAccountType(sid: *mut core::ffi::c_void, account_type: *mut i32) -> i32;
}

/// What kind of account a SID is, the way PowerShell's LocalAccounts module asks.
fn account_source(sid: PSID) -> String {
    let mut t = 0i32;
    // SAFETY: `sid` points into the member buffer, alive for the duration of the call.
    let st = unsafe { LsaLookupUserAccountType(sid.0, &mut t) };
    if st != 0 {
        return String::new();
    }
    match t {
        1 => "Local",
        2 | 3 => "ActiveDirectory",
        4 | 6 | 7 => "MicrosoftAccount",
        5 => "AzureAD",
        _ => "",
    }
    .into()
}

pub fn users() -> Result<Vec<User>, String> {
    let mut out = Vec::new();
    let mut resume = 0u32;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let (mut read, mut total) = (0u32, 0u32);
        // SAFETY: local machine, level 2, out-pointers to locals; the buffer is freed below.
        let rc = unsafe { NetUserEnum(windows::core::PCWSTR::null(), 2, FILTER_NORMAL_ACCOUNT, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total, Some(&mut resume)) };
        if rc != 0 && rc != 234 {
            return Err(format!("could not list local users (error {rc})"));
        }
        if !buf.is_null() {
            // SAFETY: Windows wrote `read` USER_INFO_2 records at `buf`.
            unsafe {
                let rows = std::slice::from_raw_parts(buf as *const USER_INFO_2, read as usize);
                for u in rows {
                    out.push(User {
                        name: from_pwstr(u.usri2_name.0),
                        enabled: u.usri2_flags.0 & UF_ACCOUNTDISABLE.0 == 0,
                        last_logon: (u.usri2_last_logon != 0).then_some(u.usri2_last_logon as i64),
                        password_age: u.usri2_password_age,
                        description: from_pwstr(u.usri2_comment.0),
                    });
                }
                NetApiBufferFree(Some(buf as *const _));
            }
        }
        if rc != 234 {
            break;
        }
    }
    Ok(out)
}

/// The Administrators group's own (localized) name, from its well-known SID.
fn administrators_name() -> Option<String> {
    let mut sid = [0u8; 68];
    let mut len = sid.len() as u32;
    let psid = PSID(sid.as_mut_ptr() as *mut _);
    let mut name = vec![0u16; 256];
    let mut dom = vec![0u16; 256];
    let (mut nl, mut dl) = (name.len() as u32, dom.len() as u32);
    let mut use_ = SID_NAME_USE::default();
    // SAFETY: buffers sized for any SID / name; local lookup.
    unsafe {
        CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(psid), &mut len).ok()?;
        LookupAccountSidW(windows::core::PCWSTR::null(), psid, Some(PWSTR(name.as_mut_ptr())), &mut nl, Some(PWSTR(dom.as_mut_ptr())), &mut dl, &mut use_).ok()?;
    }
    Some(crate::wide::from_wide(&name))
}

pub fn administrators() -> Result<Vec<Member>, String> {
    let group = administrators_name().ok_or("could not find the Administrators group")?;
    let w = Wide::new(&group);
    let mut out = Vec::new();
    let mut resume = 0usize;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let (mut read, mut total) = (0u32, 0u32);
        // SAFETY: as in users().
        let rc = unsafe { NetLocalGroupGetMembers(windows::core::PCWSTR::null(), w.pcwstr(), 2, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total, Some(&mut resume)) };
        if rc != 0 && rc != 234 {
            return Err(format!("could not list the Administrators group (error {rc})"));
        }
        if !buf.is_null() {
            // SAFETY: Windows wrote `read` records at `buf`.
            unsafe {
                for m in std::slice::from_raw_parts(buf as *const LOCALGROUP_MEMBERS_INFO_2, read as usize) {
                    out.push(Member { name: from_pwstr(m.lgrmi2_domainandname.0), sid_usage: m.lgrmi2_sidusage.0, source: account_source(m.lgrmi2_sid) });
                }
                NetApiBufferFree(Some(buf as *const _));
            }
        }
        if rc != 234 {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn lists_users_and_admins() {
        let u = super::users().expect("users");
        assert!(u.iter().any(|x| x.name.eq_ignore_ascii_case("Administrator") || x.name.eq_ignore_ascii_case("DefaultAccount") || x.name.eq_ignore_ascii_case("Guest")));
        let a = super::administrators().expect("admins");
        assert!(!a.is_empty());
    }
}
