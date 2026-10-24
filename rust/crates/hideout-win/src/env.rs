//! Environment and well-known folders.

use crate::wide::{from_wide, Wide};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_CommonStartup, FOLDERID_Startup, KF_FLAG_DEFAULT};

/// %VAR% expansion, like .NET's Environment.ExpandEnvironmentVariables: an undefined
/// variable is left exactly as written.
pub fn expand(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let w = Wide::new(s);
    // SAFETY: size query with no buffer, then a buffer of the size Windows asked for.
    let n = unsafe { ExpandEnvironmentStringsW(w.pcwstr(), None) };
    if n == 0 || n > 1 << 20 {
        return s.to_string();
    }
    let mut buf = vec![0u16; n as usize];
    let got = unsafe { ExpandEnvironmentStringsW(w.pcwstr(), Some(&mut buf)) };
    if got == 0 || got > n {
        return s.to_string();
    }
    from_wide(&buf)
}

pub fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// The current user's Startup folder ([Environment]::GetFolderPath('Startup')).
pub fn startup_folder() -> Option<String> {
    known(&FOLDERID_Startup)
}

/// The all-users Startup folder ([Environment]::GetFolderPath('CommonStartup')).
pub fn common_startup_folder() -> Option<String> {
    known(&FOLDERID_CommonStartup)
}

fn known(id: &windows::core::GUID) -> Option<String> {
    // SAFETY: valid GUID; the returned buffer is freed with CoTaskMemFree.
    unsafe {
        let p = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let s = crate::wide::from_pwstr(p.0);
        windows::Win32::System::Com::CoTaskMemFree(Some(p.0 as *const _));
        (!s.is_empty()).then_some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_known_and_keeps_unknown() {
        let s = expand("%SystemRoot%\\a");
        assert!(!s.starts_with('%'));
        assert_eq!(expand("%HIDEOUT_NOT_SET_XYZ%\\a"), "%HIDEOUT_NOT_SET_XYZ%\\a");
        assert_eq!(expand("plain"), "plain");
    }

    #[test]
    fn startup_folders_resolve() {
        assert!(startup_folder().unwrap().to_ascii_lowercase().ends_with("startup"));
        assert!(common_startup_folder().unwrap().to_ascii_lowercase().ends_with("startup"));
    }
}
