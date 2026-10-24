//! Read-only registry access. Keys are only ever opened with KEY_READ.
//!
//! Values come back the way .NET's RegistryKey.GetValue returns them (what PowerShell's
//! Get-ItemProperty shows), because the scan rules were written against those:
//! REG_EXPAND_SZ is expanded, a single trailing NUL is dropped, REG_MULTI_SZ is a list,
//! DWORD is signed.

use crate::wide::Wide;
use windows::core::PWSTR;
use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW, HKEY,
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_64KEY, REG_BINARY,
    REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    LocalMachine,
    CurrentUser,
    Users,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Multi(Vec<String>),
    Dword(i32),
    Qword(i64),
    Binary(Vec<u8>),
    /// A type .NET would hand back as raw bytes too (REG_NONE, REG_LINK, ...).
    Other(Vec<u8>),
}

impl Value {
    /// What PowerShell's "$($value)" prints: lists and byte arrays join with spaces.
    pub fn to_ps_string(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Multi(v) => v.join(" "),
            Value::Dword(n) => n.to_string(),
            Value::Qword(n) => n.to_string(),
            Value::Binary(b) | Value::Other(b) => b.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(" "),
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Dword(n) => Some(*n as i64),
            Value::Qword(n) => Some(*n),
            Value::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }
}

pub struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: we own this handle and close it exactly once.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn root(h: Hive) -> HKEY {
    match h {
        Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        Hive::CurrentUser => HKEY_CURRENT_USER,
        Hive::Users => HKEY_USERS,
    }
}

impl Key {
    /// Open `path` under `hive` for reading, in the 64-bit view. None if it does not exist
    /// or cannot be read; callers that must tell those apart use `open_why`.
    pub fn open(hive: Hive, path: &str) -> Option<Key> {
        Self::open_why(hive, path).ok()
    }

    /// Like `open`, but says why it failed (2 = not there, 5 = access denied, ...).
    pub fn open_why(hive: Hive, path: &str) -> Result<Key, u32> {
        let w = Wide::new(path);
        let mut out = HKEY::default();
        // SAFETY: valid root, NUL-terminated path, out-pointer to a local.
        let rc = unsafe { RegOpenKeyExW(root(hive), w.pcwstr(), None, KEY_READ | KEY_WOW64_64KEY, &mut out) };
        if rc == ERROR_SUCCESS {
            Ok(Key(out))
        } else {
            Err(rc.0)
        }
    }

    pub fn subkey(&self, path: &str) -> Option<Key> {
        let w = Wide::new(path);
        let mut out = HKEY::default();
        // SAFETY: as in open_why, relative to a handle we own.
        let rc = unsafe { RegOpenKeyExW(self.0, w.pcwstr(), None, KEY_READ | KEY_WOW64_64KEY, &mut out) };
        (rc == ERROR_SUCCESS).then_some(Key(out))
    }

    fn sizes(&self) -> (u32, u32, u32) {
        let (mut subkey_len, mut name_len, mut data_len) = (0u32, 0u32, 0u32);
        // SAFETY: out-pointers to locals; a handle we own.
        unsafe {
            let _ = RegQueryInfoKeyW(self.0, None, None, None, None, Some(&mut subkey_len), None, None, Some(&mut name_len), Some(&mut data_len), None, None);
        }
        (subkey_len + 1, name_len + 1, data_len)
    }

    /// Names of the direct subkeys, in registry order.
    pub fn subkeys(&self) -> Vec<String> {
        let (max_sub, _, _) = self.sizes();
        let mut out = Vec::new();
        let mut buf = vec![0u16; max_sub.max(256) as usize];
        let mut i = 0u32;
        loop {
            let mut len = buf.len() as u32;
            // SAFETY: buffer and its length in characters; handle we own.
            let rc = unsafe { RegEnumKeyExW(self.0, i, Some(PWSTR(buf.as_mut_ptr())), &mut len, None, None, None, None) };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc == ERROR_MORE_DATA && buf.len() < 65536 {
                // A key was added with a longer name since the size query: retry this index.
                buf.resize(buf.len() * 2, 0);
                continue;
            }
            if rc == ERROR_SUCCESS {
                out.push(String::from_utf16_lossy(&buf[..len as usize]));
            }
            i += 1;
        }
        out
    }

    /// Every value as (name, value). The unnamed default value has name "".
    pub fn values(&self) -> Vec<(String, Value)> {
        let (_, max_name, max_data) = self.sizes();
        let mut out = Vec::new();
        let mut name = vec![0u16; max_name.max(64) as usize];
        let mut data = vec![0u8; (max_data as usize).max(64)];
        let mut i = 0u32;
        loop {
            let mut nlen = name.len() as u32;
            let mut dlen = data.len() as u32;
            let mut ty = 0u32;
            // SAFETY: buffers and their lengths; handle we own.
            let rc = unsafe {
                RegEnumValueW(self.0, i, Some(PWSTR(name.as_mut_ptr())), &mut nlen, None, Some(&mut ty), Some(data.as_mut_ptr()), Some(&mut dlen))
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc == ERROR_MORE_DATA && data.len() < 16 * 1024 * 1024 {
                // A value grew between the size query and now: widen and retry this index.
                name.resize(name.len() * 2, 0);
                data.resize(data.len() * 2 + 64, 0);
                continue;
            }
            if rc != ERROR_SUCCESS {
                i += 1;
                continue;
            }
            let n = String::from_utf16_lossy(&name[..nlen as usize]);
            out.push((n, decode(ty, &data[..dlen as usize])));
            i += 1;
        }
        out
    }

    /// One value by name ("" for the default value), case-insensitively like Windows.
    pub fn value(&self, name: &str) -> Option<Value> {
        self.values().into_iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v)
    }

    pub fn string(&self, name: &str) -> Option<String> {
        self.value(name).map(|v| v.to_ps_string())
    }
}

fn utf16(data: &[u8]) -> Vec<u16> {
    data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
}

/// .NET semantics: drop ONE trailing NUL from a string value; keep anything before it.
fn reg_string(data: &[u8]) -> String {
    let mut w = utf16(data);
    if w.last() == Some(&0) {
        w.pop();
    }
    String::from_utf16_lossy(&w)
}

pub fn decode(ty: u32, data: &[u8]) -> Value {
    match ty {
        t if t == REG_SZ.0 => Value::Str(reg_string(data)),
        t if t == REG_EXPAND_SZ.0 => Value::Str(crate::env::expand(&reg_string(data))),
        t if t == REG_MULTI_SZ.0 => {
            let w = utf16(data);
            let mut parts: Vec<String> = w.split(|&c| c == 0).map(String::from_utf16_lossy).collect();
            // The list ends with an empty string (double NUL) in a well-formed value.
            while parts.last().map(|s| s.is_empty()).unwrap_or(false) {
                parts.pop();
            }
            Value::Multi(parts)
        }
        t if t == REG_DWORD.0 && data.len() >= 4 => Value::Dword(i32::from_le_bytes([data[0], data[1], data[2], data[3]])),
        t if t == REG_QWORD.0 && data.len() >= 8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[..8]);
            Value::Qword(i64::from_le_bytes(b))
        }
        t if t == REG_BINARY.0 => Value::Binary(data.to_vec()),
        _ => Value::Other(data.to_vec()),
    }
}

/// Names of the user hives loaded under HKEY_USERS (S-1-5-21-..., and their _Classes).
pub fn loaded_user_hives() -> Vec<String> {
    Key::open(Hive::Users, "").map(|k| k.subkeys()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    #[test]
    fn strings_drop_one_trailing_nul_only() {
        assert_eq!(decode(REG_SZ.0, &le("abc\0")), Value::Str("abc".into()));
        assert_eq!(decode(REG_SZ.0, &le("abc")), Value::Str("abc".into()));
        assert_eq!(decode(REG_SZ.0, &le("a\0b\0")), Value::Str("a\0b".into()));
    }

    #[test]
    fn multi_and_numbers() {
        assert_eq!(decode(REG_MULTI_SZ.0, &le("x\0y\0\0")), Value::Multi(vec!["x".into(), "y".into()]));
        assert_eq!(decode(REG_DWORD.0, &(-1i32).to_le_bytes()), Value::Dword(-1));
        assert_eq!(Value::Multi(vec!["a".into(), "b".into()]).to_ps_string(), "a b");
        assert_eq!(Value::Binary(vec![1, 2, 255]).to_ps_string(), "1 2 255");
    }

    #[test]
    fn expand_sz_is_expanded() {
        let v = decode(REG_EXPAND_SZ.0, &le("%SystemRoot%\\x\0"));
        let s = v.as_str().unwrap().to_string();
        assert!(!s.contains('%') && s.to_ascii_lowercase().ends_with("\\x"), "{s}");
    }

    #[test]
    fn reads_a_real_key() {
        let k = Key::open(Hive::LocalMachine, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").expect("open");
        assert!(k.string("ProductName").is_some());
        assert!(Key::open(Hive::LocalMachine, "SOFTWARE\\NoSuchKey-hideout-test").is_none());
        assert!(!loaded_user_hives().is_empty());
    }
}
