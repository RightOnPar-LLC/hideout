//! UTF-16 helpers for talking to the W-suffixed Windows APIs.

use windows::core::PCWSTR;

/// A NUL-terminated UTF-16 copy of `s`. Keep it alive for as long as the PCWSTR is used.
pub struct Wide(Vec<u16>);

impl Wide {
    pub fn new(s: &str) -> Self {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        Wide(v)
    }
    pub fn pcwstr(&self) -> PCWSTR {
        PCWSTR(self.0.as_ptr())
    }
}

/// Text up to the first NUL (or the whole slice if there is none). Invalid UTF-16 is
/// replaced, never trusted: names on a scanned PC are chosen by whoever put them there.
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Read a NUL-terminated wide string from a raw pointer. Null gives "".
///
/// # Safety
/// `p` must be null or point at a NUL-terminated UTF-16 string that stays valid for the
/// duration of the call.
pub unsafe fn from_pwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees a NUL terminator exists within the allocation.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}
