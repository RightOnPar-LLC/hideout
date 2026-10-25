//! Randomness and SHA-256 from Windows' own CNG provider (no extra crypto crates).

use std::io::Read;
use std::path::Path;
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, BCryptHash, BCRYPT_SHA256_ALG_HANDLE, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};

/// Cryptographically strong random bytes. Panics only if Windows' system RNG fails,
/// which means the machine cannot be trusted to make a session key at all.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    // SAFETY: a valid mutable buffer; the system-preferred RNG needs no algorithm handle.
    let st = unsafe { BCryptGenRandom(None, &mut buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    assert!(st.is_ok(), "system random number generator failed: {:?}", st);
    buf
}

/// Lower-case hex, the way the session key is written into the launch URL.
pub fn random_hex(n_bytes: usize) -> String {
    hex(&random_bytes(n_bytes))
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: the pseudo-handle BCRYPT_SHA256_ALG_HANDLE is always valid (Windows 10+);
    // input and output are valid slices of the right size.
    let st = unsafe { BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, data, &mut out) };
    assert!(st.is_ok(), "SHA-256 failed: {:?}", st);
    out
}

/// SHA-256 of a whole file, upper-case hex like PowerShell's Get-FileHash.
/// Reads the file once into memory, capped: anything over `cap` bytes is reported as an
/// error rather than hashed partially (a partial hash would look like a real one).
pub fn sha256_file_upper(path: &Path, cap: u64) -> std::io::Result<String> {
    let f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > cap {
        return Err(std::io::Error::other("file too large to hash"));
    }
    let mut buf = Vec::with_capacity(len as usize);
    f.take(cap + 1).read_to_end(&mut buf)?;
    Ok(hex(&sha256(&buf)).to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn random_is_random_and_sized() {
        let a = random_bytes(32);
        let b = random_bytes(32);
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "two 256-bit draws must differ");
        assert_eq!(random_hex(32).len(), 64);
    }
}
