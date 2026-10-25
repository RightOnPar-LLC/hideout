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

/// SHA-256 of a file of any size, read in 1 MB pieces (nothing big is held in memory).
/// Upper-case hex like Get-FileHash.
pub fn sha256_file_stream_upper(path: &Path) -> std::io::Result<String> {
    use windows::Win32::Security::Cryptography::{BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash, BCryptHashData, BCRYPT_HASH_HANDLE};
    let mut f = std::fs::File::open(path)?;
    let mut h = BCRYPT_HASH_HANDLE::default();
    // SAFETY: SHA-256 pseudo-handle; Windows allocates the hash object itself.
    let st = unsafe { BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &mut h, None, None, 0) };
    if st.is_err() {
        return Err(std::io::Error::other("could not start a hash"));
    }
    let mut buf = vec![0u8; 1 << 20];
    let result = (|| {
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            // SAFETY: a live hash handle and a slice of what was just read.
            if unsafe { BCryptHashData(h, &buf[..n], 0) }.is_err() {
                return Err(std::io::Error::other("hashing failed"));
            }
        }
        let mut out = [0u8; 32];
        // SAFETY: finishing the same live handle into a 32-byte buffer.
        if unsafe { BCryptFinishHash(h, &mut out, 0) }.is_err() {
            return Err(std::io::Error::other("hashing failed"));
        }
        Ok(hex(&out).to_ascii_uppercase())
    })();
    // SAFETY: destroying the handle created above, once.
    let _ = unsafe { BCryptDestroyHash(h) };
    result
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
    fn streaming_hash_matches_one_shot() {
        let p = std::env::temp_dir().join(format!("hw-hash-{}", random_hex(4)));
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&p, &data).unwrap();
        assert_eq!(sha256_file_stream_upper(&p).unwrap(), hex(&sha256(&data)).to_ascii_uppercase());
        std::fs::remove_file(&p).ok();
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
