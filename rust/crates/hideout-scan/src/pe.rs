//! A small, safe reader for the headers of Windows programs (PE files). It only looks
//! at headers: never runs, loads or maps anything. Every offset is bounds-checked;
//! malformed input gives an error, never a panic (a fuzz test runs it on garbage).
//!
//! What the scan uses it for:
//!   * a file dressed as media (.wav, .raw, .dat ...) that is really a program;
//!   * whether a program carries a signature block at all;
//!   * data appended after the program's last section (an "overlay").

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeInfo {
    pub machine: u16,
    pub is_dll: bool,
    pub is_64: bool,
    pub timestamp: u32,
    pub sections: u16,
    /// The Authenticode block (the security directory) is present and lies inside the file.
    pub has_signature_block: bool,
    /// Bytes after the end of the last section, not counting a signature block at the end.
    pub overlay: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    NotPe,
    Truncated,
    Malformed(&'static str),
}

fn u16_at(b: &[u8], o: usize) -> Result<u16, PeError> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or(PeError::Truncated)
}
fn u32_at(b: &[u8], o: usize) -> Result<u32, PeError> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or(PeError::Truncated)
}

/// Quick test on the first bytes: does this start like a Windows program?
pub fn looks_like_pe(head: &[u8]) -> bool {
    parse(head, head.len() as u64).is_ok()
}

/// Parse PE headers from `head` (the start of the file - 4 KB is plenty for real
/// programs) given the full file size.
pub fn parse(head: &[u8], file_size: u64) -> Result<PeInfo, PeError> {
    if head.len() < 2 || &head[..2] != b"MZ" {
        return Err(PeError::NotPe);
    }
    let e_lfanew = u32_at(head, 0x3C)? as usize;
    if !(0x40..=0x10000).contains(&e_lfanew) {
        return Err(PeError::Malformed("PE header offset"));
    }
    if head.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return Err(if head.len() < e_lfanew + 4 { PeError::Truncated } else { PeError::NotPe });
    }
    let coff = e_lfanew + 4;
    let machine = u16_at(head, coff)?;
    let sections = u16_at(head, coff + 2)?;
    let timestamp = u32_at(head, coff + 4)?;
    let opt_size = u16_at(head, coff + 16)? as usize;
    let characteristics = u16_at(head, coff + 18)?;
    if sections == 0 || sections > 96 {
        return Err(PeError::Malformed("section count"));
    }
    let opt = coff + 20;
    let magic = u16_at(head, opt)?;
    let is_64 = match magic {
        0x10B => false,
        0x20B => true,
        _ => return Err(PeError::Malformed("optional header magic")),
    };
    // Data directories: NumberOfRvaAndSizes then the entries. Security is entry 4.
    let (num_dirs_at, dirs_at) = if is_64 { (opt + 108, opt + 112) } else { (opt + 92, opt + 96) };
    let num_dirs = u32_at(head, num_dirs_at)? as usize;
    let mut has_signature_block = false;
    let mut sig_off = 0u64;
    let mut sig_len = 0u64;
    if num_dirs > 4 && dirs_at + 5 * 8 <= opt + opt_size {
        // The security directory holds a FILE offset, not an RVA.
        sig_off = u32_at(head, dirs_at + 4 * 8)? as u64;
        sig_len = u32_at(head, dirs_at + 4 * 8 + 4)? as u64;
        has_signature_block = sig_len >= 8 && sig_off > 0 && sig_off.checked_add(sig_len).map(|e| e <= file_size).unwrap_or(false);
    }
    let sec_table = opt.checked_add(opt_size).ok_or(PeError::Malformed("optional header size"))?;
    let mut end_of_sections = 0u64;
    for i in 0..sections as usize {
        let s = sec_table + i * 40;
        let raw_size = u32_at(head, s + 16)? as u64;
        let raw_ptr = u32_at(head, s + 20)? as u64;
        if raw_size > 0 {
            end_of_sections = end_of_sections.max(raw_ptr.saturating_add(raw_size));
        }
    }
    let mut data_end = file_size;
    if has_signature_block && sig_off.saturating_add(sig_len) == file_size && sig_off >= end_of_sections {
        data_end = sig_off;
    }
    let overlay = data_end.saturating_sub(end_of_sections);
    Ok(PeInfo { machine, is_dll: characteristics & 0x2000 != 0, is_64, timestamp, sections, has_signature_block, overlay })
}

/// Read the head of a file (up to 4 KB) and its size, then parse.
pub fn read(path: &std::path::Path) -> Result<PeInfo, PeError> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(|_| PeError::Truncated)?;
    let size = f.metadata().map(|m| m.len()).map_err(|_| PeError::Truncated)?;
    let mut head = Vec::with_capacity(4096);
    f.take(4096).read_to_end(&mut head).map_err(|_| PeError::Truncated)?;
    parse(&head, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys(p: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join(p)
    }

    #[test]
    fn reads_real_windows_programs() {
        let n = read(&sys("System32\\notepad.exe")).expect("notepad is a PE");
        assert!(!n.is_dll && n.sections > 0);
        let k = read(&sys("System32\\kernel32.dll")).expect("kernel32 is a PE");
        assert!(k.is_dll && k.is_64);
    }

    #[test]
    fn non_programs_are_not_pe() {
        assert_eq!(parse(b"RIFF....WAVEfmt ", 16), Err(PeError::NotPe));
        assert_eq!(parse(b"", 0), Err(PeError::NotPe));
        assert_eq!(parse(b"MZ", 2), Err(PeError::Truncated));
    }

    #[test]
    fn a_program_renamed_to_wav_is_still_a_program() {
        let bytes = std::fs::read(sys("System32\\notepad.exe")).unwrap();
        assert!(looks_like_pe(&bytes[..4096.min(bytes.len())]));
    }

    /// Fuzz: random and mutated input never panics, and offsets are never trusted.
    #[test]
    fn garbage_never_panics() {
        let real = std::fs::read(sys("System32\\notepad.exe")).unwrap();
        let head = &real[..4096.min(real.len())];
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for i in 0..20_000 {
            let mut b = head.to_vec();
            // Flip 1..8 bytes, sometimes truncate, sometimes pure noise.
            for _ in 0..(rnd() % 8 + 1) {
                let p = (rnd() as usize) % b.len();
                b[p] = rnd() as u8;
            }
            if i % 7 == 0 {
                let n = (rnd() as usize) % b.len();
                b.truncate(n);
            }
            if i % 11 == 0 {
                b = (0..(rnd() % 600)).map(|_| rnd() as u8).collect();
                if b.len() > 2 && i % 2 == 0 {
                    b[0] = b'M';
                    b[1] = b'Z';
                }
            }
            let size = rnd() % (u32::MAX as u64);
            let _ = parse(&b, size);
        }
    }
}
