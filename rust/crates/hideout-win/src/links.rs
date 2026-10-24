//! Shortcut (.lnk) targets, read with the shell's own parser (IShellLink) - the same
//! thing WScript.Shell's CreateShortcut(..).TargetPath reads. Loading a shortcut only
//! parses it; nothing is launched or resolved.

use crate::wide::{from_wide, Wide};
use windows::core::Interface;
use windows::Win32::System::Com::{CoCreateInstance, IPersistFile, CLSCTX_INPROC_SERVER, STGM_READ};
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shortcut {
    pub target: String,
    pub args: String,
}

/// Target and arguments of a .lnk file. None if it cannot be parsed.
pub fn read(path: &str) -> Option<Shortcut> {
    crate::com::init();
    // SAFETY: COM activation of the shell's link object; Load with read-only mode.
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        let pf: IPersistFile = link.cast().ok()?;
        let w = Wide::new(path);
        pf.Load(w.pcwstr(), STGM_READ).ok()?;
        let mut target = vec![0u16; 1024];
        // fflags 0: the long, expanded path (what WScript's TargetPath shows).
        let _ = link.GetPath(&mut target, std::ptr::null_mut(), 0);
        let mut args = vec![0u16; 4096];
        let _ = link.GetArguments(&mut args);
        Some(Shortcut { target: from_wide(&target), args: from_wide(&args) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_start_menu_shortcut() {
        let dir = std::path::PathBuf::from(crate::env::var("ProgramData")).join("Microsoft\\Windows\\Start Menu\\Programs");
        let mut found = None;
        for e in walk(&dir, 2) {
            if e.extension().map(|x| x.eq_ignore_ascii_case("lnk")).unwrap_or(false) {
                if let Some(s) = read(&e.to_string_lossy()) {
                    if !s.target.is_empty() {
                        found = Some(s);
                        break;
                    }
                }
            }
        }
        assert!(found.is_some(), "no readable shortcut in the Start menu");
        assert!(read("C:\\no\\such\\file.lnk").is_none());
    }

    fn walk(d: &std::path::Path, depth: u32) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() && depth > 0 {
                    out.extend(walk(&p, depth - 1));
                } else {
                    out.push(p);
                }
            }
        }
        out
    }
}
