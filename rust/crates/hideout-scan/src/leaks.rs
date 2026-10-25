//! The leak look-up: files left on the Desktop, in Documents, in Downloads or in the
//! start-up folders that look like they hold a key, a token, a password, a card number
//! or a recovery phrase. READ-ONLY: files are read to look, never moved, changed,
//! opened elsewhere or sent anywhere. The person sees the paths; the guide sees only
//! what kind of secret, redacted.
//!
//! Bounded so it stays quick: two folder levels deep, at most 4,000 entries, and only
//! the first 512 KB of text-like files is read.

use serde::Serialize;
use std::path::{Path, PathBuf};

const MAX_ENTRIES: usize = 4000;
const MAX_READ: u64 = 512 * 1024;
const TEXT_EXT: [&str; 22] = ["txt", "env", "json", "md", "csv", "ini", "cfg", "conf", "config", "yaml", "yml", "ps1", "bat", "cmd", "js", "py", "toml", "xml", "log", "pem", "key", "rtf"];
const NAME_HINTS: [&str; 12] = ["seed", "mnemonic", "recovery phrase", "recovery-phrase", "wallet", "secret", "credential", "password", "passwords", "apikey", "api_key", "api-key"];
const KEY_FILES: [&str; 7] = [".env", "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "credentials", ".npmrc"];

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Leak {
    #[serde(rename = "where")]
    pub path: String,
    pub kinds: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub leaks: Vec<Leak>,
    pub looked_in: Vec<String>,
    pub files_read: usize,
    /// True when the entry cap was reached (not everything was looked at).
    pub capped: bool,
}

/// Desktop, Documents, Downloads and the two start-up folders.
pub fn default_folders() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(home) = std::env::var("USERPROFILE") {
        for f in ["Desktop", "Documents", "Downloads", r"OneDrive\Desktop", r"OneDrive\Documents"] {
            v.push(Path::new(&home).join(f));
        }
    }
    v.extend(hideout_win::env::startup_folder().map(PathBuf::from));
    v.extend(hideout_win::env::common_startup_folder().map(PathBuf::from));
    v.into_iter().filter(|p| p.is_dir()).collect()
}

fn name_kind(name: &str) -> Option<&'static str> {
    let l = name.to_lowercase();
    let ext = Path::new(&l).extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
    if KEY_FILES.contains(&l.as_str()) || ["pem", "key", "ppk", "p12", "pfx"].contains(&ext.as_str()) || l == "wallet.dat" {
        return Some("a key file");
    }
    NAME_HINTS.iter().any(|h| l.contains(h)).then_some("a file named like a secret")
}

fn texty(name: &str) -> bool {
    let l = name.to_lowercase();
    match Path::new(&l).extension() {
        None => true,
        Some(e) => TEXT_EXT.contains(&e.to_string_lossy().as_ref()),
    }
}

pub fn look(folders: &[PathBuf]) -> Report {
    let mut r = Report { leaks: vec![], looked_in: folders.iter().map(|f| f.display().to_string()).collect(), files_read: 0, capped: false };
    let mut entries = 0;
    let mut stack: Vec<(PathBuf, usize)> = folders.iter().map(|f| (f.clone(), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            entries += 1;
            if entries > MAX_ENTRIES {
                r.capped = true;
                return r;
            }
            let Ok(ft) = e.file_type() else { continue };
            let path = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if ft.is_dir() {
                // "Save page as" keeps a page's scripts in "<page>_files": copies of a
                // website, not the person's notes (and wallet scripts ship the whole
                // recovery-word list).
                if depth < 2 && !name.starts_with('.') && !name.ends_with("_files") && !["node_modules", "$recycle.bin"].contains(&name.to_lowercase().as_str()) {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !ft.is_file() {
                continue; // links are not followed
            }
            let mut kinds: Vec<&'static str> = name_kind(&name).into_iter().collect();
            if texty(&name) {
                if let Ok(f) = std::fs::File::open(&path) {
                    use std::io::Read;
                    let mut buf = Vec::new();
                    if f.take(MAX_READ).read_to_end(&mut buf).is_ok() && !buf.contains(&0) {
                        r.files_read += 1;
                        for k in hideout_redact::secret_kinds(&String::from_utf8_lossy(&buf)) {
                            if !kinds.contains(&k) {
                                kinds.push(k);
                            }
                        }
                    }
                }
            }
            if !kinds.is_empty() {
                r.leaks.push(Leak { path: path.display().to_string(), kinds });
            }
        }
    }
    r.leaks.sort_by(|a, b| a.path.cmp(&b.path));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_secrets_by_name_and_by_content_and_only_looks() {
        let d = std::env::temp_dir().join(format!("hideout-leaks-{}", std::process::id()));
        let sub = d.join("Projects").join("app");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(d.join("notes.txt"), "shopping: milk\nkey sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n").unwrap();
        std::fs::write(d.join("wallet backup.txt"), "army van defense carry jealous true garbage claim echo media make crunch").unwrap();
        std::fs::write(sub.join(".env"), "PASSWORD=hunter2\n").unwrap();
        std::fs::write(d.join("photo.jpg"), b"\xFF\xD8 sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        std::fs::write(d.join("recipe.txt"), "two eggs, a cup of flour").unwrap();
        // A saved web page's scripts, and a file holding the whole word list: not leaks.
        std::fs::create_dir_all(d.join("Bank page_files")).unwrap();
        std::fs::write(d.join("Bank page_files").join("app.js"), "var k='sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';").unwrap();
        std::fs::write(d.join("words.txt"), "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict").unwrap();
        let before: Vec<_> = std::fs::read_dir(&d).unwrap().flatten().map(|e| (e.path(), e.metadata().unwrap().len())).collect();
        let r = look(std::slice::from_ref(&d));
        let kinds_of = |n: &str| r.leaks.iter().find(|l| l.path.ends_with(n)).map(|l| l.kinds.clone());
        assert_eq!(kinds_of("notes.txt"), Some(vec!["an API key or token"]));
        assert_eq!(kinds_of("wallet backup.txt"), Some(vec!["a file named like a secret", "a recovery phrase"]));
        assert_eq!(kinds_of(".env"), Some(vec!["a key file", "a password"]));
        assert_eq!(kinds_of("photo.jpg"), None, "binary files are not read");
        assert_eq!(kinds_of("recipe.txt"), None);
        assert_eq!(kinds_of("app.js"), None, "saved-page script folders are skipped");
        assert_eq!(kinds_of("words.txt"), None, "27 list words in a row is a word list, not a phrase");
        let after: Vec<_> = std::fs::read_dir(&d).unwrap().flatten().map(|e| (e.path(), e.metadata().unwrap().len())).collect();
        assert_eq!(before, after, "nothing was changed");
        std::fs::remove_dir_all(&d).ok();
    }
}
