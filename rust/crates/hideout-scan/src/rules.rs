//! The scan's rules, word for word from hideout.ps1, as pure functions.
//!
//! PowerShell's -match / -like / -contains ignore case, so every pattern here is
//! case-insensitive too. A rule that quietly became case-sensitive in the port would
//! miss "C:\PROGRAMDATA\..." - that is exactly the kind of drift the parity harness and
//! these tests exist to catch.

use regex::Regex;
use std::sync::OnceLock;

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("valid built-in pattern"))
}

/// Folders anyone (or any program the person runs) can write to.
pub fn user_writable(path: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"(?i)^[A-Za-z]:\\(ProgramData|Users\\Public|Windows\\Temp|Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents))\\").is_match(path)
}

/// Data files dressed as media / blobs.
pub fn payload_ext(name: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"(?i)\.(raw|wav|dat|bin|tmp|log|db|png|jpg|jpeg|bmp|mp3|ico|cab|pak)$").is_match(name)
}

/// The kinds of file the sideloading check looks at.
pub fn program_ext(path: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"(?i)\.(exe|dll|ocx|cpl|scr|com)$").is_match(path)
}

pub fn store_alias(path: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"(?i)\\AppData\\Local\\Microsoft\\WindowsApps\\").is_match(path)
}

/// Programs that run a DLL or script handed to them: the real target is in the args.
pub fn is_host(path: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"(?i)\\(rundll32|regsvr32|mshta|wscript|cscript)\.exe$").is_match(path)
}

/// hideout.ps1 Get-ProgramPath: the program a command line runs, or None.
pub fn program_path(cmd: &str) -> Option<String> {
    if cmd.is_empty() {
        return None;
    }
    let c = hideout_win::env::expand(cmd.trim());
    if let Some(rest) = c.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            // PowerShell: $end = IndexOf('"', 1); only "> 1" counts (a non-empty name).
            if end >= 1 {
                return Some(rest[..end].to_string());
            }
        }
    }
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"(?i)^(.+?\.(exe|dll|com|scr|cpl|ocx))(\s|,|$)").captures(&c).map(|m| m[1].to_string())
}

/// hunt.ps1's Get-ProgramPath: like `program_path`, but it also understands the
/// kernel-style paths drivers and services use ("\??\C:\...", "\SystemRoot\...",
/// "system32\..."), knows .sys files, and hands back the text itself when no program
/// name is found in it (so nothing is silently dropped).
pub fn program_path_ext(cmd: &str) -> Option<String> {
    if cmd.trim().is_empty() {
        return None;
    }
    let mut c = hideout_win::env::expand(cmd.trim());
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    if let Some(rest) = c.strip_prefix(r"\??\") {
        c = rest.to_string();
    }
    if c.len() >= 12 && c[..12].eq_ignore_ascii_case(r"\SystemRoot\") {
        c = format!(r"{windir}\{}", &c[12..]);
    } else if c.len() >= 9 && c[..9].eq_ignore_ascii_case(r"system32\") {
        c = format!(r"{windir}\System32\{}", &c[9..]);
    }
    if let Some(rest) = c.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            if end >= 1 {
                return Some(rest[..end].to_string());
            }
        }
    }
    static R: OnceLock<Regex> = OnceLock::new();
    match re(&R, r"(?i)^(.+?\.(exe|dll|sys|com|scr|cpl|ocx))(\s|,|$)").captures(&c) {
        Some(m) => Some(m[1].to_string()),
        None => Some(c),
    }
}

/// hideout.ps1 Get-TargetFromArgs: the first full path to a program in the arguments.
pub fn target_from_args(args: &str) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    let a = hideout_win::env::expand(args);
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r#"(?i)([A-Za-z]:\\[^"]+?\.(dll|exe|ocx|cpl))"#).captures(&a).map(|m| m[1].to_string())
}

/// Machine-made folder names flip case over and over (kLmQzRtPx8); human names are words.
/// Needs 4+ case flips AND (4+ capitals or a digit). Long hex runs count too.
pub fn is_random_name(n: &str) -> bool {
    static HEX: OnceLock<Regex> = OnceLock::new();
    static SHAPE: OnceLock<Regex> = OnceLock::new();
    static DIGIT: OnceLock<Regex> = OnceLock::new();
    if re(&HEX, r"(?i)^[0-9a-f]{16,}$").is_match(n) {
        return true;
    }
    if !re(&SHAPE, r"^[A-Za-z0-9]{8,14}$").is_match(n) {
        return false;
    }
    let chars: Vec<char> = n.chars().collect();
    let (mut flips, mut upper) = (0, 0);
    for i in 0..chars.len() {
        let c = chars[i];
        if c.is_uppercase() {
            upper += 1;
        }
        if i > 0 && c.is_alphabetic() && chars[i - 1].is_alphabetic() && c.is_uppercase() != chars[i - 1].is_uppercase() {
            flips += 1;
        }
    }
    flips >= 4 && (upper >= 4 || re(&DIGIT, r"\d").is_match(n))
}

/// hideout.ps1 Get-Org: the O= of a certificate subject, else its CN=, else "".
/// The pattern is the original one, unanchored and case-insensitive, on purpose: the
/// vendor match below was tuned on exactly these strings.
pub fn org_from_subject(subject: &str) -> String {
    static O: OnceLock<Regex> = OnceLock::new();
    static CN: OnceLock<Regex> = OnceLock::new();
    if let Some(m) = re(&O, r#"(?i)O="?([^",]+)"#).captures(subject) {
        return m[1].trim().to_string();
    }
    if let Some(m) = re(&CN, r#"(?i)CN="?([^",]+)"#).captures(subject) {
        return m[1].trim().to_string();
    }
    String::new()
}

/// The word Test-VendorInstalled searches for: the signer's first word, split on
/// whitespace, comma or "(". None means "too short to judge" (treated as installed).
pub fn vendor_word(org: &str) -> Option<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let first = re(&R, r"[\s,(]").split(org).next().unwrap_or("");
    (first.chars().count() >= 3).then(|| first.to_string())
}

/// Case-insensitive "is `needle` anywhere in `hay`" (PowerShell -match on an escaped word).
pub fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(&needle.to_lowercase())
}

/// The last path component, like Split-Path -Leaf.
pub fn leaf(path: &str) -> &str {
    let p = path.trim_end_matches('\\');
    p.rsplit('\\').next().unwrap_or(p)
}

/// The parent folder, like Split-Path -Parent ("C:\a\b.exe" -> "C:\a", "C:\b.exe" -> "C:\").
pub fn parent(path: &str) -> String {
    match path.rfind('\\') {
        Some(i) if i == 2 && path.as_bytes().get(1) == Some(&b':') => path[..3].to_string(),
        Some(i) => path[..i].to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_folders_any_case() {
        assert!(user_writable("C:\\ProgramData\\x\\a.exe"));
        assert!(user_writable("c:\\programdata\\x\\a.exe"));
        assert!(user_writable("C:\\Users\\Bob\\AppData\\Roaming\\a.exe"));
        assert!(user_writable("D:\\Users\\Public\\x.exe"));
        assert!(!user_writable("C:\\Program Files\\x\\a.exe"));
        assert!(!user_writable("C:\\Windows\\System32\\a.exe"));
        assert!(!user_writable("C:\\Users\\Bob\\Music\\a.exe"));
    }

    #[test]
    fn program_path_matches_powershell() {
        assert_eq!(program_path("\"C:\\A B\\x.exe\" -arg").as_deref(), Some("C:\\A B\\x.exe"));
        assert_eq!(program_path("C:\\a\\x.EXE /s").as_deref(), Some("C:\\a\\x.EXE"));
        assert_eq!(program_path("C:\\a\\x.dll,Entry").as_deref(), Some("C:\\a\\x.dll"));
        assert_eq!(program_path("C:\\a\\x.exe").as_deref(), Some("C:\\a\\x.exe"));
        assert_eq!(program_path("notepad"), None);
        assert_eq!(program_path(""), None);
        // Two quotes in a row: PowerShell's "$end -gt 1" fails and the pattern runs on
        // the raw text, quotes and all. Kept as-is: it is what the engine has always done.
        assert_eq!(program_path("\"\"C:\\x.exe"), Some("\"\"C:\\x.exe".to_string()));
        let sys = program_path("%SystemRoot%\\System32\\svchost.exe -k x").unwrap();
        assert!(sys.to_lowercase().ends_with("\\system32\\svchost.exe") && !sys.contains('%'));
    }

    #[test]
    fn hosts_and_their_targets() {
        assert!(is_host("C:\\Windows\\System32\\RUNDLL32.EXE"));
        assert!(!is_host("C:\\Windows\\System32\\notepad.exe"));
        assert_eq!(target_from_args("rundll32 \"C:\\ProgramData\\q\\x.dll\",Run").as_deref(), Some("C:\\ProgramData\\q\\x.dll"));
        assert_eq!(target_from_args("/s nothing"), None);
    }

    #[test]
    fn random_names_same_verdicts_as_selftest() {
        for n in ["kLmQzRtPx8", "qXkRzTwP4m", "deadbeefcafebabe0123", "DEADBEEFCAFEBABE0123"] {
            assert!(is_random_name(n), "{n}");
        }
        for n in ["CustomCursor", "OneDrive", "iCloudDrive", "MediaPlayer", "Tailscale", "ZohoMeeting", "nodejs"] {
            assert!(!is_random_name(n), "{n}");
        }
    }

    #[test]
    fn org_and_vendor_word() {
        assert_eq!(org_from_subject("CN=Contoso Ltd, O=Contoso Ltd, L=X, C=US"), "Contoso Ltd");
        assert_eq!(org_from_subject("CN=Solo Dev"), "Solo Dev");
        assert_eq!(org_from_subject("CN=\"Acme, Inc.\", O=\"Acme, Inc.\", C=US"), "Acme");
        assert_eq!(org_from_subject(""), "");
        assert_eq!(vendor_word("Microsoft Corporation").as_deref(), Some("Microsoft"));
        assert_eq!(vendor_word("HP Inc."), None);
        assert_eq!(vendor_word("Zoom Video (US)").as_deref(), Some("Zoom"));
    }

    #[test]
    fn kernel_style_paths() {
        let w = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into()).to_lowercase();
        assert_eq!(program_path_ext(r"\SystemRoot\System32\drivers\x.sys").unwrap().to_lowercase(), format!(r"{w}\system32\drivers\x.sys"));
        assert_eq!(program_path_ext(r"System32\drivers\x.sys").unwrap().to_lowercase(), format!(r"{w}\system32\drivers\x.sys"));
        assert_eq!(program_path_ext(r"\??\C:\a\b.sys").as_deref(), Some(r"C:\a\b.sys"));
        assert_eq!(program_path_ext("explorer.exe").as_deref(), Some("explorer.exe"));
        assert_eq!(program_path_ext("/UserInstall").as_deref(), Some("/UserInstall"));
        assert_eq!(program_path_ext("  "), None);
    }

    #[test]
    fn paths() {
        assert_eq!(parent("C:\\a\\b\\c.exe"), "C:\\a\\b");
        assert_eq!(parent("C:\\c.exe"), "C:\\");
        assert_eq!(leaf("C:\\a\\Folder"), "Folder");
        assert_eq!(leaf("C:\\a\\Folder\\"), "Folder");
        assert!(payload_ext("INTRO.WAV") && !payload_ext("a.exe"));
        assert!(program_ext("x.Dll") && !program_ext("x.vbs"));
    }
}
