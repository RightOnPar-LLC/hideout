//! hideout-redact: everything Hideout sends to its AI guide passes through here first.
//!
//! Two layers, both tested:
//!
//! 1. **The type.** The guide sends [`Clean`] text and nothing else. A `Clean` can only be
//!    made by a [`Redactor`]: it has no public constructor, no `From`, no `Default` and no
//!    `Deserialize`, so code that tries to hand the guide a plain `String` does not compile.
//!    ```compile_fail
//!    let c = hideout_redact::Clean("C:\\Users\\jane\\x.exe".to_string());
//!    ```
//!    ```compile_fail
//!    let c: hideout_redact::Clean = String::from("jane@example.com").into();
//!    ```
//!    ```compile_fail
//!    let c: hideout_redact::Clean = serde_json::from_str("\"4111 1111 1111 1111\"").unwrap();
//!    ```
//!    ```compile_fail
//!    let c: hideout_redact::Clean = Default::default();
//!    ```
//!    The negative control: the same doctest setup compiles when the redactor makes it
//!    (so the four above fail for the reason they claim, not a missing crate).
//!    ```
//!    let r = hideout_redact::Redactor::new(&hideout_redact::Identity { names: vec!["jane".into()], ..Default::default() });
//!    let c: hideout_redact::Clean = r.text("C:\\Users\\jane\\x.exe");
//!    assert_eq!(c.as_str(), "C:\\Users\\<you>\\x.exe");
//!    let s: String = serde_json::from_str("\"4111 1111 1111 1111\"").unwrap();
//!    assert_eq!(r.text(&s).as_str(), "[removed: card number]");
//!    ```
//! 2. **The redactor itself**, which also runs one last time over the whole request just
//!    before it leaves the PC ([`Redactor::leaks`]): if anything it would remove is still
//!    there, the request is not sent.
//!
//! What it removes: the Windows account names and profile folders on this PC, the PC's
//! name, the person's display name, card numbers, account and other long numbers, keys and
//! tokens, recovery (seed) phrases, private keys, email addresses (except the companies'
//! own cancellation addresses from Hideout's directory), and passwords or one-time codes
//! typed into the chat. Placeholders keep the text readable ("C:\Users\<you>\AppData\...").
//!
//! The first four steps (profile folders, PC name, account names, long tokens) are a
//! line-for-line port of app/src/redact.mjs; [`Redactor::js_compatible`] runs only those,
//! so a differential test can hold the two engines to the same output. No `unsafe`.

#![forbid(unsafe_code)]

use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

/// Text that went through a [`Redactor`]. The only thing the guide's request is built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clean(String);

impl Clean {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for Clean {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// Who and what to remove. Built on the PC from its own accounts (see hideout-win).
#[derive(Clone, Debug, Default)]
pub struct Identity {
    /// Windows account names, profile folder names, and the parts of the display name.
    pub names: Vec<String>,
    /// This PC's name.
    pub computer: String,
    /// Addresses that are not personal and may stay: the cancellation addresses companies
    /// publish, from Hideout's own directory.
    pub allowed_emails: Vec<String>,
}

/// Names that are folder names on many PCs but are ordinary words, not anyone's identity.
/// They are still replaced in a profile path (C:\Users\user\...) but not as bare words,
/// or "run from user folders" would read "run from <you> folders".
const NOISE: [&str; 14] = ["user", "users", "admin", "administrator", "guest", "test", "default", "public", "owner", "service", "temp", "home", "this", "you"];

fn word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn pc_char(c: char) -> bool {
    word_char(c) || c == '-'
}

/// JavaScript's `\s` (which includes U+FEFF).
fn js_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{FEFF}'
}

/// Does `s[i..]` start with `pat`, ignoring case? Returns the end byte index.
fn starts_ci(s: &str, i: usize, pat: &[char]) -> Option<usize> {
    let mut it = s[i..].char_indices();
    for p in pat {
        let (_, c) = it.next()?;
        if !c.to_lowercase().eq(p.to_lowercase()) {
            return None;
        }
    }
    Some(it.next().map(|(j, _)| i + j).unwrap_or(s.len()))
}

fn prev_char(s: &str, i: usize) -> Option<char> {
    s[..i].chars().next_back()
}

fn next_char(s: &str, i: usize) -> Option<char> {
    s[i..].chars().next()
}

/// Replace whole-word, case-insensitive matches of `names` (tried longest first at each
/// position, like a JavaScript alternation sorted by length) where `ok_before` and
/// `ok_after` accept the neighbouring characters.
fn replace_names(s: &str, names: &[Vec<char>], ok_before: impl Fn(Option<char>) -> bool, ok_after: impl Fn(Option<char>) -> bool, with: &str) -> String {
    if names.is_empty() {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut copied = 0;
    while i < s.len() {
        let mut hit = None;
        if ok_before(prev_char(s, i)) {
            for n in names {
                if let Some(end) = starts_ci(s, i, n) {
                    if ok_after(next_char(s, end)) {
                        hit = Some(end);
                        break;
                    }
                }
            }
        }
        match hit {
            Some(end) => {
                out.push_str(&s[copied..i]);
                out.push_str(with);
                i = end;
                copied = end;
            }
            None => i += next_char(s, i).map(char::len_utf8).unwrap_or(1),
        }
    }
    out.push_str(&s[copied..]);
    out
}

/// redact.mjs's profile rule: `([\\/]Users[\\/])(names)(?=[\\/]|$|["'\s])`, case-insensitive.
fn replace_profiles(s: &str, names: &[Vec<char>]) -> String {
    if names.is_empty() {
        return s.to_string();
    }
    const USERS: [char; 5] = ['u', 's', 'e', 'r', 's'];
    let slash = |c: Option<char>| matches!(c, Some('\\') | Some('/'));
    let mut out = String::with_capacity(s.len());
    let (mut i, mut copied) = (0, 0);
    while i < s.len() {
        let mut hit = None;
        if slash(next_char(s, i)) {
            if let Some(after_users) = starts_ci(s, i + 1, &USERS) {
                if slash(next_char(s, after_users)) {
                    let start = after_users + 1;
                    for n in names {
                        if let Some(end) = starts_ci(s, start, n) {
                            let next = next_char(s, end);
                            if next.map(|c| c == '\\' || c == '/' || c == '"' || c == '\'' || js_space(c)).unwrap_or(true) {
                                hit = Some((start, end));
                                break;
                            }
                        }
                    }
                }
            }
        }
        match hit {
            Some((start, end)) => {
                out.push_str(&s[copied..start]);
                out.push_str("<you>");
                i = end;
                copied = end;
            }
            None => i += next_char(s, i).map(char::len_utf8).unwrap_or(1),
        }
    }
    out.push_str(&s[copied..]);
    out
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid pattern"))
}

macro_rules! regex {
    ($p:expr) => {{
        static R: OnceLock<Regex> = OnceLock::new();
        re(&R, $p)
    }};
}

/// The BIP-39 English word list (2048 words; SHA-256 2f5eed53...4dbda, checked in a test).
const BIP39: &str = include_str!("../data/bip39-english.txt");

fn bip39() -> &'static HashSet<&'static str> {
    static W: OnceLock<HashSet<&'static str>> = OnceLock::new();
    W.get_or_init(|| BIP39.split_whitespace().collect())
}

/// Luhn checksum over the digits of `s`.
pub fn luhn(digits: &str) -> bool {
    let d: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() < 12 {
        return false;
    }
    let sum: u32 = d.iter().rev().enumerate().map(|(i, &x)| if i % 2 == 1 { let y = x * 2; if y > 9 { y - 9 } else { y } } else { x }).sum();
    sum.is_multiple_of(10)
}

pub struct Redactor {
    names: Vec<Vec<char>>,
    bare: Vec<Vec<char>>,
    computer: Vec<char>,
    allowed_emails: HashSet<String>,
    vocabulary: HashSet<String>,
    js_only: bool,
}

impl Redactor {
    pub fn new(id: &Identity) -> Redactor {
        let mut uniq: Vec<String> = Vec::new();
        for n in &id.names {
            if n.chars().count() >= 3 && !uniq.contains(n) {
                uniq.push(n.clone());
            }
        }
        // Longest first (stable for equal lengths), as redact.mjs sorts its alternation.
        uniq.sort_by_key(|n| std::cmp::Reverse(n.encode_utf16().count()));
        let names: Vec<Vec<char>> = uniq.iter().map(|n| n.chars().collect()).collect();
        let bare = uniq.iter().filter(|n| !NOISE.contains(&n.to_lowercase().as_str())).map(|n| n.chars().collect()).collect();
        let computer = if id.computer.chars().count() >= 3 { id.computer.chars().collect() } else { Vec::new() };
        Redactor { names, bare, computer, allowed_emails: id.allowed_emails.iter().map(|e| e.to_lowercase()).collect(), vocabulary: HashSet::new(), js_only: false }
    }

    /// Only redact.mjs's four rules, nothing more (for the differential test).
    pub fn js_compatible(id: &Identity) -> Redactor {
        let mut r = Redactor::new(id);
        r.bare = r.names.clone();
        r.js_only = true;
        r
    }

    /// Replace ordinary-word names ("user", "admin") as bare words too, as redact.mjs does.
    /// Only for the differential test's proof; the app never calls it.
    pub fn bare_noise_names(mut self) -> Redactor {
        self.bare = self.names.clone();
        self
    }

    /// Words the guide's own vocabulary uses that look like tokens to the long-token rule
    /// (a case-step id like "windows_security_folder_scan" is 28 characters). Exactly
    /// these strings are left alone.
    pub fn with_vocabulary<I: IntoIterator<Item = S>, S: Into<String>>(mut self, words: I) -> Redactor {
        self.vocabulary.extend(words.into_iter().map(Into::into));
        self
    }

    /// The redacted string, as a plain String. Used inside the redactor and by tests;
    /// the guide's request takes [`Clean`].
    pub fn scrub(&self, s: &str) -> String {
        if s.is_empty() {
            return String::new();
        }
        let mut r = s.to_string();
        if !self.js_only {
            r = regex!(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----|\z)").replace_all(&r, "[removed: private key]").into_owned();
            r = seed_phrases(&r);
            r = cards(&r);
            // Before the names, so an address with a name in it goes whole.
            r = regex!(r"(?i)[a-z0-9._%+\-]+@[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.[a-z]{2,}")
                .replace_all(&r, |m: &regex::Captures| if self.allowed_emails.contains(&m[0].to_lowercase()) { m[0].to_string() } else { "[removed: email]".to_string() })
                .into_owned();
        }
        // redact.mjs, in its order.
        r = replace_profiles(&r, &self.names);
        if !self.computer.is_empty() {
            r = replace_names(&r, std::slice::from_ref(&self.computer), |c| !c.map(pc_char).unwrap_or(false), |c| !c.map(pc_char).unwrap_or(false), "<this-pc>");
        }
        r = replace_names(&r, &self.bare, |c| !c.map(word_char).unwrap_or(false), |c| !c.map(word_char).unwrap_or(false), "<you>");
        r = regex!(r"[A-Za-z0-9+/=_\-.%]{28,}")
            .replace_all(&r, |m: &regex::Captures| {
                let t = &m[0];
                if !self.js_only && self.vocabulary.contains(t) {
                    t.to_string()
                } else {
                    format!("[redacted {} chars]", t.len())
                }
            })
            .into_owned();
        if self.js_only {
            return r;
        }
        r = regex!(r"(?:AKIA|ASIA)[0-9A-Z]{16}|(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}|xox[abprs]-[A-Za-z0-9\-]{8,}|gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_\-]{16,}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*").replace_all(&r, "[removed: key]").into_owned();
        r = regex!(r#"(?i)(?-u:\b)(password|passwd|pwd|passcode|passphrase|pass code)(\s*(?:is|was|:|=|-)\s*)("[^"]*"|'[^']*'|[^\s\[]\S*)"#).replace_all(&r, "$1$2[removed: password]").into_owned();
        r = regex!(r"(?i)(?-u:\b)(code|otp|pin)(?-u:\b)(\s*(?:is|was|:|=|-|#)?\s*)([0-9]{4,8})(?-u:\b)").replace_all(&r, "$1$2[removed: code]").into_owned();
        r = regex!(r"[0-9]{9,}").replace_all(&r, "[removed: number]").into_owned();
        r
    }

    /// Redact text for the guide.
    pub fn text(&self, s: &str) -> Clean {
        Clean(self.scrub(s))
    }

    /// Redact every string value in `v` (object keys come from Hideout's own code and are
    /// left as they are, like redact.mjs's deep()).
    pub fn value(&self, v: &serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        match v {
            Value::String(s) => Value::String(self.scrub(s)),
            Value::Array(a) => Value::Array(a.iter().map(|x| self.value(x)).collect()),
            Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), self.value(x))).collect()),
            // A number long enough to be an account number is removed like one in text.
            Value::Number(n) if !self.js_only && long_number(n) => Value::String("[removed: number]".into()),
            other => other.clone(),
        }
    }

    /// Redact a tool result and serialize it, as `JSON.stringify(redact.deep(out))`.
    pub fn json(&self, v: &serde_json::Value) -> Clean {
        Clean(self.value(v).to_string())
    }

    /// Would redaction change `s`? The last check before a request leaves the PC.
    pub fn leaks(&self, s: &str) -> bool {
        self.scrub(s) != s
    }

    /// Would redaction change anything in `v` (strings, and numbers long enough to be an
    /// account number)? A string that holds JSON (a tool result) is checked by its values,
    /// the way it was redacted, not by its escaped text. `skip` names keys whose values
    /// are opaque (signatures, ids).
    pub fn leaks_value(&self, v: &serde_json::Value, skip: &[&str]) -> bool {
        self.leaks_in(v, "", skip)
    }

    fn leaks_in(&self, v: &serde_json::Value, key: &str, skip: &[&str]) -> bool {
        use serde_json::Value;
        match v {
            Value::String(s) if skip.contains(&key) => {
                let _ = s;
                false
            }
            Value::String(s) => match serde_json::from_str::<Value>(s) {
                Ok(inner @ (Value::Object(_) | Value::Array(_))) => self.leaks_in(&inner, key, skip),
                _ => self.leaks(s),
            },
            Value::Number(n) => long_number(n),
            Value::Array(a) => a.iter().any(|x| self.leaks_in(x, key, skip)),
            Value::Object(o) => o.iter().any(|(k, x)| self.leaks_in(x, k, skip)),
            _ => false,
        }
    }
}

fn long_number(n: &serde_json::Number) -> bool {
    n.to_string().split(|c: char| !c.is_ascii_digit()).any(|run| run.len() >= 9)
}

/// Which kinds of secret a text holds (the leak look-up uses this on files the person
/// left lying around). Long random-looking strings alone are not counted - hashes and
/// encoded data are everywhere - only shapes that are secrets.
pub fn secret_kinds(s: &str) -> Vec<&'static str> {
    let mut k = Vec::new();
    if regex!(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY").is_match(s) {
        k.push("a private key");
    }
    // A phrase is 12 to 24 words; a longer run is a word list (wallet code ships the
    // whole 2048-word list), not someone's phrase.
    if seed_runs(s).iter().any(|r| (12..=24).contains(&r.2)) {
        k.push("a recovery phrase");
    }
    if regex!(r"(?:AKIA|ASIA)[0-9A-Z]{16}|(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}|xox[abprs]-[A-Za-z0-9\-]{8,}|gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_\-]{16,}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*|AIza[0-9A-Za-z_\-]{30,}").is_match(s) {
        k.push("an API key or token");
    }
    if regex!(r#"(?i)(?-u:\b)(password|passwd|pwd|passcode|passphrase)(\s*(?:is|was|:|=|-)\s*)("[^"]+"|'[^']+'|[^\s\[]\S*)"#).is_match(s) {
        k.push("a password");
    }
    if cards(s) != s {
        k.push("a card number");
    }
    k
}

/// Twelve or more recovery-phrase words in a row (separated by spaces, commas, numbering
/// or line breaks, never by other words) become one placeholder.
/// Runs of 12 or more recovery-phrase words in a row: (start, end, how many words).
fn seed_runs(s: &str) -> Vec<(usize, usize, usize)> {
    let words = bip39();
    let mut runs = Vec::new();
    let mut run: Option<(usize, usize, usize)> = None; // start, end, count
    for m in regex!(r"[A-Za-z]+").find_iter(s) {
        let in_list = words.contains(m.as_str().to_lowercase().as_str());
        run = match (run, in_list) {
            (Some((st, en, n)), true) if s[en..m.start()].chars().count() <= 8 => Some((st, m.end(), n + 1)),
            (prev, in_list) => {
                if let Some(r) = prev.filter(|r| r.2 >= 12) {
                    runs.push(r);
                }
                in_list.then(|| (m.start(), m.end(), 1))
            }
        };
    }
    if let Some(r) = run.filter(|r| r.2 >= 12) {
        runs.push(r);
    }
    runs
}

fn seed_phrases(s: &str) -> String {
    let runs = seed_runs(s);
    if runs.is_empty() {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut at = 0;
    for (st, en, _) in runs {
        out.push_str(&s[at..st]);
        out.push_str("[removed: recovery phrase]");
        at = en;
    }
    out.push_str(&s[at..]);
    out
}

/// Card numbers: groups of four (4-4-4-1..7), the 4-6-5 / 4-6-4 layout, or 13-19 digits
/// in a row that pass the Luhn check. (Other long digit runs are caught later as numbers.)
fn cards(s: &str) -> String {
    regex!(r"(?-u:\b)(?:[0-9]{4}(?:[ \-][0-9]{4}){2}[ \-][0-9]{1,7}|[0-9]{4}[ \-][0-9]{6}[ \-][0-9]{4,5}|[0-9]{13,19})(?-u:\b)")
        .replace_all(s, |m: &regex::Captures| {
            let t = &m[0];
            let digits = t.chars().filter(char::is_ascii_digit).count();
            let grouped = t.contains([' ', '-']);
            if (13..=19).contains(&digits) && (grouped || luhn(t)) {
                "[removed: card number]".to_string()
            } else {
                t.to_string()
            }
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::new(&Identity { names: vec!["jdoe".into(), "jane_doe".into()], computer: "HOME-PC".into(), allowed_emails: vec!["cancel@mailco.com".into()] })
    }

    #[test]
    fn selftest_r1_r2() {
        let red = r();
        let s = red.scrub(r"C:\Users\jdoe\AppData\x.exe ran as HOME-PC\jane_doe; key sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(!s.contains("jdoe") && !s.contains("HOME-PC") && !s.contains("jane_doe") && !s.contains("sk-ant-api03-A"), "{s}");
        assert!(s.contains(r"Users\<you>\AppData") && s.contains("<this-pc>"), "{s}");
        let d = red.value(&serde_json::json!({"a": [r"C:\Users\JDOE\x"], "b": {"c": "home-pc"}})).to_string().to_lowercase();
        assert!(!d.contains("jdoe") && !d.contains("home-pc"), "{d}");
    }

    #[test]
    fn word_list_is_the_published_one() {
        let words: Vec<&str> = BIP39.split_whitespace().collect();
        assert_eq!(words.len(), 2048);
        assert_eq!((words[0], words[2047]), ("abandon", "zoo"));
        assert!(words.windows(2).all(|w| w[0] < w[1]), "sorted, no duplicates");
    }

    #[test]
    fn placeholders_survive_a_second_pass() {
        let red = r();
        let once = red.scrub("card 4111 1111 1111 1111, jane@example.com, C:\\Users\\jdoe\\x");
        assert_eq!(red.scrub(&once), once);
        assert!(!red.leaks(&once));
    }

    #[test]
    fn noise_names_only_go_in_paths() {
        let red = Redactor::new(&Identity { names: vec!["user".into()], ..Default::default() });
        assert_eq!(red.scrub(r"C:\Users\user\x and 3 run from user folders"), r"C:\Users\<you>\x and 3 run from user folders");
        // redact.mjs replaces it everywhere; the JS-compatible mode does too.
        let js = Redactor::js_compatible(&Identity { names: vec!["user".into()], ..Default::default() });
        assert_eq!(js.scrub("run from user folders"), "run from <you> folders");
    }

    #[test]
    fn vocabulary_is_left_alone_only_when_named() {
        let red = r();
        assert_eq!(red.scrub("windows_security_folder_scan"), "[redacted 28 chars]");
        let red = red.with_vocabulary(["windows_security_folder_scan"]);
        assert_eq!(red.scrub("windows_security_folder_scan"), "windows_security_folder_scan");
        assert_eq!(red.scrub("windows_security_folder_scanX"), "[redacted 29 chars]");
    }
}
