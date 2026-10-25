//! Differential run of the redactor: thousands of random texts - profile paths, account
//! and PC names in every case and position, long tokens, BOMs, odd spaces, quotes -
//! through app/src/redact.mjs (via Node) and hideout-redact.
//!
//! Two bars:
//!   1. the port: hideout-redact limited to redact.mjs's four rules must give the SAME
//!      output as redact.mjs, every time, no exceptions
//!   2. the full redactor may differ only where one of its added rules fired, and each
//!      difference must name which one

use hideout_redact::{Identity, Redactor};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::Command;

pub const KNOWN: &[(&str, &str)] = &[
    ("new-shapes", "The Rust redactor also removes card numbers, account and other long numbers, keys with known prefixes, recovery phrases, private keys, email addresses and typed passwords or codes (\"[removed: ...]\"). redact.mjs let those through unless they happened to be 28+ token characters."),
    ("spec-vocabulary", "redact.mjs turned the guide's own case-step id \"windows_security_folder_scan\" (28 characters) into \"[redacted 28 chars]\", so the guide could not read that step back. The Rust redactor leaves exactly the spec's own words alone."),
    ("noise-names", "A profile folder named like an ordinary word (\"user\", \"admin\") is still replaced in a profile path, but not as a bare word, so \"run from user folders\" stays readable."),
];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[self.below(xs.len())]
    }
}

const NAMES: &[&str] = &["jdoe", "Jane", "mwilson", "J.Doe", "a+b", "Ünïcode", "sam", "Sam_2", "o'brien", "user", "admin", "jdoe2"];
const PCS: &[&str] = &["HOME-PC", "DESKTOP-7Q2ZK9L", "pc", "Kitchen.PC", "WORK_LAPTOP"];
const NEW_SHAPES: &[&str] = &["4111 1111 1111 1111", "000123456789", "jane.smith1984@gmail.com", "AKIAIOSFODNN7EXAMPLE", "my password is hunter2", "code: 482913", "army van defense carry jealous true garbage claim echo media make crunch", "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"];

fn piece(rng: &mut Rng, names: &[String], pc: &str) -> String {
    let n = || names.first().cloned().unwrap_or_default();
    let name = if names.is_empty() { "nobody".to_string() } else { names[rng.below(names.len())].clone() };
    let cased = match rng.below(3) {
        0 => name.to_uppercase(),
        1 => name.to_lowercase(),
        _ => name.clone(),
    };
    let sep = rng.pick(&["\\", "/"]);
    let sep2 = rng.pick(&["\\", "/"]);
    let users = rng.pick(&["Users", "users", "USERS", "Usersx", "Use"]);
    match rng.below(18) {
        0 => format!("C:{sep}{users}{sep2}{cased}{}", rng.pick(&["\\AppData\\x.exe", "/Desktop", "", "\"", "'", " ", "x", "-1", "\u{FEFF}", "\u{00A0}", "\t", ".old"])),
        1 => format!("{}{}{}", rng.pick(&["", " ", "x", "_", "-", "(", "\""]), cased, rng.pick(&["", " ", "x", "_", "-", ")", "\"", "."])),
        2 => format!("{}{}{}", rng.pick(&["", " ", "x", "_", "-", "\\\\"]), if rng.below(2) == 0 { pc.to_lowercase() } else { pc.to_string() }, rng.pick(&["", " ", "x", "_", "-", "\\share", ".", "2"])),
        3 => {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-.%";
            let len = 20 + rng.below(30);
            (0..len).map(|_| char::from(A[rng.below(A.len())])).collect()
        }
        4 => format!("sk-ant-api03-{}", "A".repeat(rng.below(40))),
        5 => rng.pick(&["\u{FEFF}", "\u{2028}", "\u{3000}", "  ", "\r\n", "\t"]).to_string(),
        6 => rng.pick(&["run from user folders", "admin rights", "<you>", "<this-pc>", "[redacted 5 chars]", "Hideout", "Windows Security"]).to_string(),
        7 => format!("{}{}", n(), n()),
        8 => rng.pick(&["get_deep_check_summary", "windows_security_folder_scan", "defender_offline_scan", "remoteAccessToolsInstalled"]).to_string(),
        9 if rng.below(6) == 0 => rng.pick(NEW_SHAPES).to_string(),
        10 => format!("{}@{}", cased, rng.pick(&["", "x", "example"])),
        _ => rng.pick(&["the ", "scan ", "found ", "a file ", "in ", "C:\\Program Files\\", "\\AppData\\Roaming\\", ", ", ". ", "12 ", "$15.49 ", "2026-08-14 ", "é ", "日本 "]).to_string(),
    }
}

fn js_redact(repo: &Path, work: &Path, cases: &[(usize, Vec<String>, String, String)]) -> Result<Vec<String>, String> {
    let inf = work.join("redact-in.jsonl");
    let outf = work.join("redact-out.jsonl");
    let mut f = std::fs::File::create(&inf).map_err(|e| e.to_string())?;
    for (id, names, pc, text) in cases {
        writeln!(f, "{}", json!({"id": id, "names": names, "computer": pc, "text": text})).map_err(|e| e.to_string())?;
    }
    drop(f);
    let st = Command::new("node").arg(repo.join("rust").join("tools").join("guide-golden.mjs")).arg("redact").arg(&inf).arg(&outf).status().map_err(|e| format!("node: {e}"))?;
    if !st.success() {
        return Err(format!("node exited {st}"));
    }
    let mut out = vec![String::new(); cases.len()];
    for line in std::io::BufReader::new(std::fs::File::open(&outf).map_err(|e| e.to_string())?).lines() {
        let v: Value = serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        out[v["id"].as_u64().unwrap_or(0) as usize] = v["r"].as_str().unwrap_or("").to_string();
    }
    Ok(out)
}

pub fn run(repo: &Path, work: &Path, n: usize) -> i32 {
    let mut rng = Rng(0x5EED_0F6E_ADC7);
    let vocab = hideout_guide::spec::vocabulary();
    let mut cases: Vec<(usize, Vec<String>, String, String)> = Vec::new();
    for i in 0..n {
        let k = 1 + rng.below(3);
        let names: Vec<String> = (0..k).map(|_| rng.pick(NAMES).to_string()).collect();
        let pc = rng.pick(PCS).to_string();
        let parts = 1 + rng.below(8);
        let text: String = (0..parts).map(|_| piece(&mut rng, &names, &pc)).collect();
        cases.push((i, names, pc, text));
    }
    // Seeded cases that MUST differ in full mode, one per explanation.
    let seeded: Vec<(Vec<String>, &str, &str)> = vec![
        (vec!["jdoe".into()], "HOME-PC", "card 4111 1111 1111 1111 for jdoe"),
        (vec!["jdoe".into()], "HOME-PC", "step windows_security_folder_scan done"),
        (vec!["user".into()], "HOME-PC", r"C:\Users\user\x and 3 run from user folders"),
    ];
    for (names, pc, t) in &seeded {
        let id = cases.len();
        cases.push((id, names.clone(), pc.to_string(), t.to_string()));
    }
    let t0 = std::time::Instant::now();
    let js = match js_redact(repo, work, &cases) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("hideout-parity: the JavaScript redactor did not run: {e}");
            return 2;
        }
    };
    let js_secs = t0.elapsed().as_secs_f64();
    let mut port_diffs = Vec::new();
    let mut full_diffs: Vec<(usize, Option<&str>)> = Vec::new();
    for (i, (_, names, pc, text)) in cases.iter().enumerate() {
        let id = Identity { names: names.clone(), computer: pc.clone(), allowed_emails: vec![] };
        let port = Redactor::js_compatible(&id).scrub(text);
        if port != js[i] {
            port_diffs.push(i);
        }
        let full = Redactor::new(&id).with_vocabulary(vocab.clone()).scrub(text);
        if full != js[i] {
            // Each explanation is proven by turning that one rule off: the full redactor
            // without it must then give exactly redact.mjs's answer.
            let without_vocab = Redactor::new(&id).scrub(text);
            let without_noise = Redactor::new(&id).with_vocabulary(vocab.clone()).bare_noise_names().scrub(text);
            let why = if full.contains("[removed: ") {
                Some("new-shapes")
            } else if without_vocab != full && Redactor::new(&id).bare_noise_names().scrub(text) == js[i] {
                Some("spec-vocabulary")
            } else if without_noise != full && without_noise == js[i] {
                Some("noise-names")
            } else {
                None
            };
            full_diffs.push((i, why));
        }
    }
    let unexplained: Vec<usize> = full_diffs.iter().filter(|d| d.1.is_none()).map(|d| d.0).collect();
    println!("redact differential: {} texts through both engines ({n} random + {} seeded; js {js_secs:.1}s)", cases.len(), seeded.len());
    println!("  the port (redact.mjs's rules only): {} differ", port_diffs.len());
    println!("  the full redactor: {} differ, {} explained, {} UNEXPLAINED", full_diffs.len(), full_diffs.len() - unexplained.len(), unexplained.len());
    for (id, why) in KNOWN {
        let k = full_diffs.iter().filter(|d| d.1 == Some(*id)).count();
        if k > 0 {
            println!("  explained {id} ({k}): {why}");
        }
    }
    let first_seeded = cases.len() - seeded.len();
    for (k, why) in ["new-shapes", "spec-vocabulary", "noise-names"].iter().enumerate() {
        let got = full_diffs.iter().find(|d| d.0 == first_seeded + k).map(|d| d.1);
        if got != Some(Some(*why)) {
            println!("  FAIL: seeded case {k} should be explained as {why}, got {got:?} - the comparison is not working");
            return 1;
        }
    }
    for i in port_diffs.iter().chain(unexplained.iter()).take(5) {
        let (_, names, pc, text) = &cases[*i];
        let id = Identity { names: names.clone(), computer: pc.clone(), allowed_emails: vec![] };
        println!("  DIFF #{i} names {names:?} pc {pc:?}\n    in:   {text:?}\n    js:   {:?}\n    port: {:?}\n    full: {:?}", js[*i], Redactor::js_compatible(&id).scrub(text), Redactor::new(&id).with_vocabulary(vocab.clone()).scrub(text));
    }
    if port_diffs.is_empty() && unexplained.is_empty() {
        0
    } else {
        1
    }
}
