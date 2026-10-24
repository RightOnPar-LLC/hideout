//! Differential fuzz of the statement reader: thousands of mutated bank statements go
//! through BOTH engines - app/src/money/statement.mjs (via Node) and hideout-money - and
//! every result is compared in full. A difference is accepted only with proof: undo the
//! one cause it is put down to, and the two engines must then agree.

use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::Command;

pub const KNOWN: &[(&str, &str)] = &[(
    "full-month-names",
    "statement.mjs looked up a month by its first FOUR letters, so dates written with a full month name (\"June 1, 2026\", \"July\", \"March\") came back unreadable and their rows were skipped. The Rust engine reads them. (Proven: with every full month name shortened to three letters, the two engines agree.)",
)];

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
}

const PIECES: &[&str] = &[",", "\"", "\n", "\r\n", "\t", ";", "-", "(", ")", "$", ".", "0", "9", "1234567890123", "/", " ", "Date", "Amount", "Description", "Debit", "Credit", "June", "Sep", "July 4, 2026", "03 March 2026", "2026-02-30", "ZELLE", "AUTOPAY", "\"\""];

fn mutate(rng: &mut Rng, base: &str) -> String {
    let mut s: Vec<char> = base.chars().collect();
    for _ in 0..(1 + rng.below(8)) {
        match rng.below(5) {
            0 if !s.is_empty() => {
                let i = rng.below(s.len());
                s.remove(i);
            }
            1 => {
                let i = rng.below(s.len() + 1);
                for (k, c) in PIECES[rng.below(PIECES.len())].chars().enumerate() {
                    s.insert(i + k, c);
                }
            }
            2 if s.len() > 2 => {
                let n = rng.below(s.len());
                s.truncate(n);
            }
            3 if !s.is_empty() => {
                let i = rng.below(s.len());
                s[i] = char::from_u32(32 + rng.below(95) as u32).unwrap_or('x');
            }
            _ => {
                let text: String = s.iter().collect();
                let lines: Vec<String> = text.split('\n').map(String::from).collect();
                if lines.len() > 1 {
                    let mut v = lines.clone();
                    v.insert(rng.below(lines.len()), lines[rng.below(lines.len())].clone());
                    s = v.join("\n").chars().collect();
                }
            }
        }
    }
    s.into_iter().collect()
}

/// Every full month name (4+ letters starting like a month) cut to three letters.
fn shorten_months(s: &str) -> String {
    let months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let mut out = String::new();
    let mut word = String::new();
    let flush = |w: &mut String, out: &mut String| {
        let l = w.to_ascii_lowercase();
        if w.len() >= 4 && w.chars().all(|c| c.is_ascii_alphabetic()) && months.iter().any(|m| l.starts_with(m)) && !l.starts_with("sept") {
            out.push_str(&w[..3]);
        } else {
            out.push_str(w);
        }
        w.clear();
    };
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).map(|w| same(v, w)).unwrap_or(false)),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q)),
        _ => a == b,
    }
}

fn js_parse(repo: &Path, work: &Path, inputs: &[(usize, String)]) -> Result<Vec<Value>, String> {
    let inf = work.join("money-in.jsonl");
    let outf = work.join("money-out.jsonl");
    let mut f = std::fs::File::create(&inf).map_err(|e| e.to_string())?;
    for (id, t) in inputs {
        writeln!(f, "{}", json!({"id": id, "text": t})).map_err(|e| e.to_string())?;
    }
    drop(f);
    let st = Command::new("node").arg(repo.join("rust").join("tools").join("money-golden.mjs")).arg("parse").arg(&inf).arg(&outf).status().map_err(|e| format!("node: {e}"))?;
    if !st.success() {
        return Err(format!("node exited {st}"));
    }
    let mut by_id = vec![Value::Null; inputs.len()];
    for line in std::io::BufReader::new(std::fs::File::open(&outf).map_err(|e| e.to_string())?).lines() {
        let v: Value = serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        if let Some(i) = v["id"].as_u64() {
            by_id[i as usize] = v["r"].clone();
        }
    }
    Ok(by_id)
}

pub fn run(repo: &Path, work: &Path, cases: usize) -> i32 {
    let fixtures = repo.join("rust").join("crates").join("hideout-money").join("tests").join("fixtures");
    let bases: Vec<String> = ["chase.csv", "amex.csv", "capone.csv", "bofa.csv", "wells.csv"].iter().filter_map(|f| std::fs::read_to_string(fixtures.join(f)).ok()).collect();
    if bases.len() != 5 {
        eprintln!("hideout-parity: bank fixtures missing under {}", fixtures.display());
        return 2;
    }
    let mut rng = Rng(0xD1FF_5EED_0000_0042);
    let mut inputs: Vec<(usize, String)> = (0..cases).map(|i| (i, if i < 5 { bases[i].clone() } else { mutate(&mut rng, &bases[i % 5]) })).collect();
    // Seeded cases that MUST differ (dates with full month names), so the run proves it
    // notices a difference and that the explanation only applies when its proof holds.
    let n = inputs.len();
    inputs.push((n, "Date,Description,Amount\n\"June 1, 2026\",NETFLIX.COM,-15.49\n\"July 1, 2026\",NETFLIX.COM,-15.49\n\"August 1, 2026\",NETFLIX.COM,-15.49\n".into()));
    inputs.push((n + 1, "Date,Description,Amount\n01 March 2026,ADOBE,54.99\n01 April 2026,ADOBE,54.99\n".into()));
    let seeded = 2usize;
    let t0 = std::time::Instant::now();
    let js = match js_parse(repo, work, &inputs) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("hideout-parity: the JavaScript engine did not run: {e}");
            return 2;
        }
    };
    let js_secs = t0.elapsed().as_secs_f64();
    let rust: Vec<Value> = inputs.iter().map(|(_, t)| serde_json::to_value(hideout_money::statement::parse_statement(t)).unwrap_or(Value::Null)).collect();
    let mut diffs: Vec<(usize, Option<&str>)> = Vec::new();
    let mut retest: Vec<(usize, String)> = Vec::new();
    for (i, (j, r)) in js.iter().zip(&rust).enumerate() {
        if !same(j, r) {
            diffs.push((i, None));
            retest.push((i, shorten_months(&inputs[i].1)));
        }
    }
    // Proof for each difference: with full month names shortened, do they agree?
    if !retest.is_empty() {
        let renumbered: Vec<(usize, String)> = retest.iter().enumerate().map(|(k, (_, t))| (k, t.clone())).collect();
        let js2 = js_parse(repo, work, &renumbered).unwrap_or_default();
        for (k, (i, t)) in retest.iter().enumerate() {
            let r2 = serde_json::to_value(hideout_money::statement::parse_statement(t)).unwrap_or(Value::Null);
            let changed = *t != inputs[*i].1;
            if changed && js2.get(k).map(|j| same(j, &r2)).unwrap_or(false) {
                if let Some(d) = diffs.iter_mut().find(|d| d.0 == *i) {
                    d.1 = Some("full-month-names");
                }
            }
        }
    }
    let unexplained: Vec<&(usize, Option<&str>)> = diffs.iter().filter(|d| d.1.is_none()).collect();
    println!("money differential: {} statements through both engines ({cases} mutated + {seeded} seeded; js {js_secs:.1}s); {} differ, {} explained, {} UNEXPLAINED", inputs.len(), diffs.len(), diffs.len() - unexplained.len(), unexplained.len());
    for (id, why) in KNOWN {
        let n = diffs.iter().filter(|d| d.1 == Some(*id)).count();
        if n > 0 {
            println!("  explained {id} ({n}): {why}");
        }
    }
    // The seeded cases must have been caught AND explained - otherwise the run proves nothing.
    let caught = (inputs.len() - seeded..inputs.len()).all(|i| diffs.iter().any(|d| d.0 == i && d.1 == Some("full-month-names")));
    if !caught {
        println!("  FAIL: the seeded full-month-name statements were not caught and explained - the comparison is not working");
        return 1;
    }
    for (i, _) in unexplained.iter().take(5) {
        let t = &inputs[*i].1;
        println!("  UNEXPLAINED #{i}: input {:?}\n    js:   {}\n    rust: {}", t.chars().take(300).collect::<String>(), js[*i].to_string().chars().take(400).collect::<String>(), rust[*i].to_string().chars().take(400).collect::<String>());
    }
    if unexplained.is_empty() { 0 } else { 1 }
}
