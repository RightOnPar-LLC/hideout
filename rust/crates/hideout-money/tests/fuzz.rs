//! Fuzz: statement files of every bad shape must give rows or a warning - never a panic,
//! never a row with an impossible date or a negative amount, and never an account number.

use hideout_money::statement::parse_statement;
use std::path::PathBuf;

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

const PIECES: &[&str] = &[",", "\"", "\n", "\r\n", "\t", ";", "-", "(", ")", "$", ".", "0", "9", "1234567890123", "/", " ", "Date", "Amount", "Description", "Debit", "Credit", "\u{FEFF}", "€", "June", "Sep", "2026-02-30", "12/31/1999", "ZELLE", "AUTOPAY", "\"\"", "\u{2028}", "é", "💳", "99999999999999999999.99"];

fn mutate(rng: &mut Rng, base: &str) -> String {
    let mut s: Vec<char> = base.chars().collect();
    for _ in 0..(1 + rng.below(12)) {
        match rng.below(6) {
            0 if !s.is_empty() => {
                let i = rng.below(s.len());
                s.remove(i);
            }
            1 => {
                let i = rng.below(s.len() + 1);
                let p: Vec<char> = PIECES[rng.below(PIECES.len())].chars().collect();
                for (k, c) in p.into_iter().enumerate() {
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
            4 => {
                let text: String = s.iter().collect();
                let lines: Vec<&str> = text.split('\n').collect();
                if lines.len() > 1 {
                    let i = rng.below(lines.len());
                    let mut v: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
                    v.insert(i, lines[rng.below(lines.len())].to_string());
                    s = v.join("\n").chars().collect();
                }
            }
            _ => {
                let i = rng.below(s.len() + 1);
                for _ in 0..rng.below(40) {
                    s.insert(i, char::from_u32(rng.below(0x3000) as u32).unwrap_or('?'));
                }
            }
        }
    }
    s.into_iter().collect()
}

#[test]
fn ten_thousand_mutated_statements_never_panic() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures");
    let bases: Vec<String> = ["chase.csv", "amex.csv", "capone.csv", "bofa.csv", "wells.csv"].iter().map(|f| std::fs::read_to_string(dir.join(f)).unwrap()).collect();
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    let mut with_rows = 0;
    for i in 0..12_000 {
        let text = if i % 50 == 0 { (0..rng.below(4000)).map(|_| char::from_u32(rng.below(0x800) as u32).unwrap_or('?')).collect() } else { mutate(&mut rng, &bases[i % bases.len()]) };
        let r = std::panic::catch_unwind(|| parse_statement(&text));
        let p = r.unwrap_or_else(|_| panic!("panic on input #{i}: {text:?}"));
        if !p.rows.is_empty() {
            with_rows += 1;
        } else {
            assert!(!p.warnings.is_empty() || p.format == "header" || p.format == "inferred", "#{i}: no rows and no word why");
        }
        for row in &p.rows {
            assert!(row.amount > 0.0 && row.amount.is_finite(), "#{i}: amount {}", row.amount);
            assert!(hideout_money::money::valid_date(&row.date, None), "#{i}: date {}", row.date);
            assert!(!row.descriptor.chars().filter(|c| c.is_ascii_digit()).collect::<String>().contains("12345678901"), "#{i}: a long number survived masking: {}", row.descriptor);
            assert!(row.descriptor.chars().count() <= 120);
        }
    }
    assert!(with_rows > 3000, "the mutations should still mostly be statements ({with_rows})");
}

#[test]
fn huge_inputs_are_capped() {
    let mut s = String::from("Date,Description,Amount\n");
    for i in 0..20_000 {
        s.push_str(&format!("2026-01-{:02},SHOP {},-1.00\n", 1 + i % 28, i % 300));
    }
    let p = parse_statement(&s);
    assert_eq!(p.rows.len(), hideout_money::statement::MAX_ROWS);
    assert!(p.warnings.iter().any(|w| w.contains("Only the first")));
}
