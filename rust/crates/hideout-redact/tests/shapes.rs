//! The gate: every known secret shape is removed (100%, listed one by one), ordinary
//! text a person needs is left alone, and randomised personal data never survives.

use hideout_redact::{luhn, Identity, Redactor};

fn red() -> Redactor {
    Redactor::new(&Identity {
        names: vec!["jdoe".into(), "Jane".into(), "Doe".into(), "mwilson".into(), "user".into()],
        computer: "DESKTOP-7Q2ZK9L".into(),
        allowed_emails: vec!["cancel@mailco.com".into()],
    })
}

/// (shape, secret, sentence carrying it)
fn corpus() -> Vec<(&'static str, &'static str, String)> {
    let mut c: Vec<(&str, &str, String)> = Vec::new();
    let mut add = |shape: &'static str, secret: &'static str, ctx: &[&str]| {
        for t in ctx {
            c.push((shape, secret, t.replace("{}", secret)));
        }
    };
    let around = ["{}", "my card is {} thanks", "CARD {} TECH SUPPORT LLC", "\"{}\"", "({})", "x\n{}\ny", "value={};"];
    for card in ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111", "5500 0000 0000 0004", "3400 000000 00009", "378282246310005", "6011111111111117", "4012888888881881", "4222222222222", "5105105105105100", "4000056655665556", "4242 4242 4242 4242 123"] {
        add("card", card, &around);
    }
    for acct in ["000123456789", "021000021", "12345678901234567", "5829301746", "987654321"] {
        add("account", acct, &["WIRE TO ACCT {} ROUTING", "account {}", "Conf# {}", "{}"]);
    }
    // A live-key prefix is assembled at run time, so the source never holds a whole
    // key-shaped literal for secret scanners to flag (it is a made-up value).
    let live: &'static str = Box::leak([["sk", "live"].join("_"), "_FAKEfake0000TESTtest00".into()].concat().into_boxed_str());
    for key in [
        "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sk-proj-abcdEFGH1234ijkl",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
        "xoxb-1234-abcdefgh",
        live,
        "rk_test_abcdefgh1234",
        "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",
        "0123456789abcdef0123456789abcdef",
    ] {
        add("key", key, &["key {}", "export API_KEY={}", "{}", "token: '{}'"]);
    }
    for tok in ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123def456", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ4In0.c2lnbmF0dXJl", "ya29.a0AfH6SMBx-very-long-oauth-token-value-123"] {
        add("token", tok, &["Bearer {}", "{}", "cookie session={}"]);
    }
    for seed in [
        "abandon ability able about above absent absorb abstract absurd abuse access accident",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "1. army 2. van 3. defense 4. carry 5. jealous 6. true 7. garbage 8. claim 9. echo 10. media 11. make 12. crunch",
        "Army Van Defense Carry Jealous True Garbage Claim Echo Media Make Crunch",
    ] {
        add("seed", seed, &["my recovery phrase is {}", "{}", "seed:\n{}\n"]);
    }
    for email in ["jane.smith1984@gmail.com", "J.Doe+bank@Outlook.com", "someone@sub.example.co.uk"] {
        add("email", email, &["email me at {}", "<{}>", "{}"]);
    }
    for pc in ["DESKTOP-7Q2ZK9L", "desktop-7q2zk9l"] {
        add("pc", pc, &["ran as {}\\jdoe", "{}", "computer {} is mine", r"\\{}\share"]);
    }
    for name in ["jdoe", "JDOE", "Jane", "mwilson"] {
        add("name", name, &[r"C:\Users\{}\AppData\Roaming\x.exe", "my name is {}", "{}", "C:/Users/{}/Desktop", "signed {}."]);
    }
    for pk in ["-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAKC\n-----END RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r"] {
        add("private-key", pk, &["{}", "here:\n{}\nok"]);
    }
    for pw in ["hunter2", "Tr0ub4dor&3", "\"correct horse\""] {
        add("password", pw, &["my password is {}", "password: {}", "Password={}", "passcode - {}"]);
    }
    for code in ["482913", "1234", "90210777"] {
        add("code", code, &["the code is {}", "code: {}", "OTP {}", "pin {}"]);
    }
    c
}

fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

#[test]
fn every_known_shape_is_removed() {
    let r = red();
    let corpus = corpus();
    let mut by_shape: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    let mut misses = Vec::new();
    for (shape, secret, text) in &corpus {
        let out = r.scrub(text);
        let e = by_shape.entry(shape).or_default();
        e.0 += 1;
        let survived_plain = out.to_lowercase().contains(&secret.to_lowercase().trim_matches('"').to_string());
        // For number shapes, not even the digits may survive with separators removed.
        let numeric = matches!(*shape, "card" | "account" | "code");
        let survived_digits = numeric && digits(&out).contains(&digits(secret));
        // A seed phrase: no more than two of its words in a row may survive.
        let survived_seed = *shape == "seed" && secret.split_whitespace().filter(|w| w.chars().all(char::is_alphabetic)).collect::<Vec<_>>().windows(3).any(|w| out.to_lowercase().contains(&w.join(" ").to_lowercase()));
        if survived_plain || survived_digits || survived_seed {
            misses.push(format!("[{shape}] {text:?} -> {out:?}"));
        } else {
            e.1 += 1;
        }
    }
    for (shape, (n, ok)) in &by_shape {
        println!("{shape:12} {ok}/{n}");
    }
    assert!(misses.is_empty(), "{} of {} not removed:\n{}", misses.len(), corpus.len(), misses.join("\n"));
    assert!(corpus.len() > 200, "the suite is not trivially small ({})", corpus.len());
}

#[test]
fn what_a_person_needs_is_left_alone() {
    let r = red();
    for keep in [
        "$15.49 on 2026-09-01",
        "2026-08-14 2026-09-14 2026-10-14",
        "Netflix charged $17.99 every month",
        "card ending ••1746",
        "Call the number printed on the back of your card.",
        "Windows Security > Virus & threat protection > Scan options",
        "Write to cancel@mailco.com to cancel",
        "465 start-up items checked, 12 run from user folders",
        "Your PIN is never needed for a refund.",
        "C:\\Program Files\\Hideout\\hideout.exe",
        "I called my bank and they said the code would arrive soon",
        "Remember: about above all, abandon nothing.",
        "Version 10.0.26200",
        "[Your name] · [Last 4 digits of card] · [Confirmation number]",
        "Total since 2026-08-14: $4,299.98 across 5 payments",
    ] {
        assert_eq!(r.scrub(keep), keep, "changed something it should not");
    }
}

#[test]
fn luhn_is_the_real_checksum() {
    assert!(luhn("4111111111111111"));
    assert!(!luhn("4111111111111112"));
    assert!(luhn("378282246310005"));
}

// ---------------------------------------------------------------- property tests

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
    fn digits(&mut self, n: usize) -> String {
        (0..n).map(|i| char::from(b'0' + if i == 0 { 1 + self.below(9) as u8 } else { self.below(10) as u8 })).collect()
    }
    fn alnum(&mut self, n: usize) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        (0..n).map(|_| char::from(A[self.below(A.len())])).collect()
    }
    fn word(&mut self, lo: usize, hi: usize) -> String {
        const L: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        let n = lo + self.below(hi - lo + 1);
        (0..n).map(|_| char::from(L[self.below(26)])).collect()
    }
}

fn luhn_card(rng: &mut Rng, len: usize) -> String {
    let mut d: Vec<u32> = rng.digits(len - 1).chars().map(|c| c.to_digit(10).unwrap()).collect();
    for check in 0..10 {
        d.push(check);
        let s: String = d.iter().map(|x| char::from_digit(*x, 10).unwrap()).collect();
        if luhn(&s) {
            return s;
        }
        d.pop();
    }
    unreachable!()
}

/// One random piece of personal data, and what must not survive (plain, and as digits).
fn secret(rng: &mut Rng, id: &Identity) -> (String, Vec<String>, Vec<String>) {
    match rng.below(10) {
        0 => {
            let len = *rng.pick(&[13, 15, 16, 16, 16, 19]);
            let c = luhn_card(rng, len);
            let shown = match rng.below(3) {
                0 => c.clone(),
                1 if c.len() == 16 => c.as_bytes().chunks(4).map(|g| std::str::from_utf8(g).unwrap()).collect::<Vec<_>>().join(" "),
                _ if c.len() == 16 => c.as_bytes().chunks(4).map(|g| std::str::from_utf8(g).unwrap()).collect::<Vec<_>>().join("-"),
                _ => c.clone(),
            };
            (shown, vec![], vec![c])
        }
        1 => {
            let len = 9 + rng.below(9);
            let n = rng.digits(len);
            (n.clone(), vec![], vec![n])
        }
        2 => {
            let k = match rng.below(5) {
                0 => format!("sk-ant-api03-{}", rng.alnum(40)),
                1 => format!("AKIA{}", rng.alnum(16).to_uppercase()),
                2 => format!("ghp_{}", rng.alnum(36)),
                3 => format!("sk_live_{}", rng.alnum(24)),
                _ => {
                    let len = 28 + rng.below(40);
                    rng.alnum(len)
                }
            };
            (k.clone(), vec![k], vec![])
        }
        3 => {
            let t = format!("eyJ{}.eyJ{}.{}", rng.alnum(12), rng.alnum(20), rng.alnum(16));
            (t.clone(), vec![t], vec![])
        }
        4 => {
            let words: Vec<&str> = include_str!("../data/bip39-english.txt").split_whitespace().collect();
            let n = *rng.pick(&[12, 15, 18, 24]);
            let phrase: Vec<&str> = (0..n).map(|_| *rng.pick(&words)).collect();
            let sep = *rng.pick(&[" ", "  ", ", ", "\n"]);
            let p = phrase.join(sep);
            // No three of its words in a row may survive.
            let triples = phrase.windows(3).map(|w| w.join(sep)).collect();
            (p, triples, vec![])
        }
        5 => {
            let e = format!("{}.{}{}@{}.{}", rng.word(2, 8), rng.word(2, 8), rng.below(100), rng.word(3, 9), rng.pick(&["com", "net", "org", "co.uk"]));
            (e.clone(), vec![e], vec![])
        }
        6 => (id.computer.clone(), vec![id.computer.to_lowercase()], vec![]),
        7 => {
            let n = rng.pick(&id.names).clone();
            (format!(r"C:\Users\{n}\AppData\Local\{}\{}.exe", rng.word(4, 10), rng.word(3, 8)), vec![format!(r"\{}\", n.to_lowercase())], vec![])
        }
        8 => {
            let pw = format!("{}{}!", rng.word(5, 9), rng.below(1000));
            (format!("my password is {pw}"), vec![pw], vec![])
        }
        _ => {
            let code = rng.digits(6);
            (format!("the code is {code}"), vec![], vec![code])
        }
    }
}

#[test]
fn randomised_personal_data_never_survives() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut checked = 0;
    for round in 0..12_000 {
        let id = Identity { names: vec![format!("{}{}", rng.word(3, 8), rng.below(10)), rng.word(4, 9)], computer: format!("DESKTOP-{}", rng.alnum(7).to_uppercase()), allowed_emails: vec![] };
        let r = Redactor::new(&id);
        let (piece, plain, nums) = secret(&mut rng, &id);
        // Where the person's data turns up: their own words, a scan finding, a statement line.
        let wrapped = match rng.below(4) {
            0 => format!("{} {} {}", rng.word(3, 9), piece, rng.word(3, 9)),
            1 => serde_json::json!({"severity": "high", "folder": piece, "reasons": [{"tag": piece}]}).to_string(),
            2 => format!("2026-08-14,{} TECH SUPPORT,-299.99", piece.to_uppercase()),
            _ => piece.clone(),
        };
        let out = r.scrub(&wrapped).to_lowercase();
        for p in &plain {
            assert!(!out.contains(&p.to_lowercase()), "round {round}: {p:?} survived in {out:?}");
        }
        for n in &nums {
            assert!(!digits(&out).contains(n.as_str()), "round {round}: digits {n} survived in {out:?}");
        }
        // The guide's last check agrees there is nothing left.
        assert!(!r.leaks(&r.scrub(&wrapped)), "round {round}: second pass still finds something in {out:?}");
        checked += 1;
    }
    assert_eq!(checked, 12_000);
}

/// Negative control: the property harness does catch a redactor that misses a shape.
#[test]
fn the_property_harness_catches_a_miss() {
    let js_only = Redactor::js_compatible(&Identity::default());
    let mut rng = Rng(7);
    let card = luhn_card(&mut rng, 16);
    assert!(digits(&js_only.scrub(&format!("card {card}"))).contains(&card), "redact.mjs's rules alone let a card through");
}
