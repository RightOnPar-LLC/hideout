//! One real guide turn through the real door, with TEST data only, every byte that
//! leaves recorded - the request Frank inspects for the Phase 5 gate.
//!
//!   hideout-parity guide-capture --gateway https://<host> --out capture.json
//!
//! The person, the PC, the statement and the scan are all made up and full of planted
//! secrets (a card number, an account number, a key, an email, the test PC's name, the
//! test account's profile path). Nothing from this PC is used: the tools read the fake
//! scan and the fake statement. The capture also times the first word (the latency
//! budget: under 2 seconds on a normal connection) and lists any planted secret found in
//! the bytes sent (the gate: none).

use hideout_guide::guide::{Guide, Pc};
use hideout_guide::transport::{Gateway, TokenStore, Wire, WireFail};
use hideout_redact::{Identity, Redactor};
use hideout_win::https::{Door, Fail};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const NAME: &str = "jane.tester";
const PC_NAME: &str = "TEST-PC-0417";
const CARD: &str = "4111 1111 1111 1111";
const ACCOUNT: &str = "000123456789";
const KEY: &str = "sk-ant-api03-TESTTESTTESTTESTTESTTESTTESTTEST";
const EMAIL: &str = "jane.tester1984@example.com";

struct Capturing {
    door: Door,
    sent: Arc<Mutex<Vec<Value>>>,
    first_byte: Arc<Mutex<Option<Duration>>>,
    started: Instant,
}

impl Wire for Capturing {
    fn host(&self) -> String {
        self.door.host().to_string()
    }
    fn post(&self, path: &str, headers: &[(&str, &str)], body: &[u8], sink: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), WireFail> {
        // Header names only: the install pass is a credential and is not written down.
        self.sent.lock().unwrap().push(json!({"path": path, "headers": headers.iter().map(|h| h.0).collect::<Vec<_>>(), "body": String::from_utf8_lossy(body)}));
        let fb = self.first_byte.clone();
        let t0 = self.started;
        self.door
            .post(path, headers, body, &mut |b| {
                fb.lock().unwrap().get_or_insert(t0.elapsed());
                sink(b)
            })
            .map_err(|f| match f {
                Fail::Refused(w) => WireFail::Refused(w),
                Fail::Network(w) => WireFail::Network(w),
                Fail::Timeout => WireFail::Timeout,
                Fail::Status(s, b) => WireFail::Status(s, b),
                Fail::TooLarge => WireFail::TooLarge,
            })
    }
}

#[derive(Default)]
struct Mem(Mutex<Option<String>>);
impl TokenStore for Mem {
    fn load(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
    fn save(&self, t: &str) {
        *self.0.lock().unwrap() = Some(t.into());
    }
    fn clear(&self) {
        *self.0.lock().unwrap() = None;
    }
}

/// A made-up PC: one planted finding under the test account's profile.
struct TestPc;
impl Pc for TestPc {
    fn latest_scan(&self) -> Option<(Value, i64)> {
        Some((
            json!({"computer": PC_NAME, "admin": false, "checked": {"startItems": 465, "inUserFolders": 12, "couldNotCheck": []}, "defender": {"realtime": true, "lastFullScan": ""},
                "findings": [{"severity": "high", "kind": "Scheduled task", "name": format!("{PC_NAME} Updater"), "program": "MediaPlayerService.exe", "folder": format!(r"C:\Users\{NAME}\AppData\Roaming\kLmQzRtPx8"), "signer": "", "arrived": "2026-08-14 10:02",
                    "reasons": [{"tag": "Tampered file", "text": format!("Changed after signing; a note beside it holds {KEY}")}]}]}),
            4,
        ))
    }
    fn scan_running(&self) -> bool {
        false
    }
    fn run_job(&self, _k: &str, _w: Duration) -> Result<(), String> {
        Ok(())
    }
    fn latest_hunt(&self) -> Option<(Value, i64)> {
        None
    }
    fn leaks(&self) -> Option<Vec<Value>> {
        None
    }
    fn changed(&self) {}
    fn now(&self) -> String {
        "2026-10-24 12:00:00".into()
    }
}

pub fn run(gateway: &str, out: &std::path::Path, question: &str) -> i32 {
    let door = match Door::open(gateway, "Hideout-parity-capture") {
        Ok(d) => d,
        Err(e) => {
            eprintln!("guide-capture: {e}");
            return 2;
        }
    };
    let sent = Arc::new(Mutex::new(Vec::new()));
    let first_byte = Arc::new(Mutex::new(None));
    let started = Instant::now();
    let wire = Capturing { door, sent: sent.clone(), first_byte: first_byte.clone(), started };
    let money = Arc::new(Mutex::new(hideout_money::money::Money::new(None, Box::new(|| "2026-10-01".to_string()))));
    {
        let mut m = money.lock().unwrap();
        let stmt = format!(
            "Date,Description,Amount\n2026-07-01,NETFLIX.COM,-15.49\n2026-08-01,NETFLIX.COM,-15.49\n2026-09-01,NETFLIX.COM,-15.49\n2026-08-14,Zelle payment to SCAMMER Conf# 5829301746,-1500.00\n2026-08-14,WIRE TO ACCT {ACCOUNT} ROUTING 021000021,-2000.00\n2026-08-15,CARD {CARD} TECH SUPPORT LLC,-299.99\n2026-09-15,CARD {CARD} TECH SUPPORT LLC,-299.99\n"
        );
        m.import_statement("test.csv", &stmt);
        m.mark_canceled("netflix", "2026-08-05");
        m.set_incident("2026-08-14");
    }
    let red = Redactor::new(&Identity { names: vec![NAME.into(), "Jane".into(), "Tester".into()], computer: PC_NAME.into(), allowed_emails: vec![] });
    let guide = Guide::new(Some(Box::new(Gateway::new(Box::new(wire), Box::new(Mem::default())))), red, Arc::new(TestPc), money, Arc::new(|l| eprintln!("  log: {l}")));
    let mut events = Vec::new();
    let mut first_text: Option<Duration> = None;
    let t0 = Instant::now();
    guide.chat(question, &mut |e| {
        // The AI notice is written by Hideout itself; the guide's first word is the
        // first text after it.
        if e["type"] == "text" && first_text.is_none() && !e["delta"].as_str().unwrap_or("").starts_with("*I'm an AI guide") {
            first_text = Some(t0.elapsed());
        }
        events.push(e);
    });
    let total = t0.elapsed();
    let sent = sent.lock().unwrap().clone();
    let all = serde_json::to_string(&sent).unwrap_or_default().to_lowercase();
    let digits: String = all.chars().filter(char::is_ascii_digit).collect();
    let planted = [NAME, PC_NAME, KEY, EMAIL, "jane", "tester"];
    let mut found: Vec<String> = planted.iter().filter(|p| all.contains(&p.to_lowercase())).map(|p| p.to_string()).collect();
    for num in [CARD.replace(' ', ""), ACCOUNT.to_string(), "021000021".into(), "5829301746".into()] {
        if digits.contains(&num) {
            found.push(format!("digits {num}"));
        }
    }
    let report = json!({
        "note": "Hideout Phase 5: one guide turn through the real WinHTTP door to the gateway, TEST data only. 'sent' is every request body that left (header names only).",
        "question": question,
        "planted": {"name": NAME, "pc": PC_NAME, "card": CARD, "account": ACCOUNT, "key": KEY, "email": EMAIL},
        "plantedFoundInWhatWasSent": found,
        "firstByteMs": first_byte.lock().unwrap().map(|d| d.as_millis()),
        "firstWordMs": first_text.map(|d| d.as_millis()),
        "totalMs": total.as_millis(),
        "sent": sent,
        "events": events,
    });
    if let Err(e) = std::fs::write(out, serde_json::to_string_pretty(&report).unwrap_or_default()) {
        eprintln!("guide-capture: could not write {}: {e}", out.display());
        return 2;
    }
    let done = report["events"].as_array().map(|a| a.last().map(|e| e["type"] == "done").unwrap_or(false)).unwrap_or(false);
    println!("guide-capture: {} request(s) sent, first word {:?} ms, total {} ms, finished: {done}", sent.len(), report["firstWordMs"], total.as_millis());
    println!("  planted secrets found in what was sent: {}", if found.is_empty() { "none".to_string() } else { found.join(", ") });
    if found.is_empty() && done {
        0
    } else {
        1
    }
}
