//! The Rust Money engine against the JavaScript engine's own answers (tests/golden.json,
//! written by rust/tools/money-golden.mjs from app/src/money/*.mjs). Every amount, date,
//! status, refund odds and cancel link must match exactly.

use hideout_money::analyze::{analyze, Options, Statement};
use hideout_money::directory::{match_merchant, merchant_key, prepare, safe_cancel_url, shipped, Merchant};
use hideout_money::statement::{classify, mask_digits, parse_amount, parse_date, parse_statement};
use serde_json::Value;
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn golden() -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir().join("golden.json")).unwrap()).unwrap()
}

/// Deep equality where 1500 and 1500.0 are the same number; reports the first path that
/// differs.
fn same(a: &Value, b: &Value, path: &str, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            if x.as_f64() != y.as_f64() {
                out.push(format!("{path}: js={x} rust={y}"));
            }
        }
        (Value::Object(x), Value::Object(y)) => {
            for (k, v) in x {
                if k == "_patterns" {
                    continue;
                }
                same(v, y.get(k).unwrap_or(&Value::Null), &format!("{path}.{k}"), out);
            }
            for k in y.keys() {
                if !x.contains_key(k) {
                    out.push(format!("{path}.{k}: only in rust"));
                }
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            if x.len() != y.len() {
                out.push(format!("{path}: js has {} items, rust {}", x.len(), y.len()));
            }
            for (i, (p, q)) in x.iter().zip(y).enumerate() {
                same(p, q, &format!("{path}[{i}]"), out);
            }
        }
        _ => {
            if a != b {
                out.push(format!("{path}: js={a} rust={b}"));
            }
        }
    }
}

fn check(name: &str, js: &Value, rust: &Value) {
    let mut diffs = Vec::new();
    same(js, rust, name, &mut diffs);
    assert!(diffs.is_empty(), "{} difference(s):\n{}", diffs.len(), diffs.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
}

fn test_dir() -> Vec<Merchant> {
    prepare(serde_json::from_str(&std::fs::read_to_string(dir().join("fixtures").join("dir.json")).unwrap()).unwrap())
}

const FILES: [&str; 5] = ["chase.csv", "amex.csv", "capone.csv", "bofa.csv", "wells.csv"];

fn statements() -> Vec<Statement> {
    FILES
        .iter()
        .enumerate()
        .map(|(i, f)| Statement { name: format!("s{i}"), rows: parse_statement(&std::fs::read_to_string(dir().join("fixtures").join(f)).unwrap()).rows })
        .collect()
}

#[test]
fn every_bank_statement_parses_exactly_like_the_js_engine() {
    let g = golden();
    for f in FILES {
        let text = std::fs::read_to_string(dir().join("fixtures").join(f)).unwrap();
        check(f, &g["parsed"][f], &serde_json::to_value(parse_statement(&text)).unwrap());
    }
}

#[test]
fn every_scenario_analyses_exactly_like_the_js_engine() {
    let g = golden();
    let dir = test_dir();
    let stmts = statements();
    let installed: Vec<String> = ["Norton 360", "AnyDesk", "7-Zip 24.08"].iter().map(|s| s.to_string()).collect();
    let base = |test: bool| Options { today: "2026-10-01".into(), merchants: Some(if test { &dir[..] } else { shipped() }), ..Default::default() };
    let cases: Vec<(&str, Options)> = vec![
        ("plain", base(true)),
        ("cancels", Options { cancels: vec![("netflix".into(), "2026-08-05".into()), ("spotify".into(), "2026-07-10".into()), ("adobe".into(), "2026-09-20".into())], ..base(true) }),
        ("incident", Options { incident_date: Some("2026-08-14".into()), ..base(true) }),
        ("installed", Options { installed: installed.clone(), ..base(true) }),
        ("shipped", Options { incident_date: Some("2026-08-14".into()), installed, ..base(false) }),
    ];
    for (name, o) in cases {
        check(name, &g["analyses"][name], &serde_json::to_value(analyze(&stmts, &o)).unwrap());
    }
}

#[test]
fn helpers_match_the_js_engine() {
    let g = golden();
    for h in g["helpers"].as_array().unwrap() {
        let s = h["s"].as_str().unwrap();
        let rust = serde_json::json!({"s": s, "amount": parse_amount(s), "date": parse_date(s), "mask": mask_digits(s), "kind": classify(s)});
        check(&format!("helper {s:?}"), h, &rust);
    }
}

#[test]
fn directory_matches_the_js_engine() {
    let g = golden();
    for c in g["directory"]["cancelUrls"].as_array().unwrap() {
        let p = c["provider"].as_str().unwrap();
        let m = shipped().iter().find(|m| m.provider == p);
        assert_eq!(serde_json::to_value(safe_cancel_url(m)).unwrap(), c["url"], "cancel page for {p}");
    }
    let dir = test_dir();
    for c in g["directory"]["testCancelUrls"].as_array().unwrap() {
        let p = c["provider"].as_str().unwrap();
        assert_eq!(serde_json::to_value(safe_cancel_url(dir.iter().find(|m| m.provider == p))).unwrap(), c["url"], "test cancel page for {p}");
    }
    for c in g["directory"]["matches"].as_array().unwrap() {
        let d = c["d"].as_str().unwrap();
        let m = match_merchant(d, shipped());
        assert_eq!(m.as_ref().map(|m| m.merchant.provider.as_str()), c["provider"].as_str(), "match for {d}");
        assert_eq!(m.as_ref().map(|m| m.ambiguous), c["ambiguous"].as_bool(), "ambiguity for {d}");
        assert_eq!(merchant_key(d), c["key"].as_str().unwrap(), "key for {d}");
    }
}

/// Negative control: the comparator must catch a one-cent change, a missing field and a
/// changed status - or every "match" above would be meaningless.
#[test]
fn comparator_catches_differences() {
    let g = golden();
    let js = g["analyses"]["cancels"].clone();
    let mut rust = js.clone();
    rust["recurring"][0]["lastAmount"] = serde_json::json!(15.5);
    let mut d = Vec::new();
    same(&js, &rust, "x", &mut d);
    assert_eq!(d.len(), 1, "{d:?}");
    let mut rust = js.clone();
    rust["recurring"][0].as_object_mut().unwrap().remove("status");
    let mut d = Vec::new();
    same(&js, &rust, "x", &mut d);
    assert!(!d.is_empty());
    let mut rust = js.clone();
    rust["stillCharging"] = serde_json::json!(0);
    let mut d = Vec::new();
    same(&js, &rust, "x", &mut d);
    assert!(!d.is_empty());
}
