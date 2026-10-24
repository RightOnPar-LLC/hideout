//! The Money tab's state (money.mjs's M1-M9 in Rust), the redaction promise, and the
//! "what changed since the first statement" view.

use hideout_money::directory::{prepare, Merchant};
use hideout_money::money::{installed_from, remote_tools_in, valid_date, Money};
use std::path::PathBuf;

fn fixture(f: &str) -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(f)).unwrap()
}

fn money() -> Money {
    let dir: Vec<Merchant> = serde_json::from_str(&fixture("dir.json")).unwrap();
    Money::new(Some(prepare(dir)), Box::new(|| "2026-10-01".to_string()))
}

#[test]
fn import_cancel_incident_forget() {
    let mut m = money();
    let r = m.import_statement("chase.csv", &fixture("chase.csv"));
    assert_eq!(r["ok"], true);
    assert_eq!(r["rows"], 8);
    assert_eq!(r["saved"], false, "this build says it is not saving");
    // A bad file is refused with a reason and nothing is kept.
    let bad = m.import_statement("x.csv", "not,a\nstatement,at all");
    assert_eq!(bad["ok"], false);
    assert!(!bad["warnings"].as_array().unwrap().is_empty());
    assert_eq!(m.view()["statements"].as_array().unwrap().len(), 1);
    // Cancels: only a repeating charge, only a real past date.
    assert_eq!(m.mark_canceled("nobody", "2026-09-01")["ok"], false);
    assert_eq!(m.mark_canceled("netflix", "2027-01-01")["ok"], false);
    assert_eq!(m.mark_canceled("netflix", "2026-13-01")["ok"], false);
    assert_eq!(m.mark_canceled("netflix", "2026-02-30")["ok"], false, "a date that does not exist is refused");
    assert_eq!(m.mark_canceled("netflix", "2026-08-05")["ok"], true);
    assert_eq!(m.summary().recurring[0].status, "still-charging");
    assert_eq!(m.set_incident("2026-08-14")["ok"], true);
    assert_eq!(m.set_incident("next tuesday")["ok"], false);
    assert_eq!(m.summary().incident_date.as_deref(), Some("2026-08-14"));
    m.forget_all();
    let v = m.view();
    assert!(v["statements"].as_array().unwrap().is_empty() && v["incidentDate"].is_null() && v["recurring"].as_array().unwrap().is_empty());
}

#[test]
fn cancel_steps_and_safe_links() {
    let mut m = money();
    m.import_statement("amex.csv", &fixture("amex.csv"));
    let a = m.cancel_info("adobe").unwrap();
    assert_eq!(a["canOpen"], true);
    assert_eq!(a["traps"].as_array().unwrap().len(), 1);
    assert_eq!(a["steps"][0], "Sign in");
    assert_eq!(m.cancel_url("adobe").as_deref(), Some("https://account.adobe.com/plans"));
    assert_eq!(m.cancel_url("maxtest"), None, "off-domain page is never opened");
    assert_eq!(m.cancel_url("mailco"), None, "plain http is never opened");
    assert!(m.cancel_info("nobody").is_none());
}

#[test]
fn installed_programs_and_remote_tools() {
    let inst = installed_from(vec![
        ("Norton 360".into(), "Gen Digital".into(), "20260712".into()),
        ("AnyDesk".into(), "AnyDesk Software GmbH".into(), "20260814".into()),
        ("7-Zip 24.08".into(), "Igor Pavlov".into(), "".into()),
        ("AnyDesk".into(), "dup".into(), "20260101".into()),
        ("".into(), "no name".into(), "".into()),
    ]);
    assert_eq!(inst.len(), 3);
    assert_eq!(inst[1].installed.as_deref(), Some("2026-08-14"));
    assert_eq!(remote_tools_in(&inst).iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["AnyDesk"]);
    let mut m = money();
    m.installed = Some(inst);
    for f in ["bofa.csv"] {
        m.import_statement(f, &fixture(f));
    }
    let v = m.view();
    assert_eq!(v["remoteTools"][0]["name"], "AnyDesk");
    assert_eq!(v["recurring"].as_array().unwrap().iter().find(|r| r["merchant"] == "norton").unwrap()["onThisPc"][0], "Norton 360");
}

/// No statement, transaction or account number reaches the guide.
#[test]
fn account_numbers_never_reach_the_guide() {
    let secrets = ["4111111111111111", "000123456789", "021000021", "5829301746", "1234567890123456"];
    let stmt = "Date,Description,Amount\n\
        2026-08-14,Zelle payment to JOHN DOE Conf# 5829301746,-1500.00\n\
        2026-08-14,WIRE TO ACCT 000123456789 ROUTING 021000021,-2000.00\n\
        2026-08-15,CARD 4111-1111-1111-1111 TECH SUPPORT LLC,-299.99\n\
        2026-09-15,CARD 4111 1111 1111 1111 TECH SUPPORT LLC,-299.99\n\
        2026-09-16,ACCOUNT 1234567890123456 GIFT CARD,-500.00\n";
    for s in secrets {
        assert!(stmt.replace(['-', ' '], "").contains(s), "the fixture really carries {s}");
    }
    let mut m = money();
    assert_eq!(m.import_statement("bank.csv", stmt)["ok"], true);
    m.set_incident("2026-08-01");
    for (name, v) in [("guide", m.guide_view()), ("window", m.view())] {
        let text = v.to_string();
        let digits_only: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
        for s in secrets {
            assert!(!text.contains(s), "{name} view leaked {s}");
            // Not even with its spaces or dashes taken out, inside the one long digit run.
            assert!(!digits_only.contains(&format!("{s}")) || s.len() < 9, "{name} view leaked {s} (spread out)");
        }
        assert!(text.contains("••1746"), "{name}: masked to the last four, so a person can still tell which");
    }
    // The guide view has what it needs to help: the post-incident money and the total.
    let g = m.guide_view();
    assert!(g["sinceIncidentTotal"].as_f64().unwrap() > 4000.0);
}

#[test]
fn what_changed_since_the_first_statement() {
    let mut m = money();
    m.import_statement("july.csv", "Date,Description,Amount\n2026-06-01,NETFLIX.COM,-15.49\n2026-07-01,NETFLIX.COM,-15.49\n2026-07-02,SAFEWAY,-20.00\n");
    assert!(m.view()["drift"].is_null(), "one statement: nothing to compare yet");
    m.import_statement("sept.csv", "Date,Description,Amount\n2026-08-01,NETFLIX.COM,-17.99\n2026-09-01,NETFLIX.COM,-17.99\n2026-08-14,TECH SUPPORT SOLUTIONS LLC,-299.99\n2026-09-14,TECH SUPPORT SOLUTIONS LLC,-299.99\n2026-08-20,SAFEWAY,-31.00\n");
    let d = m.view()["drift"].clone();
    assert_eq!(d["since"], "2026-07-02");
    let payees: Vec<&str> = d["newPayees"].as_array().unwrap().iter().map(|p| p["merchant"].as_str().unwrap()).collect();
    assert_eq!(payees, vec!["TECH SUPPORT"], "SAFEWAY and Netflix were already there");
    assert_eq!(d["newSubscriptions"][0]["merchant"], "TECH SUPPORT");
    assert_eq!(d["priceChanges"][0]["merchant"], "netflix");
    assert_eq!(d["priceChanges"][0]["to"], 17.99);
}

#[test]
fn dates_must_be_real() {
    assert!(valid_date("2026-02-28", Some("2026-10-01")));
    assert!(!valid_date("2026-02-30", None));
    assert!(!valid_date("1999-12-31", None));
    assert!(!valid_date("2026-1-5", None));
    assert!(!valid_date("2026-10-02", Some("2026-10-01")));
}
