//! The offline guide: no AI and no network, only Hideout's own steps, letters and
//! checklists, built from what Hideout found on this PC. It answers when the AI guide is
//! not set up on this PC or cannot be reached. It never claims more than the data shows.

use crate::checks::Check;
use serde_json::Value;

pub const NOTICE: &str = "*I'm Hideout's offline guide - not an AI, and not connected to the internet. I can show the steps, check your statements and this PC, and write letters for you to send.*\n\n";

pub struct Context {
    pub tracker: Vec<Value>,
    /// Money::guide_view().
    pub money: Value,
    pub scan: Option<Value>,
    pub checks: Vec<Check>,
}

pub struct Answer {
    pub text: String,
    /// A letter to build: (kind, merchant id).
    pub letter: Option<(String, Option<String>)>,
}

fn has(t: &str, words: &[&str]) -> bool {
    words.iter().any(|w| t.contains(w))
}

fn usd(v: &Value) -> String {
    format!("${:.2}", v.as_f64().unwrap_or(0.0))
}

const URGENT: &str = "**If it is happening right now** - someone controlling the mouse, a caller on the phone, a pop-up demanding payment:\n1. Hang up, and stop typing any codes.\n2. Disconnect this PC from the internet (Wi-Fi off or cable out).\n3. Never pay, never buy gift cards, never call a number shown in a pop-up.\n\nThen change your passwords from a different device you trust, starting with email, then your bank.\n\n";

pub fn answer(text: &str, c: &Context) -> Answer {
    let t = text.to_lowercase();
    let recurring = c.money["repeating"].as_array().cloned().unwrap_or_default();
    // A company named in the message: its id in brackets (the Money tab's buttons send
    // that), or its name.
    let named = recurring.iter().find(|r| {
        let id = r["merchant"].as_str().unwrap_or("").to_lowercase();
        let name = r["name"].as_str().unwrap_or("").to_lowercase();
        (!id.is_empty() && t.contains(&format!("({id})"))) || (name.len() >= 3 && t.contains(&name))
    });

    if has(&t, &["letter", "dispute", "refund", "write to", "cancel by email", "cancellation email"]) {
        let kind = if has(&t, &["dispute", "bank"]) {
            "bank_dispute"
        } else if has(&t, &["email"]) && named.map(|r| !r["acceptsCancelByEmail"].is_null()).unwrap_or(false) {
            "cancel_by_email"
        } else if has(&t, &["refund"]) {
            "refund_request"
        } else {
            "bank_dispute"
        };
        let merchant = named.and_then(|r| r["merchant"].as_str().map(String::from));
        let lead = match named {
            Some(r) => format!("Here is a letter about **{}**, filled in from your statement. ", r["name"].as_str().unwrap_or("")),
            None if recurring.is_empty() => "Here is a letter to start from. Import a statement in the Money tab and I can fill in the amounts and dates for you. ".into(),
            None => "Here is a letter to start from - tell me which company (as it appears in the Money tab) and I'll fill in its amounts and dates. ".into(),
        };
        return Answer { text: format!("{lead}Read it, fill in the [brackets], delete any [Confirm: ...] line that isn't true, and send it yourself. Hideout never sends anything."), letter: Some((kind.into(), merchant)) };
    }

    if has(&t, &["drift", "leak", "rogue", "agent", "evidence", "browser", "deeper", "test charge", "secret", "key", "token"]) {
        return Answer { text: checks_text(&c.checks), letter: None };
    }

    // Something happening right now comes before anything else.
    let urgent = has(&t, &["call", "remote", "pop-up", "popup", "right now", "mouse", "someone"]);

    if !urgent && has(&t, &["charge", "bank", "money", "statement", "zelle", "subscription", "card", "paid", "payment", "wire"]) {
        return Answer { text: money_text(&c.money), letter: None };
    }

    if !urgent && has(&t, &["scan", "hacked", "virus", "malware", "found", "infected", "threat"]) {
        let mut s = scan_text(c.scan.as_ref());
        s.push_str("\n\nAsk me for **the steps** to see where you are in getting through this.");
        return Answer { text: s, letter: None };
    }

    let mut s = String::new();
    if urgent {
        s.push_str(URGENT);
    }
    s.push_str(&tracker_text(&c.tracker));
    s.push_str("\n\nYou can also ask me to **check my bank charges**, **write a dispute letter**, or run **the deeper checks** (scam drift, test charges, leaks, rogue AI, evidence, browser drift).");
    Answer { text: s, letter: None }
}

pub fn tracker_text(tracker: &[Value]) -> String {
    let mut s = String::from("**The six steps:**\n");
    for (i, step) in tracker.iter().enumerate() {
        let mark = match step["status"].as_str().unwrap_or("") {
            "done" => "Done",
            "in-progress" => "Under way",
            "found" => "Needs you",
            "checked" => "Checked",
            "not-checked" => "Not checked yet",
            "keep-watching" => "Keep watching",
            _ => "To do",
        };
        let note = step["note"].as_str().filter(|n| !n.is_empty()).map(|n| format!(" ({n})")).unwrap_or_default();
        s.push_str(&format!("{}. **{}** - {}: {}{}\n", i + 1, step["title"].as_str().unwrap_or(""), mark, step["text"].as_str().unwrap_or(""), note));
    }
    s
}

pub fn money_text(m: &Value) -> String {
    if m["statementsImported"].as_u64().unwrap_or(0) == 0 {
        return "No statement is imported yet. Sign in to your bank's website (type the address yourself), download the last 2-3 months as a CSV file, then press **Import** in the Money tab. Never paste statement lines or account numbers into a chat.".into();
    }
    let mut s = format!("**Repeating charges:** {} a month.\n", usd(&m["repeatingChargesPerMonth"]));
    let still: Vec<&Value> = m["repeating"].as_array().map(|a| a.iter().filter(|r| r["status"] == "still-charging").collect()).unwrap_or_default();
    for r in &still {
        let n = r["chargedAfterCancel"].as_array().map(|a| a.len()).unwrap_or(0);
        s.push_str(&format!("- **{} is still charging you**: {} time(s) after you cancelled on {}. That's the strongest case for a refund - ask me for a dispute letter.\n", r["name"].as_str().unwrap_or(""), n, r["canceledOn"].as_str().unwrap_or("")));
    }
    if still.is_empty() {
        s.push_str("- None still charging after a cancellation you recorded.\n");
    }
    match m["incidentDate"].as_str() {
        Some(d) => {
            let n = m["sinceIncident"].as_array().map(|a| a.len()).unwrap_or(0);
            s.push_str(&format!("\n**Since {d}:** {n} transfer(s) or new compan(ies), {} in all. ", usd(&m["sinceIncidentTotal"])));
            s.push_str("If any money went to a scammer by Zelle, wire, gift card or crypto, call your bank now on the number on your card and say it was a scam - speed matters.\n");
        }
        None => s.push_str("\nTell Hideout the day things went wrong (Money tab) and it lists every transfer and new company since.\n"),
    }
    s.push_str("\nRefund odds and \"tell your bank by\" dates are general information, not legal or financial advice - your bank's own terms decide.");
    s
}

pub fn scan_text(scan: Option<&Value>) -> String {
    let Some(s) = scan else { return "No scan has finished yet - press **Scan now** on the Your PC tab (it usually takes under a minute).".into() };
    let f = s["findings"].as_array().cloned().unwrap_or_default();
    let not_checked = s["checked"]["couldNotCheck"].as_array().map(|a| a.len()).unwrap_or(0);
    let mut out = if f.is_empty() {
        format!("The last quick scan flagged nothing among {} things set to start by themselves.", s["checked"]["startItems"].as_u64().unwrap_or(0))
    } else {
        let high = f.iter().filter(|x| x["severity"] == "high").count();
        format!("The last quick scan flagged {} item(s){}:\n{}", f.len(), if high > 0 { format!(", {high} of them a likely threat") } else { String::new() }, f.iter().take(5).map(|x| format!("- **{}** ({})", x["program"].as_str().unwrap_or(""), x["name"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n"))
    };
    if not_checked > 0 {
        out.push_str(&format!("\n\n{not_checked} item(s) couldn't be checked - not checked is not the same as clean."));
    }
    if !f.is_empty() {
        out.push_str("\n\nDon't delete files by hand. Let Windows Security handle it: Virus & threat protection > Scan options > Custom scan of the flagged folder, then a Full scan.");
    }
    out
}

pub fn checks_text(checks: &[Check]) -> String {
    let mut s = String::from("**Deeper checks** (read from this PC; nothing was changed):\n");
    for c in checks {
        let head = match c.status {
            "found" => format!("{} found", c.items.len()),
            "nothing-found" => "nothing found".into(),
            _ => "not checked yet".into(),
        };
        s.push_str(&format!("\n**{}** - {}.", c.title, head));
        if !c.why.is_empty() {
            s.push_str(&format!(" {}", c.why));
        }
        s.push('\n');
        for it in c.items.iter().take(6) {
            s.push_str(&format!("- {it}\n"));
        }
        if let Some(a) = c.advice.first() {
            s.push_str(&format!("{a}\n"));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::{CaseFile, Facts};
    use serde_json::json;

    fn ctx() -> Context {
        Context {
            tracker: CaseFile::default().tracker(&Facts::default()),
            money: json!({"statementsImported": 1, "repeatingChargesPerMonth": 15.49, "incidentDate": null, "repeating": [{"merchant": "netflix", "name": "Netflix", "status": "still-charging", "canceledOn": "2026-08-05", "chargedAfterCancel": [{"date": "2026-09-01"}], "acceptsCancelByEmail": null}]}),
            scan: None,
            checks: vec![],
        }
    }

    #[test]
    fn routes_to_letters_money_scan_and_steps() {
        let a = answer("Write a letter to my bank disputing the charges from Netflix after I cancelled (netflix).", &ctx());
        assert_eq!(a.letter, Some(("bank_dispute".into(), Some("netflix".into()))));
        let m = answer("check my bank charges", &ctx());
        assert!(m.text.contains("Netflix is still charging you") && m.letter.is_none());
        assert!(answer("am I hacked?", &ctx()).text.contains("No scan has finished yet"));
        let s = answer("someone called me about a virus", &ctx()).text;
        assert!(s.contains("Hang up") && s.contains("The six steps"), "{s}");
        assert!(answer("what now", &ctx()).text.contains("6. **Watch for the second scam**"));
    }
}
