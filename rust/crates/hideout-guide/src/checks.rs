//! The deeper checks from the website guide: scam drift, small test charges, secret
//! leaks, rogue AI and agents, preserved evidence, browser drift. Each one reads only
//! what Hideout already found on this PC (scans, the deep check, installed programs, the
//! Money tab, the leak look-up); none needs the network, and none changes anything.
//!
//! A check that has nothing to read says "not checked" and why - never "nothing found".

use hideout_money::money::{Installed, REMOTE_TOOLS};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    /// found | nothing-found | not-checked
    pub status: &'static str,
    /// Why not checked, or what "found" means.
    pub why: String,
    /// What was found, for the person (local; the guide gets these redacted).
    pub items: Vec<String>,
    pub advice: &'static [&'static str],
}

pub struct Input<'a> {
    pub incident: Option<&'a str>,
    /// The latest quick scan report.
    pub scan: Option<&'a Value>,
    /// The latest deep check: {at, admin, summary, changes}.
    pub hunt: Option<&'a Value>,
    pub installed: Option<&'a [Installed]>,
    /// From Money::test_charges.
    pub test_charges: Option<Vec<Value>>,
    /// From the leak look-up: [{where, kinds}], None if it has not run.
    pub leaks: Option<&'a [Value]>,
}

/// AI, agent and automation tools: fine if the person installed them, part of the scam
/// until proven otherwise if not.
const AGENT_WORDS: [&str; 16] = ["agent", "copilot", "chatgpt", "openai", "claude", "gemini", "ollama", "autogpt", "browser use", "selenium", "puppeteer", "playwright", "autohotkey", "autoit", "macro recorder", "remote control"];

fn since(date: &str, incident: Option<&str>) -> bool {
    incident.map(|i| !date.is_empty() && date >= i).unwrap_or(false)
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").to_string()
}

fn notable<'a>(hunt: &'a Value, section: &str) -> Vec<&'a Value> {
    hunt["summary"][section]["notable"].as_array().map(|a| a.iter().collect()).unwrap_or_default()
}

fn check(id: &'static str, title: &'static str, advice: &'static [&'static str], checked: Result<Vec<String>, String>, found_why: &str) -> Check {
    match checked {
        Err(why) => Check { id, title, status: "not-checked", why, items: vec![], advice },
        Ok(items) if items.is_empty() => Check { id, title, status: "nothing-found", why: String::new(), items, advice },
        Ok(items) => Check { id, title, status: "found", why: found_why.to_string(), items, advice },
    }
}

pub fn run(i: &Input) -> Vec<Check> {
    vec![scam_drift(i), test_charges(i), leaks(i), rogue_ai(i), evidence(i), browser_drift(i)]
}

fn scam_drift(i: &Input) -> Check {
    const ADVICE: &[&str] = &[
        "Check these yourself, from a device you trust: password or recovery-email changes, new email forwarding rules, and new devices signed in to your accounts. The guide never logs in to check them for you.",
        "New scheduled tasks, services and programs set to start at sign-in since the scam date are on this list when Hideout can see them.",
    ];
    let Some(inc) = i.incident else {
        return check("scam-drift", "Scam drift since the scam date", ADVICE, Err("Tell Hideout the day things went wrong (Money tab) to compare against it.".into()), "");
    };
    if i.scan.is_none() && i.hunt.is_none() && i.installed.is_none() {
        return check("scam-drift", "Scam drift since the scam date", ADVICE, Err("Run a quick scan or a deep check first.".into()), "");
    }
    let mut items = Vec::new();
    if let Some(scan) = i.scan {
        for it in scan["items"].as_array().into_iter().flatten() {
            let created = s(&it["facts"], "created");
            if since(&created, Some(inc)) {
                items.push(format!("Set to start by itself, its file new since {inc}: {} ({}) - {}", s(it, "name"), s(it, "kind"), created));
            }
        }
    }
    if let Some(h) = i.hunt {
        for t in notable(h, "scheduledTasks") {
            if since(&s(t, "registered"), Some(inc)) {
                items.push(format!("Scheduled task made since {inc}: {}", s(t, "name")));
            }
        }
        for f in notable(h, "startupFolders") {
            if since(&s(f, "created"), Some(inc)) {
                items.push(format!("Start-up folder item since {inc}: {}", s(f, "file")));
            }
        }
        for f in notable(h, "recentFiles") {
            if since(&s(f, "created"), Some(inc)) {
                items.push(format!("Program file new since {inc}: {}", s(f, "path")));
            }
        }
        if let Some(secs) = h["changes"]["sections"].as_object() {
            for (name, c) in secs {
                let n = c["added"].as_array().map(|a| a.len()).unwrap_or(0);
                if n > 0 && ["scheduledTasks", "services", "drivers", "registryAutoruns", "startupFolders", "accounts", "browserExtensions", "remoteAccess"].contains(&name.as_str()) {
                    items.push(format!("{n} new in {} since the last deep check", name));
                }
            }
        }
    }
    for p in i.installed.into_iter().flatten() {
        if since(p.installed.as_deref().unwrap_or(""), Some(inc)) {
            items.push(format!("Installed since {inc}: {} ({})", p.name, p.installed.clone().unwrap_or_default()));
        }
    }
    check("scam-drift", "Scam drift since the scam date", ADVICE, Ok(items), "Changes on this PC since the day things went wrong. Some may be yours (updates, things you installed) - the rest are worth a look.")
}

fn test_charges(i: &Input) -> Check {
    const ADVICE: &[&str] = &["Tiny charges, often $1 or less, before a large one are card-testing. Flag them for your bank with the same dates."];
    let checked = match &i.test_charges {
        None => Err("Import a statement in the Money tab and Hideout checks this for you.".into()),
        Some(list) => Ok(list
            .iter()
            .map(|t| {
                let follow = &t["followedBy"];
                let then = if follow.is_null() { String::new() } else { format!(", then ${:.2} on {} ({})", follow["amount"].as_f64().unwrap_or(0.0), s(follow, "date"), s(follow, "descriptor")) };
                format!("${:.2} on {} ({}){then}", t["amount"].as_f64().unwrap_or(0.0), s(t, "date"), s(t, "descriptor"))
            })
            .collect()),
    };
    check("test-charges", "Small test charges first", ADVICE, checked, "Small charges of $2 or less. If you don't recognise one, tell your bank about it and anything large that came after.")
}

fn leaks(i: &Input) -> Check {
    const ADVICE: &[&str] = &[
        "If a file holds a key, token, password or recovery phrase: rotate it at its provider first (make a new one, cancel the old one), then delete the file.",
        "Never paste a key, token, password or recovery phrase into this guide, into email, or into chat. The guide never asks for one.",
    ];
    let checked = match i.leaks {
        None => Err("Run the deeper checks to look through your Desktop, Documents, Downloads and start-up folders.".into()),
        Some(list) => Ok(list.iter().map(|l| format!("{} - looks like it holds: {}", s(l, "where"), l["kinds"].as_array().map(|k| k.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default())).collect()),
    };
    check("leaks", "API and secret leaks - look, never paste", ADVICE, checked, "Files that look like they hold secrets. Hideout only looked; it did not open them anywhere else or move them.")
}

fn rogue_ai(i: &Input) -> Check {
    const ADVICE: &[&str] = &[
        "If you did not install it, treat it as part of the scam until proven otherwise. Remove it through Windows Settings > Apps after the Windows Security scans.",
        "Anything that can read your screen, files or browser by itself deserves the same question: did you set it up?",
    ];
    if i.installed.is_none() && i.hunt.is_none() {
        return check("rogue-ai", "Rogue AI and agents", ADVICE, Err("Hideout is still reading the installed programs - try again in a moment, or run a deep check.".into()), "");
    }
    let mut items = Vec::new();
    for p in i.installed.into_iter().flatten() {
        let l = p.name.to_lowercase();
        let remote = REMOTE_TOOLS.iter().any(|t| l.contains(&t.to_lowercase()));
        let agent = AGENT_WORDS.iter().any(|w| l.contains(w));
        if remote || agent {
            let when = p.installed.clone().map(|d| format!(", installed {d}{}", if since(&d, i.incident) { " - after the scam date" } else { "" })).unwrap_or_default();
            items.push(format!("{} ({}{when})", p.name, if remote { "remote-access program" } else { "AI or automation tool" }));
        }
    }
    if let Some(h) = i.hunt {
        for e in notable(h, "browserExtensions") {
            items.push(format!("Browser extension with wide permissions: {} ({})", s(e, "name"), s(e, "browser")));
        }
        for r in notable(h, "remoteAccess") {
            let n = s(r, "name");
            if !n.is_empty() {
                items.push(format!("Remote access: {n}"));
            }
        }
    }
    check("rogue-ai", "Rogue AI and agents", ADVICE, Ok(items), "Programs and extensions that can act on this PC by themselves. Did you install each one?")
}

fn evidence(i: &Input) -> Check {
    const ADVICE: &[&str] = &[
        "Don't delete the suspicious files, emails, call logs or transaction records before your bank or a report asks for them.",
        "Save screenshots, transaction IDs and dates. A file changed after signing, a new folder with a machine-made name, and a task created after the scam date are evidence, not just clutter.",
    ];
    let mut items = Vec::new();
    for f in i.scan.and_then(|s| s["findings"].as_array()).into_iter().flatten() {
        items.push(format!("Keep for now: {} ({}, arrived {})", s(f, "program"), s(f, "folder"), s(f, "arrived")));
    }
    if let Some(h) = i.hunt {
        items.push(format!("Hideout saved its deep check of {} on this PC (in Hideout's hunts folder).", s(h, "at")));
    }
    let mut c = check("evidence", "Drifting evidence - preserve it", ADVICE, Ok(items), "What Hideout found is evidence. Let Windows Security handle removal; keep a record first.");
    if c.status == "nothing-found" {
        c.why = "Nothing flagged yet - the advice still applies to the calls, emails and bank records.".into();
    }
    c
}

fn browser_drift(i: &Input) -> Check {
    const ADVICE: &[&str] = &["Homepage or search changed, new extensions, saved passwords exported, or new bookmarks to fake bank sites: reset those from your browser's settings, on a clean device if you can."];
    let Some(h) = i.hunt else {
        return check("browser-drift", "Browser drift", ADVICE, Err("Run a deep check - it reads your browsers' settings and extensions.".into()), "");
    };
    let mut items = Vec::new();
    for b in notable(h, "browserSettings") {
        let what = if b["unusualSearch"].as_bool().unwrap_or(false) { "unusual search engine".to_string() } else { s(b, "type") };
        items.push(format!("{} {}: {}", s(b, "browser"), s(b, "profile"), what).trim().to_string());
    }
    for e in notable(h, "browserExtensions") {
        items.push(format!("Extension {} ({}) can read or change the pages you visit", s(e, "name"), s(e, "browser")));
    }
    check("browser-drift", "Browser drift", ADVICE, Ok(items), "Browser settings and extensions worth a look.")
}

/// What the guide gets: per check, its status, how many, and up to five short items
/// (the tool result is redacted on top of this).
pub fn guide_view(checks: &[Check]) -> Value {
    json!(checks.iter().map(|c| json!({"id": c.id, "status": c.status, "found": c.items.len(), "why": c.why, "items": c.items.iter().take(5).collect::<Vec<_>>()})).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(name: &str, d: Option<&str>) -> Installed {
        Installed { name: name.into(), publisher: String::new(), installed: d.map(String::from) }
    }

    #[test]
    fn nothing_to_read_is_not_checked_never_clean() {
        let i = Input { incident: None, scan: None, hunt: None, installed: None, test_charges: None, leaks: None };
        let c = run(&i);
        for id in ["scam-drift", "test-charges", "leaks", "rogue-ai", "browser-drift"] {
            assert_eq!(c.iter().find(|x| x.id == id).unwrap().status, "not-checked", "{id}");
        }
        assert_eq!(c.iter().find(|x| x.id == "evidence").unwrap().status, "nothing-found");
    }

    #[test]
    fn drift_test_charges_and_agents_are_found() {
        let scan = json!({"items": [{"name": "Updater", "kind": "Scheduled task", "facts": {"created": "2026-08-15 10:02"}}, {"name": "Old", "kind": "Run key", "facts": {"created": "2025-01-01 09:00"}}], "findings": []});
        let hunt = json!({"at": "2026-10-24 10:00", "summary": {"browserSettings": {"notable": [{"browser": "Edge", "profile": "Default", "type": "settings", "unusualSearch": true}]}, "browserExtensions": {"notable": []}}, "changes": {"sections": {"services": {"added": ["x"]}}}});
        let inst = vec![installed("AnyDesk", Some("2026-08-14")), installed("7-Zip", Some("2024-01-01")), installed("Agent Smith Helper", None)];
        let i = Input { incident: Some("2026-08-14"), scan: Some(&scan), hunt: Some(&hunt), installed: Some(&inst), test_charges: Some(vec![json!({"date": "2026-08-14", "descriptor": "XYZ", "amount": 0.99, "followedBy": {"date": "2026-08-15", "descriptor": "BIG", "amount": 499.0}})]), leaks: Some(&[]) };
        let c = run(&i);
        let get = |id: &str| c.iter().find(|x| x.id == id).unwrap().clone();
        let d = get("scam-drift");
        assert_eq!(d.status, "found");
        assert!(d.items.iter().any(|x| x.contains("Updater")) && !d.items.iter().any(|x| x.contains("Old")));
        assert!(d.items.iter().any(|x| x.contains("AnyDesk")) && d.items.iter().any(|x| x.contains("1 new in services")));
        assert!(get("test-charges").items[0].contains("$0.99 on 2026-08-14") && get("test-charges").items[0].contains("$499.00"));
        let r = get("rogue-ai");
        assert!(r.items.iter().any(|x| x.contains("AnyDesk") && x.contains("after the scam date")) && r.items.iter().any(|x| x.contains("Agent Smith")));
        assert_eq!(get("leaks").status, "nothing-found");
        assert_eq!(get("browser-drift").status, "found");
        assert_eq!(guide_view(&c)[0]["found"], 3);
    }
}
