//! The Money tab's state: the person's imported statements, the companies they told us
//! they cancelled, and the day things went wrong. A port of money.mjs.
//!
//! In this build the state lives in memory for the session only (the window says so:
//! "Memory is off - statements are only kept until Hideout closes"). The encrypted,
//! PC-sealed case file arrives with the memory phase.
//!
//! Hideout never logs into anything, never sends anything and never cancels anything. It
//! shows, drafts, and opens the vendor's own cancel page when the person clicks.

use crate::analyze::{analyze, group_key, merge_rows, Analysis, Options, Statement};
use crate::directory::{safe_cancel_url, shipped, Merchant};
use crate::js;
use crate::statement::parse_statement;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Remote-support tools tech-support scammers commonly ask people to install. Being
/// installed isn't proof of anything (IT departments use them too) - it's a question.
pub const REMOTE_TOOLS: [&str; 20] = [
    "AnyDesk", "TeamViewer", "ScreenConnect", "ConnectWise Control", "Zoho Assist", "LogMeIn", "GoTo Resolve", "UltraViewer", "RustDesk", "Splashtop", "Supremo", "AeroAdmin", "Ammyy", "RemotePC",
    "Chrome Remote Desktop", "Remote Utilities", "HopToDesk", "DWService", "SimpleHelp", "Atera",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Installed {
    pub name: String,
    pub publisher: String,
    /// YYYY-MM-DD when Windows recorded it.
    pub installed: Option<String>,
}

/// Programs from the Uninstall lists (name, publisher, InstallDate "YYYYMMDD"), cleaned
/// the way pc.mjs cleaned them: names capped, duplicates dropped, dates checked.
pub fn installed_from(entries: Vec<(String, String, String)>) -> Vec<Installed> {
    let mut seen = std::collections::HashSet::new();
    entries
        .into_iter()
        .filter(|(n, _, _)| !n.is_empty())
        .map(|(n, p, d)| Installed {
            name: js::take(&n, 120),
            publisher: js::take(&p, 80),
            installed: (d.len() == 8 && d.chars().all(|c| c.is_ascii_digit())).then(|| format!("{}-{}-{}", &d[..4], &d[4..6], &d[6..])),
        })
        .filter(|p| seen.insert(p.name.clone()))
        .collect()
}

pub fn remote_tools_in(installed: &[Installed]) -> Vec<&Installed> {
    installed.iter().filter(|p| REMOTE_TOOLS.iter().any(|t| p.name.to_lowercase().contains(&t.to_lowercase()))).collect()
}

#[derive(Debug, Clone)]
struct Stored {
    name: String,
    from: Option<String>,
    to: Option<String>,
    rows: Vec<crate::statement::Row>,
}

/// A real calendar date "YYYY-MM-DD", from 2000 on, and not after `today`.
/// (money.mjs let JavaScript's Date.parse roll "2026-02-30" over to 2 March; a date that
/// does not exist is refused here.)
pub fn valid_date(d: &str, today: Option<&str>) -> bool {
    static ISO: OnceLock<Regex> = OnceLock::new();
    let iso = ISO.get_or_init(|| Regex::new(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$").expect("valid pattern"));
    if !iso.is_match(d) || d < "2000-01-01" {
        return false;
    }
    let real = js::day_number(d).map(|n| js::iso_of(n) == d).unwrap_or(false);
    real && today.map(|t| d <= t).unwrap_or(true)
}

pub struct Money {
    merchants: Vec<Merchant>,
    statements: Vec<Stored>,
    cancels: Vec<(String, String)>,
    incident: Option<String>,
    /// None = not looked at yet.
    pub installed: Option<Vec<Installed>>,
    today: Box<dyn Fn() -> String + Send + Sync>,
}

impl Money {
    pub fn new(merchants: Option<Vec<Merchant>>, today: Box<dyn Fn() -> String + Send + Sync>) -> Money {
        Money { merchants: merchants.unwrap_or_else(|| shipped().to_vec()), statements: vec![], cancels: vec![], incident: None, installed: None, today }
    }

    pub fn saving(&self) -> bool {
        false
    }

    fn statements_for_analysis(&self) -> Vec<Statement> {
        self.statements.iter().map(|s| Statement { name: s.name.clone(), rows: s.rows.clone() }).collect()
    }

    pub fn import_statement(&mut self, name: &str, text: &str) -> Value {
        let parsed = parse_statement(text);
        if parsed.rows.is_empty() {
            let w = if parsed.warnings.is_empty() { vec!["No charges found in that file.".to_string()] } else { parsed.warnings };
            return json!({"ok": false, "warnings": w});
        }
        static UNSAFE: OnceLock<Regex> = OnceLock::new();
        let unsafe_chars = UNSAFE.get_or_init(|| Regex::new(r"[^A-Za-z0-9_ .()\-]").expect("valid pattern"));
        let nm = if name.is_empty() { "statement" } else { name };
        let safe_name = js::take(&unsafe_chars.replace_all(nm, "_"), 80);
        let n = parsed.rows.len();
        self.statements.push(Stored { name: safe_name, from: parsed.from.clone(), to: parsed.to.clone(), rows: parsed.rows });
        json!({"ok": true, "rows": n, "from": parsed.from, "to": parsed.to, "warnings": parsed.warnings, "saved": self.saving()})
    }

    pub fn summary(&self) -> Analysis {
        let installed: Vec<String> = self.installed.as_ref().map(|v| v.iter().map(|p| p.name.clone()).collect()).unwrap_or_default();
        analyze(&self.statements_for_analysis(), &Options { cancels: self.cancels.clone(), incident_date: self.incident.clone(), installed, today: (self.today)(), merchants: Some(&self.merchants) })
    }

    pub fn knows(&self, merchant: &str) -> bool {
        self.summary().recurring.iter().any(|r| r.merchant == merchant)
    }

    pub fn mark_canceled(&mut self, merchant: &str, on: &str) -> Value {
        if !self.knows(merchant) {
            return json!({"ok": false, "error": "That company isn't in the repeating charges."});
        }
        if !valid_date(on, Some(&(self.today)())) {
            return json!({"ok": false, "error": "The cancel date must be a real date, not in the future (YYYY-MM-DD)."});
        }
        self.cancels.push((merchant.into(), on.into()));
        json!({"ok": true, "saved": self.saving()})
    }

    pub fn set_incident(&mut self, date: &str) -> Value {
        if !valid_date(date, Some(&(self.today)())) {
            return json!({"ok": false, "error": "That date must be a real date, not in the future (YYYY-MM-DD)."});
        }
        self.incident = Some(date.into());
        json!({"ok": true, "saved": self.saving()})
    }

    pub fn forget_all(&mut self) -> Value {
        self.statements.clear();
        self.cancels.clear();
        self.incident = None;
        json!({"ok": true})
    }

    /// How to cancel one company: the vendor's own steps, the traps, and whether there is
    /// a safe page to open. None for a company that isn't a repeating charge.
    pub fn cancel_info(&self, merchant: &str) -> Option<Value> {
        let m = self.merchants.iter().find(|x| x.provider == merchant);
        let s = self.summary();
        let r = s.recurring.iter().find(|x| x.merchant == merchant)?;
        let steps: Vec<String> = match m {
            Some(m) if !m.cancel_steps.is_empty() => m.cancel_steps.clone(),
            _ => vec![
                "Sign in to your account on the company's own website (type the address yourself - don't use a link from an email).".into(),
                "Find Account, Billing, Membership or Subscription.".into(),
                "Choose Cancel, and keep going past any offers until it says the cancellation is confirmed.".into(),
                "Save the confirmation email or take a screenshot.".into(),
            ],
        };
        Some(json!({
            "merchant": merchant, "name": r.name, "steps": steps, "traps": m.map(|m| m.traps.clone()).unwrap_or_default(),
            "canOpen": safe_cancel_url(m).is_some(), "cancelByEmail": m.and_then(|m| m.cancel_by_email.clone()).filter(|x| !x.is_empty()),
            "refundLikelihood": r.refund_likelihood, "refundBasis": r.refund_basis, "known": m.is_some(),
        }))
    }

    /// The directory's cancel page for a merchant id - the ONLY thing Money ever opens.
    pub fn cancel_url(&self, merchant: &str) -> Option<String> {
        safe_cancel_url(self.merchants.iter().find(|x| x.provider == merchant))
    }

    /// What changed since the first statement: payees never seen before, subscriptions
    /// that started later, and price rises after it. None until there is something later
    /// than the first statement to compare.
    pub fn drift(&self, s: &Analysis) -> Value {
        let Some(first) = self.statements.first() else { return Value::Null };
        let Some(since) = first.to.clone() else { return Value::Null };
        let rows = merge_rows(&self.statements_for_analysis());
        if !rows.iter().any(|r| r.date > since) {
            return Value::Null;
        }
        // Each company's first money out, and what has gone to it since.
        let mut seen: BTreeMap<String, (String, f64, String)> = BTreeMap::new();
        for r in rows.iter().filter(|r| r.direction == "out") {
            let Some(k) = group_key(r, &self.merchants) else { continue };
            let e = seen.entry(k).or_insert_with(|| (r.date.clone(), 0.0, r.descriptor.clone()));
            e.1 = js::money(e.1 + r.amount);
        }
        let mut new_payees: Vec<(String, String, f64, String)> = seen.into_iter().filter(|(_, (d, _, _))| *d > since).map(|(k, (d, t, sample))| (k, d, t, sample)).collect();
        new_payees.sort_by(|a, b| a.1.cmp(&b.1));
        json!({
            "since": since,
            "newPayees": new_payees.iter().map(|(k, d, t, sample)| json!({"merchant": k, "firstDate": d, "total": t, "sample": sample})).collect::<Vec<_>>(),
            "newSubscriptions": s.recurring.iter().filter(|r| r.first_date > since).map(|r| json!({"merchant": r.merchant, "name": r.name, "firstDate": r.first_date, "lastAmount": r.last_amount, "cadence": r.cadence})).collect::<Vec<_>>(),
            "priceChanges": s.recurring.iter().filter_map(|r| r.price_up.as_ref().filter(|p| p.on > since).map(|p| json!({"merchant": r.merchant, "name": r.name, "from": p.from, "to": p.to, "on": p.on}))).collect::<Vec<_>>(),
        })
    }

    /// Everything the window shows (local only).
    pub fn view(&self) -> Value {
        let s = self.summary();
        let drift = self.drift(&s);
        let mut v = json!({
            "saving": self.saving(),
            "statements": self.statements.iter().map(|x| json!({"name": x.name, "from": x.from, "to": x.to, "rows": x.rows.len()})).collect::<Vec<_>>(),
            "remoteTools": self.installed.as_ref().map(|i| remote_tools_in(i).iter().map(|p| json!({"name": p.name, "installed": p.installed})).collect::<Vec<_>>()),
            "drift": drift,
        });
        if let (Value::Object(a), Ok(Value::Object(b))) = (&mut v, serde_json::to_value(&s)) {
            a.extend(b);
        }
        v
    }

    /// What the guide sees: the same facts, trimmed. Account and card numbers were masked
    /// when the statement was read; the guide's redactor runs on top of this.
    pub fn guide_view(&self) -> Value {
        let v = self.view();
        let rec: Vec<Value> = v["recurring"].as_array().cloned().unwrap_or_default().into_iter().take(40).map(|r| {
            json!({
                "merchant": r["merchant"], "name": r["name"], "knownCompany": r["known"], "cadence": r["cadence"], "lastAmount": r["lastAmount"], "lastDate": r["lastDate"],
                "perMonth": r["monthly"], "status": r["status"], "canceledOn": r["canceledOn"], "chargedAfterCancel": r["afterCancel"], "priceWentUp": r["priceUp"],
                "refundOdds": r["refundLikelihood"], "refundPolicy": r["refundBasis"], "cancelPageAvailable": r["hasCancelPage"], "acceptsCancelByEmail": r["cancelByEmail"], "installedOnThisPc": r["onThisPc"],
            })
        }).collect();
        let since = v["sinceIncident"].as_array().cloned().unwrap_or_default();
        let tail: Vec<Value> = since.iter().skip(since.len().saturating_sub(30)).cloned().collect();
        json!({
            "statementsImported": v["statements"].as_array().map(|a| a.len()).unwrap_or(0), "period": v["period"], "savedInMemory": v["saving"],
            "incidentDate": v["incidentDate"], "repeatingChargesPerMonth": v["monthlyTotal"], "repeating": rec,
            "sinceIncident": tail, "sinceIncidentTotal": v["sinceTotal"], "remoteAccessToolsInstalled": v["remoteTools"],
        })
    }
}
