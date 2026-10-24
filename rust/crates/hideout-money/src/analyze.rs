//! Turns statement rows into what a person needs to see:
//!   - repeating charges (how often, how much a month, did the price go up)
//!   - STILL CHARGING: a company that billed again after the person said they cancelled,
//!     with the dates as receipts (the dispute that actually wins)
//!   - money that left after the day things went wrong (new companies, transfers, Zelle)
//!   - honest refund odds and a conservative "act by" date
//!
//! Pure functions: no network, no disk, no clock except the `today` passed in. A port of
//! analyze.mjs - the same rules, the same field names, the same numbers.

use crate::directory::{match_merchant, merchant_key, safe_cancel_url, Merchant, SUBSCRIPTION_CATEGORIES};
use crate::js::{add_days, days, median, money};
use crate::statement::Row;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

/// (name, shortest gap, longest gap, period in days, charges per month)
pub const CADENCES: [(&str, f64, f64, i64, f64); 4] = [
    ("weekly", 5.0, 9.0, 7, 52.0 / 12.0),
    ("monthly", 25.0, 35.0, 31, 1.0),
    ("quarterly", 80.0, 100.0, 92, 1.0 / 3.0),
    ("yearly", 330.0, 400.0, 366, 1.0 / 12.0),
];

/// Bank dispute windows are commonly 60 days from the statement that showed the charge.
/// We can't see the statement's date, so count from the charge itself: never later than
/// the real deadline, sometimes earlier. Shown as "act by", never as legal advice.
pub const DISPUTE_DAYS: i64 = 60;
/// A charge within 2 days of the cancel date was usually already in flight.
const STOP_GRACE: i64 = 2;

fn cadence(name: &str) -> Option<&'static (&'static str, f64, f64, i64, f64)> {
    CADENCES.iter().find(|c| c.0 == name)
}

fn cadence_of(dates: &[String]) -> Option<&'static str> {
    if dates.len() < 2 {
        return None;
    }
    let gaps: Vec<f64> = dates.windows(2).map(|w| days(&w[0], &w[1]) as f64).filter(|g| *g > 0.0).collect();
    if gaps.is_empty() {
        return None;
    }
    let g = median(&gaps);
    CADENCES.iter().find(|c| g >= c.1 && g <= c.2).map(|c| c.0)
}

#[derive(Debug, Clone, Default)]
pub struct Statement {
    pub name: String,
    pub rows: Vec<Row>,
}

/// De-duplicate rows from overlapping statements (same day, amount, direction, text).
pub fn merge_rows(statements: &[Statement]) -> Vec<Row> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for s in statements {
        for r in &s.rows {
            let k = format!("{}|{}|{}|{}", r.date, js_num(r.amount), r.direction, r.descriptor);
            if seen.insert(k) {
                out.push(r.clone());
            }
        }
    }
    out.sort_by(|a, b| a.date.cmp(&b.date));
    out
}

/// A number the way JavaScript prints it in a template string ("15.49", "1500").
pub fn js_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AfterCancel {
    pub date: String,
    pub amount: f64,
    pub act_by: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PriceUp {
    pub from: f64,
    pub to: f64,
    pub on: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Recurring {
    pub merchant: String,
    pub name: String,
    pub known: bool,
    pub ambiguous: bool,
    pub category: Option<String>,
    pub sample: String,
    pub cadence: String,
    pub charges: usize,
    pub first_date: String,
    pub last_date: String,
    pub last_amount: f64,
    pub monthly: Option<f64>,
    pub price_up: Option<PriceUp>,
    pub status: String,
    pub canceled_on: Option<String>,
    pub after_cancel: Vec<AfterCancel>,
    pub next_expected: Option<String>,
    pub refund_likelihood: String,
    pub refund_basis: Option<String>,
    pub has_cancel_page: bool,
    pub cancel_by_email: Option<String>,
    pub on_this_pc: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SinceIncident {
    pub date: String,
    pub descriptor: String,
    pub amount: f64,
    pub kind: String,
    pub merchant: Option<String>,
    pub known: bool,
    pub act_by: String,
    pub days_left: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Period {
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    pub period: Period,
    pub statement_count: usize,
    pub rows: usize,
    pub monthly_total: f64,
    pub recurring: Vec<Recurring>,
    pub still_charging: usize,
    pub incident_date: Option<String>,
    pub since_incident: Vec<SinceIncident>,
    pub since_total: f64,
}

#[derive(Debug, Clone, Default)]
pub struct Options<'a> {
    /// (merchant, cancelled on), oldest first; the latest for a merchant wins.
    pub cancels: Vec<(String, String)>,
    pub incident_date: Option<String>,
    /// Names of installed programs (for "on your PC AND on your bill").
    pub installed: Vec<String>,
    pub today: String,
    pub merchants: Option<&'a [Merchant]>,
}

struct Group<'a> {
    key: String,
    m: Option<&'a Merchant>,
    ambiguous: bool,
    rows: Vec<usize>,
}

/// Which group a row belongs to (the directory's company, "transfer:<who>", or a stable
/// key for a company the directory doesn't know). None for card payments.
pub fn group_key(r: &Row, merchants: &[Merchant]) -> Option<String> {
    if r.kind == "payment" {
        return None;
    }
    let mm = if r.kind == "merchant" { match_merchant(&r.descriptor, merchants) } else { None };
    Some(match mm {
        Some(m) => m.merchant.provider.clone(),
        None if r.kind == "transfer" => format!("transfer:{}", merchant_key(&r.descriptor)),
        None => merchant_key(&r.descriptor),
    })
}

pub fn analyze(statements: &[Statement], o: &Options) -> Analysis {
    let merchants = o.merchants.unwrap_or_else(|| crate::directory::shipped());
    let rows = merge_rows(statements);
    let to = rows.last().map(|r| r.date.clone());
    let from = rows.first().map(|r| r.date.clone());
    let mut groups: Vec<Group> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut group_of: Vec<Option<usize>> = vec![None; rows.len()];
    for (i, r) in rows.iter().enumerate() {
        if r.kind == "payment" {
            continue;
        }
        let mm = if r.kind == "merchant" { match_merchant(&r.descriptor, merchants) } else { None };
        let key = match &mm {
            Some(m) => m.merchant.provider.clone(),
            None if r.kind == "transfer" => format!("transfer:{}", merchant_key(&r.descriptor)),
            None => merchant_key(&r.descriptor),
        };
        let gi = *index.entry(key.clone()).or_insert_with(|| {
            groups.push(Group { key: key.clone(), m: mm.as_ref().map(|m| m.merchant), ambiguous: mm.as_ref().map(|m| m.ambiguous).unwrap_or(false), rows: vec![] });
            groups.len() - 1
        });
        groups[gi].rows.push(i);
        group_of[i] = Some(gi);
    }
    let mut cancel_of: HashMap<&str, &str> = HashMap::new();
    for (m, on) in &o.cancels {
        if !m.is_empty() && !on.is_empty() {
            cancel_of.insert(m, on);
        }
    }

    let mut recurring: Vec<Recurring> = Vec::new();
    for g in &groups {
        if g.key.starts_with("transfer:") {
            continue;
        }
        let out: Vec<&Row> = g.rows.iter().map(|i| &rows[*i]).filter(|r| r.direction == "out").collect();
        if out.is_empty() {
            continue;
        }
        let mut dates: Vec<String> = Vec::new();
        for r in &out {
            if !dates.contains(&r.date) {
                dates.push(r.date.clone());
            }
        }
        let amounts: Vec<f64> = out.iter().map(|r| r.amount).collect();
        let cad = cadence_of(&dates);
        let med = median(&amounts);
        let stable = amounts.iter().filter(|a| (*a - med).abs() <= med * 0.1).count() as f64 >= (amounts.len() as f64 * 2.0 / 3.0).ceil();
        let known_sub = g.m.map(|m| SUBSCRIPTION_CATEGORIES.contains(&m.category.as_str())).unwrap_or(false);
        // Two charges a month apart at the same price is a subscription; so is any charge
        // from a company the directory knows only sells subscriptions (even seen once).
        if !((cad.is_some() && stable) || known_sub) {
            continue;
        }
        let last = *out.last().expect("non-empty");
        let prev = if out.len() > 1 { Some(out[out.len() - 2]) } else { None };
        let canceled_on = cancel_of.get(g.key.as_str()).map(|s| s.to_string());
        let after: Vec<&Row> = canceled_on.as_ref().map(|c| out.iter().copied().filter(|r| days(c, &r.date) > STOP_GRACE).collect()).unwrap_or_default();
        let period = cad.and_then(cadence).map(|c| c.3).unwrap_or(31);
        let status = if canceled_on.is_some() && !after.is_empty() {
            "still-charging"
        } else if let Some(c) = &canceled_on {
            if to.as_ref().map(|t| days(c, t) >= period + 5).unwrap_or(false) { "stopped" } else { "waiting" }
        } else if cad.is_none() {
            "once" // one charge (often a yearly plan): can't call it quiet or active yet
        } else if to.as_ref().map(|t| days(&last.date, t) as f64 > period as f64 * 1.5).unwrap_or(false) {
            "quiet"
        } else {
            "active"
        };
        let m = g.m;
        let on_this_pc: Vec<String> = match m {
            Some(m) if !m.software.is_empty() => o.installed.iter().filter(|p| m.software.iter().any(|s| p.to_lowercase().contains(&s.to_lowercase()))).cloned().collect(),
            _ => vec![],
        };
        let per_month = cad.and_then(cadence).map(|c| c.4);
        recurring.push(Recurring {
            merchant: g.key.clone(),
            // JavaScript's `x || fallback`: an empty string counts as missing.
            name: m.map(|m| m.name.clone()).filter(|n| !n.is_empty()).unwrap_or_else(|| g.key.clone()),
            known: m.is_some(),
            ambiguous: g.ambiguous,
            category: m.map(|m| m.category.clone()).filter(|c| !c.is_empty()),
            sample: last.descriptor.clone(),
            cadence: cad.map(String::from).unwrap_or_else(|| if out.len() == 1 { "one charge so far" } else { "irregular" }.into()),
            charges: out.len(),
            first_date: out[0].date.clone(),
            last_date: last.date.clone(),
            last_amount: last.amount,
            monthly: per_month.map(|p| money(last.amount * p)),
            price_up: match (prev, cad) {
                (Some(p), Some(_)) if last.amount > p.amount * 1.01 => Some(PriceUp { from: p.amount, to: last.amount, on: last.date.clone() }),
                _ => None,
            },
            status: status.into(),
            canceled_on: canceled_on.clone(),
            after_cancel: after.iter().map(|r| AfterCancel { date: r.date.clone(), amount: r.amount, act_by: add_days(&r.date, DISPUTE_DAYS) }).collect(),
            next_expected: match cad {
                Some(c) if status != "stopped" => Some(add_days(&last.date, cadence(c).map(|x| x.3).unwrap_or(31))),
                _ => None,
            },
            refund_likelihood: m.and_then(|m| m.refund_likelihood.clone()).filter(|x| !x.is_empty()).unwrap_or_else(|| "unknown".into()),
            refund_basis: m.and_then(|m| m.refund_basis.clone()).filter(|x| !x.is_empty()),
            has_cancel_page: safe_cancel_url(m).is_some(),
            cancel_by_email: m.and_then(|m| m.cancel_by_email.clone()).filter(|x| !x.is_empty()),
            on_this_pc,
        });
    }
    let order = |s: &str| ["still-charging", "active", "once", "waiting", "quiet", "stopped"].iter().position(|x| *x == s).unwrap_or(9);
    recurring.sort_by(|a, b| {
        order(&a.status).cmp(&order(&b.status)).then_with(|| b.monthly.unwrap_or(0.0).partial_cmp(&a.monthly.unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal))
    });
    let monthly_total = money(recurring.iter().filter(|r| r.status == "active" || r.status == "still-charging").map(|r| r.monthly.unwrap_or(0.0)).sum());

    // Money that left after the incident: transfers of any kind, and companies first seen
    // on or after that day. (Subscriptions that were already running aren't news.)
    let mut since: Vec<SinceIncident> = Vec::new();
    if let Some(inc) = &o.incident_date {
        for (i, r) in rows.iter().enumerate() {
            if r.direction != "out" || r.kind == "payment" || r.date.as_str() < inc.as_str() {
                continue;
            }
            let g = group_of[i].map(|gi| &groups[gi]);
            let new_company = g.map(|g| rows[g.rows[0]].date.as_str() >= inc.as_str()).unwrap_or(false);
            if r.kind != "transfer" && !new_company {
                continue;
            }
            let act_by = add_days(&r.date, DISPUTE_DAYS);
            since.push(SinceIncident {
                date: r.date.clone(),
                descriptor: r.descriptor.clone(),
                amount: r.amount,
                kind: r.kind.clone(),
                merchant: g.map(|g| g.key.clone()),
                known: g.map(|g| g.m.is_some()).unwrap_or(false),
                days_left: days(&o.today, &act_by),
                act_by,
            });
        }
        let n = since.len();
        if n > 60 {
            since.drain(..n - 60);
        }
    }
    let since_total = money(since.iter().map(|x| x.amount).sum());
    let still_charging = recurring.iter().filter(|r| r.status == "still-charging").count();
    Analysis {
        period: Period { from, to },
        statement_count: statements.len(),
        rows: rows.len(),
        monthly_total,
        recurring,
        still_charging,
        incident_date: o.incident_date.clone(),
        since_incident: since,
        since_total,
    }
}
