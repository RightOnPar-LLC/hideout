//! Who a statement line really is, how to cancel it, and whether a refund is realistic.
//! Data: app/data/merchants.json, compiled in (one copy, shared with the Node app).
//!
//! The cancel co-pilot opens a page ONLY from this directory, and only after
//! `safe_cancel_url` agrees it is an https page on the vendor's own domain - never a link
//! from a statement, an email, the guide, or the page. A port of directory.mjs.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

pub const DATA: &str = include_str!("../../../../app/data/merchants.json");

pub const SUBSCRIPTION_CATEGORIES: [&str; 12] = ["streaming", "music", "software", "security-software", "cloud-storage", "news", "fitness", "dating", "gaming", "app-store", "phone-internet", "developer"];
pub const REFUND_LIKELIHOOD: [&str; 5] = ["good", "decent", "low", "near-zero", "unknown"];

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Merchant {
    pub provider: String,
    pub name: String,
    pub category: String,
    pub descriptor_patterns: Vec<String>,
    pub domain: Option<String>,
    pub other_domains: Vec<String>,
    pub cancel_url: Option<String>,
    pub cancel_steps: Vec<String>,
    pub traps: Vec<String>,
    pub refund_likelihood: Option<String>,
    pub refund_basis: Option<String>,
    pub cancel_by_email: Option<String>,
    pub software: Vec<String>,
    pub sources: Vec<serde_json::Value>,
    pub checked: Option<String>,
    /// Normalised patterns, longest first (filled in by `prepare`).
    #[serde(skip)]
    pub patterns: Vec<String>,
}

pub fn prepare(mut list: Vec<Merchant>) -> Vec<Merchant> {
    for m in &mut list {
        let mut p: Vec<String> = m.descriptor_patterns.iter().map(|x| normalize(x)).filter(|x| !x.is_empty()).collect();
        p.sort_by_key(|x| std::cmp::Reverse(x.len()));
        m.patterns = p;
    }
    list
}

/// The shipped directory, parsed once.
pub fn shipped() -> &'static [Merchant] {
    static M: OnceLock<Vec<Merchant>> = OnceLock::new();
    M.get_or_init(|| prepare(serde_json::from_str(DATA).expect("app/data/merchants.json is valid")))
}

/// Upper-case, anything but A-Z/0-9/space becomes a space, runs of spaces collapse.
pub fn normalize(s: &str) -> String {
    let up = s.to_uppercase();
    let mapped: String = up.chars().map(|c| if c.is_ascii_uppercase() || c.is_ascii_digit() || c == ' ' { c } else { ' ' }).collect();
    mapped.split(' ').filter(|t| !t.is_empty()).collect::<Vec<_>>().join(" ")
}

// Word-boundary match ("MAX" must not match "MAXWELL"); long patterns may also match
// inside a run-together descriptor ("AMAZONPRIME").
fn hit(norm: &str, pat: &str) -> bool {
    format!(" {norm} ").contains(&format!(" {pat} ")) || (pat.len() >= 7 && norm.replace(' ', "").contains(&pat.replace(' ', "")))
}

pub struct Match<'a> {
    pub merchant: &'a Merchant,
    pub ambiguous: bool,
}

/// Best directory match for a statement descriptor (longest matching pattern wins).
pub fn match_merchant<'a>(descriptor: &str, merchants: &'a [Merchant]) -> Option<Match<'a>> {
    let norm = normalize(descriptor);
    let mut best: Option<&Merchant> = None;
    let (mut best_len, mut others) = (0usize, 0usize);
    for m in merchants {
        let Some(p) = m.patterns.iter().find(|x| hit(&norm, x)) else { continue };
        if p.len() > best_len {
            if best.is_some() {
                others += 1;
            }
            best = Some(m);
            best_len = p.len();
        } else {
            others += 1;
        }
    }
    best.map(|m| Match { merchant: m, ambiguous: others > 0 })
}

const NOISE: &[&str] = &["SQ", "TST", "PAYPAL", "PP", "SP", "POS", "DEBIT", "PURCHASE", "CARD", "RECURRING", "WWW", "COM", "NET", "ORG", "HTTPS", "HTTP", "INC", "LLC", "LTD", "CO", "USA", "US", "BILL", "HELP", "ONLINE", "PMT", "PAYMENT", "ACH", "WEB", "CHECKCARD", "VISA", "MC"];
const STATES: &str = "AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC";

/// A stable key for a merchant the directory doesn't know:
/// "SQ *BLUE BOTTLE #123 SF CA" -> "BLUE BOTTLE".
pub fn merchant_key(descriptor: &str) -> String {
    let n = normalize(descriptor);
    let mut toks: Vec<&str> = n.split(' ').filter(|t| t.chars().count() > 1 && !t.chars().any(|c| c.is_ascii_digit()) && !NOISE.contains(t)).collect();
    while toks.len() > 1 && toks.last().map(|t| STATES.split(' ').any(|s| s == *t)).unwrap_or(false) {
        toks.pop();
    }
    let k = toks.iter().take(2).copied().collect::<Vec<_>>().join(" ");
    if !k.is_empty() {
        return k;
    }
    let short: String = n.chars().take(24).collect();
    if !short.is_empty() {
        short
    } else {
        "UNKNOWN".into()
    }
}

/// The vendor's cancel page, if it is a real https page on the vendor's own domain, in
/// the form a browser would show it (lower-case host, "/" for an empty path).
pub fn safe_cancel_url(m: Option<&Merchant>) -> Option<String> {
    let m = m?;
    let url = m.cancel_url.as_deref()?;
    if url.is_empty() || url.contains(['<', '>', '{', '}']) || url.chars().any(char::is_whitespace) {
        return None;
    }
    let rest = url.get(..8).filter(|p| p.eq_ignore_ascii_case("https://")).map(|_| &url[8..])?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    // user:password@host is how a link hides where it really goes.
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (h, Some(p)),
        Some((_, _)) => return None,
        None => (authority, None),
    };
    let host = host.to_ascii_lowercase();
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return None;
    }
    let domains: Vec<String> = m.domain.iter().chain(m.other_domains.iter()).filter(|d| !d.is_empty()).map(|d| d.to_lowercase()).collect();
    if !domains.iter().any(|d| host == *d || host.ends_with(&format!(".{d}"))) {
        return None;
    }
    let port = match port {
        Some("443") | None => String::new(),
        Some(p) => format!(":{p}"),
    };
    let tail = if tail.is_empty() || tail.starts_with('?') || tail.starts_with('#') { format!("/{tail}") } else { tail.to_string() };
    Some(format!("https://{host}{port}{tail}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(domain: &str, url: &str) -> Merchant {
        Merchant { domain: Some(domain.into()), cancel_url: Some(url.into()), ..Default::default() }
    }

    #[test]
    fn cancel_urls() {
        assert_eq!(safe_cancel_url(Some(&m("netflix.com", "https://www.netflix.com/cancelplan"))).as_deref(), Some("https://www.netflix.com/cancelplan"));
        assert_eq!(safe_cancel_url(Some(&m("apple.com", "https://account.apple.com"))).as_deref(), Some("https://account.apple.com/"));
        assert_eq!(safe_cancel_url(Some(&m("max.com", "https://evil.example/cancel"))), None);
        assert_eq!(safe_cancel_url(Some(&m("mailco.com", "http://mailco.com/cancel"))), None);
        assert_eq!(safe_cancel_url(Some(&m("x.com", "https://<space>.x.com/billing"))), None);
        assert_eq!(safe_cancel_url(Some(&m("x.com", "https://user:pw@x.com/"))), None);
        assert_eq!(safe_cancel_url(Some(&m("x.com", "https://x.com.evil.example/"))), None);
        assert_eq!(safe_cancel_url(None), None);
    }

    #[test]
    fn keys_and_matching() {
        assert_eq!(merchant_key("SQ *BLUE BOTTLE #123 SAN FRANCISCO CA"), "BLUE BOTTLE");
        assert_eq!(merchant_key("TECH SUPPORT SOLUTIONS LLC 8005551234 FL"), "TECH SUPPORT");
        assert_eq!(merchant_key("TST* JOE'S PIZZA 555"), "JOE PIZZA");
        let dir = prepare(vec![Merchant { provider: "maxtest".into(), descriptor_patterns: vec!["MAX".into()], ..Default::default() }]);
        assert!(match_merchant("MAXWELL HOUSE COFFEE", &dir).is_none());
        assert_eq!(match_merchant("MAX.COM 855-442-6629 NY", &dir).unwrap().merchant.provider, "maxtest");
    }

    #[test]
    fn shipped_directory_is_sound() {
        let d = shipped();
        assert!(d.len() >= 40);
        let mut ids: Vec<&str> = d.iter().map(|m| m.provider.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), d.len(), "ids are unique");
        for m in d {
            assert!(SUBSCRIPTION_CATEGORIES.contains(&m.category.as_str()) || ["shopping", "other"].contains(&m.category.as_str()), "{}", m.provider);
            assert!(REFUND_LIKELIHOOD.contains(&m.refund_likelihood.as_deref().unwrap_or("")), "{}", m.provider);
        }
    }
}
