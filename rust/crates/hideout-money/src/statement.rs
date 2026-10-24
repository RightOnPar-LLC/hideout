//! Reads the statement a person downloads from their bank's website (CSV, or tab or
//! semicolon separated) into plain rows: date, descriptor, amount, direction, kind.
//!
//! Banks disagree on everything: Chase card exports show purchases as NEGATIVE, Amex as
//! POSITIVE; Capital One splits Debit/Credit columns; Bank of America puts a summary block
//! above the header; Wells Fargo has no header at all. So columns are found by header name
//! when there is one and by what the cells look like when there isn't, and the sign of a
//! charge is decided per file (whichever sign most rows carry).
//!
//! A port of app/src/money/statement.mjs. Nothing here touches the network or the disk.
//! Long digit runs (card, account and reference numbers) are masked on the way in, so they
//! never reach memory or the guide. Input of any shape is safe: everything is capped, and
//! a malformed file gives a warning, never a panic (a fuzz test feeds it garbage).

use crate::js;
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

pub const MAX_ROWS: usize = 5000;

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("valid built-in pattern"))
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Row {
    pub date: String,
    pub descriptor: String,
    pub amount: f64,
    /// "out" (money left) or "in".
    pub direction: String,
    /// "merchant", "transfer" or "payment".
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Parsed {
    pub rows: Vec<Row>,
    pub from: Option<String>,
    pub to: Option<String>,
    /// "header", "inferred", "unknown" or "empty".
    pub format: String,
    pub skipped: usize,
    pub warnings: Vec<String>,
}

/// 6+ digits in a row (spaces and dashes allowed inside) -> keep only the last 4.
pub fn mask_digits(s: &str) -> String {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"[0-9][0-9 \-]{4,}[0-9]")
        .replace_all(s, |m: &regex::Captures| {
            let d: String = m[0].chars().filter(|c| c.is_ascii_digit()).collect();
            if d.len() >= 6 {
                format!("••{}", &d[d.len() - 4..])
            } else {
                m[0].to_string()
            }
        })
        .into_owned()
}

fn detect_delimiter(text: &str) -> char {
    let head: Vec<&str> = text.split('\n').take(15).collect();
    let head = head.join("\n");
    let count = |c: char| head.chars().filter(|x| *x == c).count();
    // Ties go to the first in this order, as the JavaScript stable sort did.
    let mut best = (',', count(','));
    for c in ['\t', ';'] {
        let n = count(c);
        if n > best.1 {
            best = (c, n);
        }
    }
    if best.1 > 0 {
        best.0
    } else {
        ','
    }
}

/// RFC 4180-ish: quoted fields, doubled quotes, CRLF, a delimiter inside quotes. Stops
/// reading once it has more rows than any statement Hideout reads.
pub fn parse_delimited(text: &str, delim: Option<char>) -> Vec<Vec<String>> {
    let t = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let delim = delim.unwrap_or_else(|| detect_delimiter(t));
    let chars: Vec<char> = t.chars().collect();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut q = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if q {
            if c == '"' {
                if chars.get(i + 1) == Some(&'"') {
                    field.push('"');
                    i += 1;
                } else {
                    q = false;
                }
            } else {
                field.push(c);
            }
        } else if c == '"' {
            q = true;
        } else if c == delim {
            row.push(std::mem::take(&mut field));
        } else if c == '\n' || c == '\r' {
            if c == '\r' && chars.get(i + 1) == Some(&'\n') {
                i += 1;
            }
            row.push(std::mem::take(&mut field));
            rows.push(std::mem::take(&mut row));
            if rows.len() > MAX_ROWS + 50 {
                break;
            }
        } else {
            field.push(c);
        }
        i += 1;
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows.into_iter()
        .map(|r| r.into_iter().map(|s| js::trim(&s).to_string()).collect::<Vec<_>>())
        .filter(|r| r.iter().any(|s| !s.is_empty()))
        .collect()
}

fn month(name: &str) -> Option<u32> {
    // The first three letters name the month ("Jun", "June", "JUNE" ...). statement.mjs
    // looked up the first FOUR letters, so "June 1, 2026" or "July" came back unreadable;
    // the parity harness lists that as an explained difference.
    let l = name.to_ascii_lowercase();
    let k = l.get(..3)?;
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"].iter().position(|m| *m == k).map(|i| i as u32 + 1)
}

fn ymd(y: i64, m: i64, d: i64) -> Option<String> {
    let y = if y < 100 { y + 2000 } else { y };
    if !((1..=12).contains(&m) && (1..=31).contains(&d) && (1990..=2100).contains(&y)) {
        return None;
    }
    let s = format!("{y:04}-{m:02}-{d:02}");
    // A real calendar day (no 30 February).
    (js::iso_of(js::day_number(&s)?) == s).then_some(s)
}

/// US order for a/b/yyyy (the banks Hideout's people use); ISO and month names always.
pub fn parse_date(s: &str) -> Option<String> {
    static ISO: OnceLock<Regex> = OnceLock::new();
    static SLASH: OnceLock<Regex> = OnceLock::new();
    static DASH: OnceLock<Regex> = OnceLock::new();
    static DMY: OnceLock<Regex> = OnceLock::new();
    static MDY: OnceLock<Regex> = OnceLock::new();
    let v = js::trim(s);
    let n = |x: &str| x.parse::<i64>().unwrap_or(-1);
    if let Some(m) = re(&ISO, r"^([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})").captures(v) {
        return ymd(n(&m[1]), n(&m[2]), n(&m[3]));
    }
    if let Some(m) = re(&SLASH, r"^([0-9]{1,2})/([0-9]{1,2})/([0-9]{2,4})$").captures(v) {
        return ymd(n(&m[3]), n(&m[1]), n(&m[2]));
    }
    if let Some(m) = re(&DASH, r"^([0-9]{1,2})-([0-9]{1,2})-([0-9]{2,4})$").captures(v) {
        return ymd(n(&m[3]), n(&m[1]), n(&m[2]));
    }
    if let Some(m) = re(&DMY, r"^([0-9]{1,2})[ \-]([A-Za-z]{3,4})[a-z]*[ -,]*([0-9]{2,4})$").captures(v) {
        return month(&m[2]).and_then(|mo| ymd(n(&m[3]), mo as i64, n(&m[1])));
    }
    if let Some(m) = re(&MDY, r"^([A-Za-z]{3,4})[a-z]*\.? ([0-9]{1,2}),? ([0-9]{4})$").captures(v) {
        return month(&m[1]).and_then(|mo| ymd(n(&m[3]), mo as i64, n(&m[2])));
    }
    None
}

/// "$1,234.56" / "(15.99)" / "-15.99" / "15.99-" / "USD 15.99" -> a number, else None.
pub fn parse_amount(s: &str) -> Option<f64> {
    static CURRENCY: OnceLock<Regex> = OnceLock::new();
    static NUMBER: OnceLock<Regex> = OnceLock::new();
    let mut v = js::trim(s).to_string();
    if v.is_empty() {
        return None;
    }
    let mut neg = false;
    // /^\(.*\)$/ - JavaScript's "." does not cross a line break, so neither does this.
    if v.len() >= 2 && v.starts_with('(') && v.ends_with(')') && !v.contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
        neg = true;
        v = v[1..v.len() - 1].to_string();
    }
    if v.ends_with('-') {
        neg = true;
        v.pop();
    }
    v = re(&CURRENCY, r"(?i)[$€£]|USD|CAD|EUR|GBP|,|\s").replace_all(&v, "").into_owned();
    if let Some(rest) = v.strip_prefix('-') {
        neg = !neg;
        v = rest.to_string();
    }
    if let Some(rest) = v.strip_prefix('+') {
        v = rest.to_string();
    }
    if !re(&NUMBER, r"^[0-9]+(\.[0-9]{1,2})?$").is_match(&v) {
        return None;
    }
    let n: f64 = v.parse().ok()?;
    Some(if neg { -n } else { n })
}

// Money that moved but isn't a merchant charging on a schedule. Kept (a scam victim's
// Zelle or wire IS the story) but never counted as a subscription.
fn transfer_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"(?-u:\b)(ZELLE|VENMO|CASH ?APP|SQUARE CASH|WIRE|TRANSFER|XFER|ATM|WITHDRAWAL|CHECK ?#?[0-9]*|DEPOSIT|WESTERN UNION|MONEYGRAM|REMITLY|WISE(?-u:\b)|COINBASE|CRYPTO|BITCOIN|GIFT ?CARD)(?-u:\b)")
}

fn payment_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"(?-u:\b)(PAYMENT THANK YOU|AUTOPAY|AUTO PAY|ONLINE PAYMENT|MOBILE PAYMENT|PAYMENT RECEIVED|CRD AUTOPAY|EPAY|INTEREST CHARGE|LATE FEE|ANNUAL FEE|BALANCE TRANSFER)(?-u:\b)")
}

pub fn classify(descriptor: &str) -> &'static str {
    let d = descriptor.to_uppercase();
    if payment_re().is_match(&d) {
        "payment"
    } else if transfer_re().is_match(&d) {
        "transfer"
    } else {
        "merchant"
    }
}

#[derive(Debug, Clone, Copy)]
struct Cols {
    at: Option<usize>,
    date: Option<usize>,
    desc: usize,
    amount: Option<usize>,
    debit: Option<usize>,
    credit: Option<usize>,
}

fn find_header(rows: &[Vec<String>]) -> Option<Cols> {
    static DATE: OnceLock<Regex> = OnceLock::new();
    static PREFER: OnceLock<Regex> = OnceLock::new();
    static D1: OnceLock<Regex> = OnceLock::new();
    static D2: OnceLock<Regex> = OnceLock::new();
    static D3: OnceLock<Regex> = OnceLock::new();
    static AMT: OnceLock<Regex> = OnceLock::new();
    static DEBIT: OnceLock<Regex> = OnceLock::new();
    static CREDIT: OnceLock<Regex> = OnceLock::new();
    let date_re = re(&DATE, r"(?i)^(trans(action|\.)?\s*date|date|posted\s*date|post(ing)?\s*date|booking\s*date)$");
    let prefer = re(&PREFER, r"(?i)^trans");
    let descs = [
        re(&D1, r"(?i)^description$"),
        re(&D2, r"(?i)^(payee|merchant|merchant name|name|payee name)$"),
        re(&D3, r"(?i)^(transaction|details|memo|narrative|original description)$"),
    ];
    let amt = re(&AMT, r"(?i)^(amount|transaction amount|amount \(usd\)|amt)$");
    let debit = re(&DEBIT, r"(?i)^(debit|debits|withdrawal|withdrawals|money out|charges?|debit amount)$");
    let credit = re(&CREDIT, r"(?i)^(credit|credits|deposit|deposits|money in|payments?|credit amount)$");
    for (i, r) in rows.iter().take(20).enumerate() {
        let ai = r.iter().position(|c| amt.is_match(c));
        let dbi = r.iter().position(|c| debit.is_match(c));
        let desc = descs.iter().find_map(|d| r.iter().position(|c| d.is_match(c)));
        if let Some(desc) = desc {
            if ai.is_some() || dbi.is_some() {
                let dates: Vec<usize> = r.iter().enumerate().filter(|(_, c)| date_re.is_match(c)).map(|(k, _)| k).collect();
                let date = dates.iter().copied().find(|k| prefer.is_match(&r[*k])).or(dates.first().copied());
                return Some(Cols { at: Some(i), date, desc, amount: ai, debit: dbi, credit: r.iter().position(|c| credit.is_match(c)) });
            }
        }
    }
    None
}

/// No header (Wells Fargo) or an unrecognised one: pick columns by what the cells hold.
fn infer_columns(rows: &[Vec<String>]) -> Option<Cols> {
    let sample: Vec<&Vec<String>> = rows.iter().take(60).collect();
    let width = sample.iter().map(|r| r.len()).max().unwrap_or(0);
    fn cell(r: &[String], k: usize) -> &str {
        r.get(k).map(String::as_str).unwrap_or("")
    }
    let score = |k: usize, f: &dyn Fn(&str) -> bool| sample.iter().filter(|r| !cell(r, k).is_empty() && f(cell(r, k))).count();
    let looks_date = |c: &str| parse_date(c).is_some();
    let mut cols: Vec<usize> = (0..width).collect();
    cols.sort_by_key(|k| std::cmp::Reverse(score(*k, &looks_date)));
    let date = *cols.first()?;
    let need = sample.len() as f64 * 0.6;
    let amount = (0..width).filter(|k| *k != date).find(|k| score(*k, &|c: &str| parse_amount(c).is_some() && c.contains('.')) as f64 >= need);
    let letters = |k: usize| sample.iter().map(|r| cell(r, k).chars().filter(|c| c.is_ascii_alphabetic()).count()).sum::<usize>();
    let mut text: Vec<usize> = (0..width).filter(|k| *k != date && Some(*k) != amount).collect();
    text.sort_by_key(|k| std::cmp::Reverse(letters(*k)));
    let desc = text.first().copied();
    if (score(date, &looks_date) as f64) < need || amount.is_none() || desc.is_none() {
        return None;
    }
    Some(Cols { at: None, date: Some(date), desc: desc?, amount, debit: None, credit: None })
}

/// Read a statement. `rows` come out sorted by date, amounts positive, each with the
/// direction money moved and what kind of line it is.
pub fn parse_statement(text: &str) -> Parsed {
    let all = parse_delimited(text, None);
    let mut warnings = Vec::new();
    if all.is_empty() {
        return Parsed { rows: vec![], from: None, to: None, format: "empty".into(), skipped: 0, warnings: vec!["The file is empty.".into()] };
    }
    let header = find_header(&all);
    let format = if header.is_some() { "header" } else { "inferred" };
    let Some(cols) = header.or_else(|| infer_columns(&all)) else {
        return Parsed {
            rows: vec![],
            from: None,
            to: None,
            format: "unknown".into(),
            skipped: all.len(),
            warnings: vec!["Couldn't find the date, description and amount columns. Download the statement as CSV from your bank's website and try again.".into()],
        };
    };
    static SPACES: OnceLock<Regex> = OnceLock::new();
    let spaces = re(&SPACES, r"\s+");
    let body = &all[cols.at.map(|a| a + 1).unwrap_or(0)..];
    struct Raw {
        date: String,
        descriptor: String,
        signed: f64,
        split: bool,
    }
    let mut raw: Vec<Raw> = Vec::new();
    let mut skipped = 0usize;
    for r in body {
        let get = |k: Option<usize>| k.and_then(|k| r.get(k)).map(String::as_str).unwrap_or("");
        let date = cols.date.and_then(|_| parse_date(get(cols.date)));
        let descriptor = js::take(&mask_digits(&spaces.replace_all(get(Some(cols.desc)), " ")), 120);
        let mut signed: Option<f64> = None;
        let mut split = false;
        if cols.debit.is_some() {
            let d = parse_amount(get(cols.debit));
            let c = if cols.credit.is_some() { parse_amount(get(cols.credit)) } else { None };
            if let Some(d) = d.filter(|x| *x != 0.0) {
                signed = Some(-d.abs());
                split = true;
            } else if let Some(c) = c.filter(|x| *x != 0.0) {
                signed = Some(c.abs());
                split = true;
            }
        }
        if signed.is_none() && cols.amount.is_some() {
            signed = parse_amount(get(cols.amount));
        }
        match (date, signed) {
            (Some(date), Some(signed)) if !descriptor.is_empty() && signed != 0.0 => {
                raw.push(Raw { date, descriptor, signed, split });
                if raw.len() >= MAX_ROWS {
                    warnings.push(format!("Only the first {MAX_ROWS} rows were read."));
                    break;
                }
            }
            _ => skipped += 1,
        }
    }
    // Which sign is money going out? Split columns say so directly; a single Amount column
    // is decided by the majority of merchant rows (most rows on any statement are spending).
    let merchant_rows: Vec<&Raw> = raw.iter().filter(|x| !x.split && classify(&x.descriptor) == "merchant").collect();
    let neg = merchant_rows.iter().filter(|x| x.signed < 0.0).count();
    let out_is_negative = merchant_rows.is_empty() || neg >= merchant_rows.len() - neg;
    let mut rows: Vec<Row> = raw
        .iter()
        .map(|x| {
            // Split columns already carry the sign; a single Amount column uses the file's.
            let out = if x.split || out_is_negative { x.signed < 0.0 } else { x.signed > 0.0 };
            Row { date: x.date.clone(), descriptor: x.descriptor.clone(), amount: js::money(x.signed.abs()), direction: if out { "out" } else { "in" }.into(), kind: classify(&x.descriptor).into() }
        })
        .collect();
    rows.sort_by(|a, b| a.date.cmp(&b.date));
    if skipped > 3 && (skipped as f64) > rows.len() as f64 / 5.0 {
        warnings.push(format!("{skipped} lines couldn't be read and were skipped."));
    }
    Parsed { from: rows.first().map(|r| r.date.clone()), to: rows.last().map(|r| r.date.clone()), rows, format: format.into(), skipped, warnings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts() {
        assert_eq!(parse_amount("$1,234.56"), Some(1234.56));
        assert_eq!(parse_amount("(15.99)"), Some(-15.99));
        assert_eq!(parse_amount("15.99-"), Some(-15.99));
        assert_eq!(parse_amount("USD 9.99"), Some(9.99));
        assert_eq!(parse_amount("abc"), None);
        assert_eq!(parse_amount(""), None);
        assert_eq!(parse_amount("1.234"), None);
    }

    #[test]
    fn dates() {
        assert_eq!(parse_date("09/01/2026").as_deref(), Some("2026-09-01"));
        assert_eq!(parse_date("9/1/26").as_deref(), Some("2026-09-01"));
        assert_eq!(parse_date("2026-09-01").as_deref(), Some("2026-09-01"));
        assert_eq!(parse_date("Sep 1, 2026").as_deref(), Some("2026-09-01"));
        assert_eq!(parse_date("01 Sep 2026").as_deref(), Some("2026-09-01"));
        assert_eq!(parse_date("June 1, 2026").as_deref(), Some("2026-06-01"), "full month names read");
        assert_eq!(parse_date("02/30/2026"), None);
        assert_eq!(parse_date("hello"), None);
    }

    #[test]
    fn delimited_and_mask() {
        assert_eq!(parse_delimited("a,\"b, c\",\"say \"\"hi\"\"\"\n1,2,3", None), vec![vec!["a", "b, c", "say \"hi\""], vec!["1", "2", "3"]]);
        assert_eq!(mask_digits("Zelle Conf# 5829301746"), "Zelle Conf# ••1746");
        assert_eq!(mask_digits("card 4111 1111 1111 1111 x"), "card ••1111 x");
        assert_eq!(mask_digits("SHELL OIL 57444"), "SHELL OIL 57444");
    }

    #[test]
    fn kinds() {
        assert_eq!(classify("Zelle payment to JOHN"), "transfer");
        assert_eq!(classify("CHECKCARD GOOGLE *PLAY GIFT CARD"), "transfer");
        assert_eq!(classify("AUTOPAY PAYMENT - THANK YOU"), "payment");
        assert_eq!(classify("NETFLIX.COM"), "merchant");
    }
}
