//! The few places where JavaScript and Rust disagree about strings, numbers and dates,
//! pinned down so the Money engine gives exactly the answers app/src/money/*.mjs gave.

/// String.prototype.trim(): JavaScript's whitespace set, which includes the byte-order
/// mark (U+FEFF) and leaves out U+0085 - unlike Rust's `str::trim`.
pub fn trim(s: &str) -> &str {
    let ws = |c: char| {
        matches!(c, '\t' | '\n' | '\u{000B}' | '\u{000C}' | '\r' | ' ' | '\u{00A0}' | '\u{1680}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}')
            || ('\u{2000}'..='\u{200A}').contains(&c)
    };
    s.trim_matches(ws)
}

/// The first `n` characters (JavaScript's slice counts UTF-16 units; for the text a bank
/// statement carries that is the same thing).
pub fn take(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Math.round(n * 100) / 100 for the non-negative amounts Money rounds.
pub fn money(n: f64) -> f64 {
    (n * 100.0).round() / 100.0
}

/// Days since 1970-01-01 for a valid ISO date "YYYY-MM-DD" (what Date.parse gives, in days).
pub fn day_number(iso: &str) -> Option<i64> {
    let b = iso.as_bytes();
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let y: i64 = iso.get(0..4)?.parse().ok()?;
    let m: i64 = iso.get(5..7)?.parse().ok()?;
    let d: i64 = iso.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let yy = if m <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

pub fn iso_of(day: i64) -> String {
    let z = day + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

/// analyze.mjs `days(a, b)`: whole days from a to b.
pub fn days(a: &str, b: &str) -> i64 {
    match (day_number(a), day_number(b)) {
        (Some(x), Some(y)) => y - x,
        _ => 0,
    }
}

/// analyze.mjs `addDays(d, n)`.
pub fn add_days(d: &str, n: i64) -> String {
    day_number(d).map(|x| iso_of(x + n)).unwrap_or_default()
}

/// The median of a non-empty list (analyze.mjs `median`).
pub fn median(xs: &[f64]) -> f64 {
    let mut s = xs.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let m = s.len() >> 1;
    if s.len() % 2 == 1 {
        s[m]
    } else {
        (s[m - 1] + s[m]) / 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_trim_set() {
        assert_eq!(trim("\u{FEFF} a \u{00A0}"), "a");
        assert_eq!(trim("\u{0085}a"), "\u{0085}a", "NEL is not whitespace to JavaScript");
    }

    #[test]
    fn day_arithmetic() {
        assert_eq!(days("2026-08-05", "2026-09-01"), 27);
        assert_eq!(add_days("2026-09-01", 60), "2026-10-31");
        assert_eq!(add_days("2024-02-28", 1), "2024-02-29");
        assert_eq!(iso_of(day_number("2026-10-24").unwrap()), "2026-10-24");
    }

    #[test]
    fn rounding_and_median() {
        assert_eq!(money(15.494999), 15.49);
        assert_eq!(money(0.1 + 0.2), 0.3);
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[4.0, 1.0, 2.0, 3.0]), 2.5);
    }
}
