//! Local-time formatting, matching the formats the reports already use.

use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Local {
    pub year: u16,
    pub month: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
}

impl Local {
    /// "yyyy-MM-dd HH:mm" - hideout.ps1's scannedAt / arrived.
    pub fn minutes(&self) -> String {
        format!("{:04}-{:02}-{:02} {:02}:{:02}", self.year, self.month, self.day, self.hour, self.minute)
    }
    /// "yyyy-MM-ddTHH:mm:ss" - .NET's sortable "s" format, used by hunt.ps1.
    pub fn sortable(&self) -> String {
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", self.year, self.month, self.day, self.hour, self.minute, self.second)
    }
    /// "yyyy-MM-dd".
    pub fn date(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

const EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;

/// UTC FILETIME ticks (100 ns since 1601) -> local wall-clock time.
pub fn local_from_filetime(ticks: u64) -> Option<Local> {
    let ft = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    // SAFETY: pointers to locals.
    unsafe {
        FileTimeToSystemTime(&ft, &mut utc).ok()?;
        SystemTimeToTzSpecificLocalTime(None, &utc, &mut local).ok()?;
    }
    Some(Local { year: local.wYear, month: local.wMonth, day: local.wDay, hour: local.wHour, minute: local.wMinute, second: local.wSecond })
}

pub fn local_from_system_time(t: SystemTime) -> Option<Local> {
    let d = t.duration_since(UNIX_EPOCH).ok()?;
    let ticks = EPOCH_AS_FILETIME + d.as_secs() * 10_000_000 + (d.subsec_nanos() / 100) as u64;
    local_from_filetime(ticks)
}

pub fn local_from_unix(secs: i64) -> Option<Local> {
    if secs < 0 {
        return None;
    }
    local_from_filetime(EPOCH_AS_FILETIME + secs as u64 * 10_000_000)
}

pub fn now_local() -> Local {
    local_from_system_time(SystemTime::now()).unwrap_or(Local { year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0 })
}

/// Seconds since 1970, UTC.
pub fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// An OLE automation date (days since 1899-12-30, already local time, as the Task
/// Scheduler hands back) -> wall-clock fields. No time-zone conversion.
pub fn local_from_ole_date(d: f64) -> Option<Local> {
    if !(d.is_finite() && d > 1.0 && d < 2_958_466.0) {
        return None;
    }
    let days = d.floor() as i64;
    let mut secs = ((d - d.floor()) * 86400.0).round() as i64;
    let mut day_index = days - 25569; // 1970-01-01 is OLE day 25569
    if secs >= 86400 {
        secs -= 86400;
        day_index += 1;
    }
    let (y, m, dd) = civil_from_days(day_index);
    Some(Local { year: y as u16, month: m as u16, day: dd as u16, hour: (secs / 3600) as u16, minute: ((secs % 3600) / 60) as u16, second: (secs % 60) as u16 })
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trip() {
        for days in [-1000i64, 0, 1, 19_000, 20_385, 40_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), Some(days));
        }
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2026, 10, 24), Some(20_750));
    }

    #[test]
    fn ole_date() {
        // 2026-10-24 12:30:00 is OLE 46319.520833...
        let l = local_from_ole_date(46_319.0 + 12.5 / 24.0).unwrap();
        assert_eq!((l.year, l.month, l.day, l.hour, l.minute), (2026, 10, 24, 12, 30));
        assert!(local_from_ole_date(0.0).is_none());
    }

    #[test]
    fn formats() {
        let l = Local { year: 2026, month: 3, day: 4, hour: 5, minute: 6, second: 7 };
        assert_eq!(l.minutes(), "2026-03-04 05:06");
        assert_eq!(l.sortable(), "2026-03-04T05:06:07");
    }
}
