//! WMI queries (read-only WQL SELECTs). Used for what Windows only exposes there:
//! Defender's status and preferences, WMI event subscriptions, process command lines.
//!
//! Rows come back as JSON objects so each scan section can pick the fields it needs.
//! WMI's own conventions are kept: 64-bit integers arrive as strings, dates as
//! "yyyymmddHHMMSS.ffffff+zzz" strings.

use serde_json::{Map, Number, Value};
use windows::core::{BSTR, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoSetProxyBlanket, CLSCTX_INPROC_SERVER, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_IMP_LEVEL_IMPERSONATE, SAFEARRAY,
};
use windows::Win32::System::Ole::{SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound};
use windows::Win32::System::Variant::{
    VARENUM, VARIANT, VT_ARRAY, VT_BOOL, VT_BSTR, VT_DATE, VT_EMPTY, VT_I1, VT_I2, VT_I4, VT_I8, VT_NULL,
    VT_R4, VT_R8, VT_UI1, VT_UI2, VT_UI4, VT_UI8,
};
use windows::Win32::System::Wmi::{
    IEnumWbemClassObject, IWbemClassObject, IWbemLocator, WbemLocator, WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_NONSYSTEM_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE,
};

const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;

/// Run a WQL SELECT in `namespace` (e.g. "root\\cimv2"). Err when the namespace or the
/// query cannot be served - the caller reports that area as "could not check".
/// `limit` caps the rows kept, so one odd namespace cannot exhaust memory.
pub fn query(namespace: &str, wql: &str, limit: usize) -> Result<Vec<Map<String, Value>>, String> {
    crate::com::init();
    // SAFETY: COM activation and calls on live interfaces; every out-value is owned by
    // a Rust wrapper that releases it.
    unsafe {
        let loc: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER).map_err(|e| format!("WMI unavailable: {e}"))?;
        let svc = loc
            .ConnectServer(&BSTR::from(namespace), &BSTR::new(), &BSTR::new(), &BSTR::new(), 0, &BSTR::new(), None)
            .map_err(|e| format!("could not open {namespace}: {e}"))?;
        CoSetProxyBlanket(&svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, PCWSTR::null(), RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, None, EOAC_NONE)
            .map_err(|e| format!("could not secure the WMI connection: {e}"))?;
        let en: IEnumWbemClassObject = svc
            .ExecQuery(&BSTR::from("WQL"), &BSTR::from(wql), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, None)
            .map_err(|e| format!("query failed: {e}"))?;
        let mut rows = Vec::new();
        loop {
            let mut objs: [Option<IWbemClassObject>; 1] = [None];
            let mut got = 0u32;
            let hr = en.Next(WBEM_INFINITE, &mut objs, &mut got);
            if hr.is_err() {
                if rows.is_empty() {
                    return Err(format!("query failed: {}", windows::core::Error::from(hr)));
                }
                break;
            }
            if got == 0 {
                break;
            }
            let Some(obj) = objs[0].take() else { break };
            rows.push(object_to_json(&obj));
            if rows.len() >= limit {
                break;
            }
        }
        Ok(rows)
    }
}

/// Every non-system property of a WMI object.
fn object_to_json(obj: &IWbemClassObject) -> Map<String, Value> {
    let mut m = Map::new();
    // SAFETY: enumeration over a live object; each VARIANT is dropped (cleared) by Rust.
    unsafe {
        if obj.BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY.0).is_err() {
            return m;
        }
        loop {
            let mut name = BSTR::new();
            let mut v = VARIANT::default();
            let mut ty = 0i32;
            let mut flavor = 0i32;
            if obj.Next(0, &mut name, &mut v, &mut ty, &mut flavor).is_err() {
                break;
            }
            if name.is_empty() {
                break;
            }
            m.insert(name.to_string(), variant_to_json(&v));
        }
        let _ = obj.EndEnumeration();
        // The object's own class (a consumer's kind, e.g. CommandLineEventConsumer).
        let mut cls = VARIANT::default();
        if obj.Get(windows::core::w!("__CLASS"), 0, &mut cls, None, None).is_ok() {
            m.insert("__CLASS".into(), variant_to_json(&cls));
        }
    }
    m
}

fn num_f(x: f64) -> Value {
    Number::from_f64(x).map(Value::Number).unwrap_or(Value::Null)
}

/// VARIANT -> JSON. Unknown kinds become null rather than a guess.
pub fn variant_to_json(v: &VARIANT) -> Value {
    let vt: VARENUM = v.vt();
    // SAFETY: the union member read matches the type tag Windows set.
    unsafe {
        let u = &v.Anonymous.Anonymous.Anonymous;
        if vt.0 & VT_ARRAY.0 != 0 {
            return array_to_json(u.parray, VARENUM(vt.0 & !VT_ARRAY.0));
        }
        match vt {
            VT_EMPTY | VT_NULL => Value::Null,
            VT_BSTR => BSTR::try_from(v).map(|b| Value::String(b.to_string())).unwrap_or(Value::Null),
            VT_BOOL => Value::Bool(u.boolVal.as_bool()),
            VT_I1 => Value::from(u.cVal as i64),
            VT_UI1 => Value::from(u.bVal as i64),
            VT_I2 => Value::from(u.iVal as i64),
            VT_UI2 => Value::from(u.uiVal as i64),
            VT_I4 => Value::from(u.lVal as i64),
            VT_UI4 => Value::from(u.ulVal as i64),
            VT_I8 => Value::from(u.llVal),
            VT_UI8 => Value::from(u.ullVal),
            VT_R4 => num_f(u.fltVal as f64),
            VT_R8 => num_f(u.dblVal),
            VT_DATE => num_f(u.date),
            _ => Value::Null,
        }
    }
}

/// One-dimensional SAFEARRAY of a simple type -> JSON array.
///
/// # Safety
/// `psa` must be null or a valid SAFEARRAY whose element type is `elem`.
unsafe fn array_to_json(psa: *mut SAFEARRAY, elem: VARENUM) -> Value {
    if psa.is_null() {
        return Value::Null;
    }
    // SAFETY: bounds come from the array itself; each element is read into a value of
    // the matching type; a BSTR element is owned by the BSTR wrapper and freed.
    unsafe {
        let (Ok(lo), Ok(hi)) = (SafeArrayGetLBound(psa, 1), SafeArrayGetUBound(psa, 1)) else { return Value::Null };
        let mut out = Vec::new();
        let mut i = lo;
        while i <= hi && out.len() < 10_000 {
            let idx = i;
            let item = match elem {
                VT_BSTR => {
                    let mut b = BSTR::new();
                    if SafeArrayGetElement(psa, &idx, &mut b as *mut BSTR as *mut _).is_ok() { Value::String(b.to_string()) } else { Value::Null }
                }
                VT_I4 | VT_UI4 => {
                    let mut x = 0i32;
                    if SafeArrayGetElement(psa, &idx, &mut x as *mut i32 as *mut _).is_ok() { Value::from(if elem == VT_UI4 { x as u32 as i64 } else { x as i64 }) } else { Value::Null }
                }
                VT_I2 | VT_UI2 => {
                    let mut x = 0i16;
                    if SafeArrayGetElement(psa, &idx, &mut x as *mut i16 as *mut _).is_ok() { Value::from(if elem == VT_UI2 { x as u16 as i64 } else { x as i64 }) } else { Value::Null }
                }
                VT_UI1 | VT_I1 => {
                    let mut x = 0u8;
                    if SafeArrayGetElement(psa, &idx, &mut x as *mut u8 as *mut _).is_ok() { Value::from(x as i64) } else { Value::Null }
                }
                VT_BOOL => {
                    let mut x: i16 = 0;
                    if SafeArrayGetElement(psa, &idx, &mut x as *mut i16 as *mut _).is_ok() { Value::Bool(x != 0) } else { Value::Null }
                }
                _ => Value::Null,
            };
            out.push(item);
            i += 1;
        }
        Value::Array(out)
    }
}

/// WMI datetime "20261024133000.123456-420" -> seconds since 1970 (UTC). None if malformed.
pub fn wmi_datetime_to_unix(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 14 || !b[..14].iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n = |a: usize, l: usize| s[a..a + l].parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (n(0, 4)?, n(4, 2)?, n(6, 2)?, n(8, 2)?, n(10, 2)?, n(12, 2)?);
    let mut offset_min = 0i64;
    if b.len() >= 25 && (b[21] == b'+' || b[21] == b'-') {
        if let Ok(o) = s[22..25].parse::<i64>() {
            offset_min = if b[21] == b'-' { -o } else { o };
        }
    }
    let days = crate::time::days_from_civil(y, mo as u32, d as u32)?;
    Some(days * 86400 + h * 3600 + mi * 60 + se - offset_min * 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_operating_system() {
        let rows = query("root\\cimv2", "SELECT Caption, BuildNumber FROM Win32_OperatingSystem", 5).expect("wmi");
        assert_eq!(rows.len(), 1);
        assert!(rows[0]["Caption"].as_str().unwrap().contains("Windows"));
    }

    #[test]
    fn bad_namespace_is_an_error_not_empty() {
        assert!(query("root\\no_such_namespace_hideout", "SELECT * FROM X", 5).is_err());
    }

    #[test]
    fn datetime_parses_with_offset() {
        // 2026-01-01 00:00:00 at UTC-1h = 01:00 UTC.
        let t = wmi_datetime_to_unix("20260101000000.000000-060").unwrap();
        assert_eq!(t, 1_767_225_600 + 3600);
        assert!(wmi_datetime_to_unix("garbage").is_none());
    }
}
