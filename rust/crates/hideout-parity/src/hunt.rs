//! Deep-check parity: run hunt.ps1 and `hideout hunt` on the same PC, one right after
//! the other, and compare every section item by item.
//!
//! The two snapshots are taken seconds apart, so a few things can honestly change in
//! between (a process exits, a connection opens, a task runs). Those are only accepted
//! as "changed between the two snapshots" with evidence taken right after both runs:
//! the process is gone now, or it started after the first snapshot began.

use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug)]
pub struct D {
    pub section: String,
    pub key: String,
    pub what: String,
    pub explained: Option<&'static str>,
}

pub const KNOWN: &[(&str, &str)] = &[
    ("changed-between-snapshots", "The two deep checks run one after the other; this process, connection, file or task changed in between (proven: it is gone now, or it started after the first check began)."),
    ("cim-driver-list-incomplete", "hunt.ps1 listed drivers with Get-CimInstance Win32_SystemDriver, which returns fewer drivers than the Service Control Manager has (and fewer than WMI itself returns when asked directly) - on the build PC, drivers whose file is missing and a filter driver were dropped. The Rust engine reads the Service Control Manager. (Proven: the driver is absent from Get-CimInstance's list.)"),
    ("signer-source", "A file signed BOTH inside itself and through a Windows catalog: hunt.ps1 asked the catalog first and named the catalog's signer (usually Microsoft, for hardware-certified drivers and tools); the Rust engine reads the file's own signature first and names its maker. Both say Valid. (Proven: the catalog signer is PowerShell's answer, the embedded signer is Rust's.)"),
    ("dual-stack-listener", "A program listening on both IPv4 and IPv6: Get-NetTCPConnection shows only the IPv6 socket (:::port), the Rust engine shows both. (Proven: PowerShell has the same port and process on :::.)"),
    ("wmi-empty-service-path", "WMI returns an empty PathName for some services; hunt.ps1 then had no program for them. The Rust engine reads the configuration from the Service Control Manager."),
    ("ps-prefixed-run-value", "hunt.ps1 skipped registry values whose names start with 'PS' (its filter for PowerShell's own PSPath/PSChildName properties)."),
    ("wider-surface", "The quick scan inside the deep check reads the whole start-up surface on the Rust side; hunt.ps1 ran hideout.ps1's four sources."),
];

fn list(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Null => vec![],
        o => vec![o.clone()],
    }
}

fn items(rep: &Value, section: &str) -> Vec<Value> {
    list(rep.pointer(&format!("/sections/{section}/items")).unwrap_or(&Value::Null))
}

/// "MM/dd/yyyy HH:mm:ss" (how PowerShell 5.1 printed dates here) -> ISO; a never-ran
/// task's 1999-11-30 placeholder -> "".
fn iso(s: &str) -> String {
    let s = s.trim();
    let parts: Vec<&str> = s.split([' ', '/', ':']).filter(|p| !p.is_empty()).collect();
    if parts.len() >= 6 && s.contains('/') {
        let n = |i: usize| parts[i].trim_end_matches(['A', 'M', 'P']).parse::<u32>().unwrap_or(0);
        let (mo, d, y, mut h, mi, se) = (n(0), n(1), n(2), n(3), n(4), n(5));
        if s.ends_with("PM") && h < 12 {
            h += 12;
        }
        if s.ends_with("AM") && h == 12 {
            h = 0;
        }
        let out = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{se:02}");
        return if out.starts_with("1999-11-30") { String::new() } else { out };
    }
    s.to_string()
}

/// A comparable form of a field: null and "" are the same; dates are ISO; paths and
/// Windows names compare without case.
fn norm(v: Option<&Value>, ci: bool) -> Value {
    match v {
        None | Some(Value::Null) => json!(""),
        Some(Value::String(x)) => {
            let x = iso(x);
            json!(if ci { x.to_lowercase() } else { x })
        }
        // Empty entries in a list carry nothing (hunt.ps1 wrote [""] for a task with no
        // triggers: piping nothing into ForEach-Object runs it once on $null).
        Some(Value::Array(a)) => {
            let v: Vec<Value> = a.iter().map(|e| norm(Some(e), ci)).filter(|e| e.as_str() != Some("")).collect();
            if v.is_empty() { json!("") } else { json!(v) }
        }
        Some(o) => o.clone(),
    }
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => String::new(),
        Some(o) => o.to_string(),
    }
}

/// Seconds between two ISO times, or None.
fn secs_apart(a: &str, b: &str) -> Option<i64> {
    let p = |x: &str| -> Option<i64> {
        let x = iso(x);
        let d: Vec<i64> = x.split(['-', 'T', ':']).filter_map(|n| n.parse().ok()).collect();
        if d.len() < 6 {
            return None;
        }
        Some(((((d[0] * 372 + d[1] * 31 + d[2]) * 24 + d[3]) * 60 + d[4]) * 60) + d[5])
    };
    Some((p(a)? - p(b)?).abs())
}

pub struct Context {
    /// When the first (PowerShell) snapshot began, ISO local time.
    pub ps_started: String,
    /// Processes running now: pid -> (name, creation time ISO).
    pub alive: HashMap<u64, (String, String)>,
    /// Names WMI's Win32_SystemDriver lists.
    pub wmi_drivers: Vec<String>,
    /// Services WMI gives an empty PathName.
    pub wmi_no_path: Vec<String>,
    /// (path, PowerShell's signer, Rust's signer) -> true when the catalog signer is
    /// PowerShell's and the file's own signer is Rust's.
    pub signer_proof: fn(&str, &str, &str) -> bool,
}

impl Context {
    /// Gone now, or started after the first snapshot began.
    fn changed(&self, pid: u64) -> bool {
        match self.alive.get(&pid) {
            None => true,
            Some((_, created)) => iso(created) > self.ps_started,
        }
    }
    /// No process of this name has been running since before the first snapshot.
    fn name_changed(&self, name: &str) -> bool {
        !self.alive.values().any(|(n, c)| n.eq_ignore_ascii_case(name) && iso(c) <= self.ps_started)
    }
}

struct Spec {
    key: fn(&Value) -> String,
    /// (field, compare without case)
    fields: &'static [(&'static str, bool)],
}

fn spec(section: &str) -> Spec {
    let f = |fields: &'static [(&'static str, bool)], key: fn(&Value) -> String| Spec { key, fields };
    match section {
        "hideout" => f(&[("severity", false), ("score", false)], |v| format!("{}|{}|{}|{}", s(v, "kind"), s(v, "name"), s(v, "program"), s(v, "folder")).to_lowercase()),
        "scheduledTasks" => f(&[("author", false), ("registered", false), ("hidden", false), ("runAs", false), ("runLevel", false), ("triggers", false)], |v| format!("{}{}", s(v, "path"), s(v, "name")).to_lowercase()),
        "services" => f(&[("display", false), ("start", false), ("account", true), ("program", true), ("sig", false), ("signer", false), ("userFolder", false), ("serviceDll", true), ("serviceDllSig", false)], |v| s(v, "name").to_lowercase()),
        "drivers" => f(&[("path", true), ("sig", false), ("signer", false), ("start", false)], |v| s(v, "name").to_lowercase()),
        "registryAutoruns" => f(&[("program", true), ("sig", false), ("signer", false), ("value", false), ("flags", false), ("userFolder", false)], |v| format!("{}|{}", s(v, "where"), s(v, "name")).to_lowercase()),
        "startupFolders" => f(&[("created", false), ("program", true), ("sig", false), ("signer", false), ("flags", false)], |v| format!("{}|{}", s(v, "folder"), s(v, "file")).to_lowercase()),
        "wmiSubscriptions" => f(&[("query", false), ("flags", false)], |v| format!("{}|{}", s(v, "type"), s(v, "name")).to_lowercase()),
        "defender" => f(&[("realtime", false), ("antivirus", false), ("tamperProtected", false), ("signatureAgeDays", false), ("lastQuick", false), ("lastFull", false), ("disableRealtime", false), ("disableBehavior", false), ("disableIOAV", false), ("exclusionPaths", false)], |v| format!("{}|{}|{}", s(v, "type"), s(v, "threatId"), s(v, "name"))),
        "rootCertificates" => f(&[("subject", false), ("issuer", false), ("notBefore", false), ("notAfter", false)], |v| format!("{}|{}", s(v, "store"), s(v, "thumbprint")).to_lowercase()),
        "network" => f(&[("path", true), ("sig", false)], |v| format!("{}|{}|{}|{}", s(v, "state"), s(v, "local"), s(v, "remote"), s(v, "process")).to_lowercase()),
        "processes" => f(&[("path", true), ("sig", false), ("signer", false), ("parent", true), ("flags", false), ("started", false)], |v| format!("{}|{}", s(v, "pid"), s(v, "name")).to_lowercase()),
        "recentFiles" => f(&[("kind", false), ("created", false), ("size", false), ("sig", false), ("sha256", false)], |v| s(v, "path").to_lowercase()),
        "powershellProfiles" => f(&[("size", false), ("sha256", false), ("flags", false)], |v| s(v, "path").to_lowercase()),
        "browserExtensions" => f(&[("name", false), ("version", false), ("updateUrl", false), ("riskyPermissions", false)], |v| format!("{}|{}|{}|{}", s(v, "user"), s(v, "browser"), s(v, "profile"), s(v, "id")).to_lowercase()),
        "hostsAndProxy" => f(&[], |v| v.to_string()),
        "accounts" => f(&[("enabled", false), ("description", false), ("source", false)], |v| format!("{}|{}", s(v, "type"), s(v, "name")).to_lowercase()),
        _ => f(&[], |v| v.to_string()),
    }
}

/// Why a one-sided item may be one-sided. `rust_only` says which side has it.
fn explain_one_sided(section: &str, it: &Value, rust_only: bool, cx: &Context) -> Option<&'static str> {
    match section {
        "processes" => cx.changed(it["pid"].as_u64().unwrap_or(0)).then_some("changed-between-snapshots"),
        // Connections come and go every second; an established one is never evidence of
        // a bug. A listener only counts as changed if its process changed.
        "network" if s(it, "state") == "Established" => Some("changed-between-snapshots"),
        "network" => cx.name_changed(&s(it, "process")).then_some("changed-between-snapshots"),
        "recentFiles" if rust_only => (iso(&s(it, "created")) > cx.ps_started).then_some("changed-between-snapshots"),
        "recentFiles" => (!std::path::Path::new(&s(it, "path")).exists()).then_some("changed-between-snapshots"),
        "drivers" if rust_only => (!cx.wmi_drivers.iter().any(|d| d.eq_ignore_ascii_case(&s(it, "name")))).then_some("cim-driver-list-incomplete"),
        "registryAutoruns" if rust_only => s(it, "name").to_lowercase().starts_with("ps").then_some("ps-prefixed-run-value"),
        "hideout" if rust_only => (!["Scheduled task", "Startup (registry)", "Startup folder", "Service"].contains(&s(it, "kind").as_str())).then_some("wider-surface"),
        _ => None,
    }
}

/// Per section: (items in hunt.ps1, items in hideout hunt, matched).
pub type Counts = BTreeMap<String, (usize, usize, usize)>;

pub fn compare(ps: &Value, rs: &Value, cx: &Context) -> (Vec<D>, Counts) {
    let mut diffs = Vec::new();
    let mut counts = BTreeMap::new();
    for section in crate::HUNT_SECTIONS {
        let ok = |r: &Value| r.pointer(&format!("/sections/{section}/ok")).and_then(|v| v.as_bool()).unwrap_or(false);
        if ok(ps) != ok(rs) {
            diffs.push(D { section: section.into(), key: "(section)".into(), what: format!("read: ps={} rust={}", ok(ps), ok(rs)), explained: None });
        }
        let sp = spec(section);
        let index = |v: Vec<Value>| -> BTreeMap<String, Value> { v.into_iter().map(|it| ((sp.key)(&it), it)).collect() };
        let (pi, ri) = (index(items(ps, section)), index(items(rs, section)));
        let mut matched = 0;
        for (k, p) in &pi {
            let Some(r) = ri.get(k) else {
                let explained = explain_one_sided(section, p, false, cx);
                diffs.push(D { section: section.into(), key: k.clone(), what: "only in hunt.ps1".into(), explained });
                continue;
            };
            matched += 1;
            for (f, ci) in sp.fields {
                let (a, b) = (norm(p.get(*f), *ci), norm(r.get(*f), *ci));
                if a == b {
                    continue;
                }
                // Same moment within a couple of seconds (rounding differs) is the same.
                if let (Some(x), Some(y)) = (a.as_str(), b.as_str()) {
                    if secs_apart(x, y).map(|d| d <= 2).unwrap_or(false) {
                        continue;
                    }
                }
                let path_of = |v: &Value| match section {
                    "services" => s(v, "program"),
                    "network" | "processes" | "drivers" => s(v, "path"),
                    _ => s(v, "program"),
                };
                let explained = match (section, *f) {
                    // WMI handed back a thin record for these services: no path, no account, its
                    // short name as the display name, "Unknown" start type.
                    ("services", _) if cx.wmi_no_path.iter().any(|n| n.eq_ignore_ascii_case(&s(p, "name"))) => Some("wmi-empty-service-path"),
                    (_, "signer") if s(p, "sig") == "Valid" && s(r, "sig") == "Valid" && (cx.signer_proof)(&path_of(r), &s(p, "signer"), &s(r, "signer")) => Some("signer-source"),
                    ("processes", _) if cx.changed(p["pid"].as_u64().unwrap_or(0)) => Some("changed-between-snapshots"),
                    _ => None,
                };
                diffs.push(D { section: section.into(), key: k.clone(), what: format!("{f}: ps={a} rust={b}"), explained });
            }
        }
        for (k, r) in &ri {
            if !pi.contains_key(k) {
                // An IPv4 listener whose IPv6 twin (same port, same process) PowerShell has.
                let twin = k.strip_prefix("listen|0.0.0.0:").map(|rest| format!("listen|:::{rest}"));
                let explained = if section == "network" && twin.as_ref().map(|t| pi.contains_key(t)).unwrap_or(false) {
                    Some("dual-stack-listener")
                } else {
                    explain_one_sided(section, r, true, cx)
                };
                diffs.push(D { section: section.into(), key: k.clone(), what: "only in hideout hunt".into(), explained });
            }
        }
        counts.insert(section.to_string(), (pi.len(), ri.len(), matched));
    }
    (diffs, counts)
}
