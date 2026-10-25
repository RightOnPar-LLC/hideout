//! The deep check: a read-only evidence snapshot of everywhere malware usually hides.
//! A native port of hunt.ps1 - same 16 sections, same names, same item fields - plus
//! three areas hunt.ps1 did not have (security settings, remote-access tools, browser
//! settings), a link from each network connection to the start-up item behind its
//! program, and "what changed since the last deep check".
//!
//! NEVER deletes, moves, disables, runs or uploads anything. Command lines are NOT
//! copied whole: each gets behaviour flags, the URL hosts it names, and a snippet with
//! every long token-like run replaced by [redacted N chars]. File CONTENTS are never
//! copied (PowerShell profiles: size, date, hash, flags only; browser files: settings
//! only; password exports: the file NAME only).
//!
//! Each section reports `ok`, its items, how long it took and - when it could not be
//! read - why. A section that failed is never shown as "nothing found".

use crate::autostart;
use crate::quick;
use crate::rules::{program_path_ext, user_writable};
use crate::{par, sigcache};
use hideout_win::registry::{Hive, Key, Value as RegValue};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

pub const SECTIONS: [&str; 16] = [
    "hideout",
    "scheduledTasks",
    "services",
    "drivers",
    "registryAutoruns",
    "startupFolders",
    "wmiSubscriptions",
    "defender",
    "rootCertificates",
    "network",
    "processes",
    "recentFiles",
    "powershellProfiles",
    "browserExtensions",
    "hostsAndProxy",
    "accounts",
];
pub const EXTRA_SECTIONS: [&str; 3] = ["securitySettings", "remoteAccess", "browserSettings"];

/// Remote-support tools tech-support scammers commonly ask people to install. Being
/// installed is not proof of anything (IT departments use them too) - it is a question
/// to ask. The same list the Money tab uses.
pub const REMOTE_TOOLS: [&str; 20] = [
    "AnyDesk", "TeamViewer", "ScreenConnect", "ConnectWise Control", "Zoho Assist", "LogMeIn", "GoTo Resolve", "UltraViewer", "RustDesk", "Splashtop", "Supremo", "AeroAdmin", "Ammyy", "RemotePC",
    "Chrome Remote Desktop", "Remote Utilities", "HopToDesk", "DWService", "SimpleHelp", "Atera",
];

// ------------------------------------------------------------------ helpers (hunt.ps1)

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("valid built-in pattern"))
}

/// Behaviour flags of a command line (hunt.ps1 Get-Flags).
pub fn flags(s: &str) -> Vec<String> {
    static P: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    let pats = P.get_or_init(|| {
        [
            ("encoded-command", r"(?i)(^|\s)-(e|en|enc|enco|encod|encodedcommand)\s"),
            ("url", r"(?i)https?://"),
            ("download", r"(?i)downloadstring|downloadfile|invoke-webrequest|\biwr\b|start-bitstransfer|bitsadmin|certutil.*urlcache|curl(\.exe)?\s|wget\s"),
            ("policy-bypass", r"(?i)-(ep|exec|executionpolicy)\s+bypass"),
            ("hidden-window", r"(?i)-(w|win|windowstyle)\s+h(idden)?\b"),
            ("eval", r"(?i)frombase64string|\biex\b|invoke-expression"),
            ("long-base64", r"[A-Za-z0-9+/=]{120,}"),
            ("user-folder-path", r"(?i)\\(appdata|programdata|temp|users\\public)\\"),
            ("lolbin", r"(?i)\b(rundll32|regsvr32|mshta|wscript|cscript|msiexec|installutil|regasm|regsvcs|cmstp)\b"),
        ]
        .into_iter()
        .map(|(n, p)| (n, Regex::new(p).expect("valid flag pattern")))
        .collect()
    });
    if s.is_empty() {
        return vec![];
    }
    pats.iter().filter(|(_, r)| r.is_match(s)).map(|(n, _)| n.to_string()).collect()
}

/// Hosts named in URLs (hunt.ps1 Get-UrlHosts).
pub fn url_hosts(s: &str) -> Vec<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let mut out: Vec<String> = Vec::new();
    for c in re(&R, r#"(?i)https?://([^/\s"':]+)"#).captures_iter(s) {
        let h = c[1].to_string();
        if !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

/// A command line with every long token-like run replaced (hunt.ps1 Get-Redacted):
/// command lines carry passwords and API keys often enough.
pub fn redacted(s: &str) -> String {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(&R, r"[A-Za-z0-9+/=_\-\.%]{28,}").replace_all(s, |m: &regex::Captures| format!("[redacted {} chars]", m[0].chars().count())).to_string();
    if r.chars().count() > 240 {
        format!("{}...", r.chars().take(240).collect::<String>())
    } else {
        r
    }
}

/// hunt.ps1 Get-Sig: status and signer organisation, or None for no path.
fn sig(path: &str) -> Option<(String, String)> {
    if path.is_empty() {
        return None;
    }
    let p = Path::new(path);
    if !p.is_file() {
        return Some(("FileMissing".into(), String::new()));
    }
    let s = sigcache::check(p);
    Some((s.status.as_str().into(), crate::rules::org_from_subject(&s.subject)))
}

/// hunt.ps1 Describe-Command.
fn describe(exe: &str, args: &str) -> Map<String, Value> {
    let all = format!("{exe} {args}");
    let p = program_path_ext(exe);
    let mut o = Map::new();
    o.insert("program".into(), p.clone().map(Value::String).unwrap_or(Value::Null));
    o.insert("userFolder".into(), Value::Bool(p.as_deref().map(user_writable).unwrap_or(false)));
    if let Some((st, signer)) = p.as_deref().and_then(sig) {
        o.insert("sig".into(), json!(st));
        o.insert("signer".into(), json!(signer));
    }
    let fl = flags(&all);
    if !fl.is_empty() {
        o.insert("flags".into(), json!(fl));
        o.insert("snippet".into(), json!(redacted(args)));
    }
    let h = url_hosts(&all);
    if !h.is_empty() {
        o.insert("urlHosts".into(), json!(h));
    }
    o
}

fn sha256_upper(path: &str) -> String {
    let p = Path::new(path);
    if !p.is_file() {
        return String::new();
    }
    hideout_win::crypto::sha256_file_stream_upper(p).unwrap_or_else(|_| "unreadable".into())
}

fn iso(t: std::io::Result<std::time::SystemTime>) -> String {
    t.ok().and_then(hideout_win::time::local_from_system_time).map(|l| l.sortable()).unwrap_or_default()
}

fn wmi_iso(v: Option<&Value>) -> String {
    v.and_then(|x| x.as_str())
        .and_then(hideout_win::wmi::wmi_datetime_to_unix)
        .and_then(hideout_win::time::local_from_unix)
        .map(|l| l.sortable())
        .unwrap_or_default()
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => String::new(),
        Some(o) => o.to_string(),
    }
}

/// User profile folders (hunt.ps1 $users: C:\Users\* with an AppData, minus templates).
fn users() -> Vec<PathBuf> {
    autostart::profile_dirs()
}

fn hku_sids(suffix_classes: bool) -> Vec<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    static C: OnceLock<Regex> = OnceLock::new();
    let r = if suffix_classes { re(&C, r"^S-1-5-21-[\d-]+_Classes$") } else { re(&R, r"^S-1-5-21-[\d-]+$") };
    hideout_win::registry::loaded_user_hives().into_iter().filter(|s| r.is_match(s)).collect()
}

// ------------------------------------------------------------------ sections

fn sec_hideout(g: &quick::Gathered) -> Result<Vec<Value>, String> {
    let installed = quick::Installed::read();
    let r = quick::scan_with(g, &installed, false);
    Ok(r.findings.into_iter().map(|f| serde_json::to_value(f).unwrap_or(Value::Null)).collect())
}

fn sec_tasks() -> Result<Vec<Value>, String> {
    let l = hideout_win::tasks::list()?;
    Ok(l.tasks
        .iter()
        .map(|t| {
            let acts: Vec<Value> = t
                .actions
                .iter()
                .filter_map(|a| match a {
                    hideout_win::tasks::Action::Exec { path, args } => Some(Value::Object(describe(path, args))),
                    hideout_win::tasks::Action::ComHandler { class_id } => Some(json!({"comHandler": class_id})),
                    hideout_win::tasks::Action::Other => None,
                })
                .collect();
            json!({
                "path": t.folder, "name": t.name, "state": t.state, "author": t.author, "registered": t.date,
                "hidden": t.hidden, "runAs": t.user_id, "runLevel": t.run_level, "triggers": t.triggers,
                "lastRun": t.last_run.and_then(hideout_win::time::local_from_ole_date).map(|l| l.sortable()).unwrap_or_default(),
                "lastResult": t.last_result, "actions": acts,
            })
        })
        .collect())
}

fn sec_services() -> Result<Vec<Value>, String> {
    let v = hideout_win::services::list(hideout_win::services::Kind::Win32)?;
    Ok(par::map(&v, |svc| {
        let d = describe(&svc.path, "");
        let mut o = json!({
            "name": svc.name, "display": svc.display, "state": svc.state, "start": svc.start, "account": svc.account,
            "program": d.get("program").cloned().unwrap_or(Value::Null), "sig": d.get("sig").cloned().unwrap_or(Value::Null),
            "signer": d.get("signer").cloned().unwrap_or(Value::Null), "userFolder": d.get("userFolder").cloned().unwrap_or(json!(false)),
        });
        if svc.path.to_lowercase().contains("svchost.exe") {
            let key = format!(r"SYSTEM\CurrentControlSet\Services\{}\Parameters", svc.name);
            if let Some(dll) = Key::open(Hive::LocalMachine, &key).and_then(|k| k.string("ServiceDll")) {
                if let Some(dp) = program_path_ext(&dll) {
                    o["serviceDll"] = json!(dp);
                    if let Some((st, signer)) = sig(&dp) {
                        o["serviceDllSig"] = json!(st);
                        o["serviceDllSigner"] = json!(signer);
                    }
                }
            }
        }
        o
    })
    .into_iter()
    .flatten()
    .collect())
}

fn sec_drivers() -> Result<Vec<Value>, String> {
    static NORMAL: OnceLock<Regex> = OnceLock::new();
    let normal = re(&NORMAL, r"(?i)\\Windows\\System32\\(drivers|DriverStore)\\");
    let v = hideout_win::services::list(hideout_win::services::Kind::Driver)?;
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let rows = par::map(&v, |d| {
        let p = if d.path.is_empty() { format!(r"{windir}\system32\drivers\{}.sys", d.name) } else { program_path_ext(&d.path).unwrap_or_default() };
        let sg = sig(&p);
        if sg.as_ref().map(|(st, _)| st == "Valid").unwrap_or(false) && normal.is_match(&p) {
            return None;
        }
        let (st, signer) = sg.unwrap_or_default();
        Some(json!({"name": d.name, "state": d.state, "start": d.start, "path": p, "sig": st, "signer": signer}))
    });
    Ok(rows.into_iter().flatten().flatten().collect())
}

fn reg_open(path: &str) -> Option<Key> {
    // hunt.ps1 spells hives "HKLM:\SOFTWARE" and "Registry::HKEY_USERS\<sid>\SOFTWARE".
    if let Some(rest) = path.strip_prefix(r"HKLM:\") {
        Key::open(Hive::LocalMachine, rest)
    } else if let Some(rest) = path.strip_prefix(r"Registry::HKEY_USERS\") {
        Key::open(Hive::Users, rest)
    } else {
        None
    }
}

fn int_of(v: &RegValue) -> Option<i64> {
    match v {
        RegValue::Str(t) => {
            let t = t.trim();
            t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).map(|h| i64::from_str_radix(h, 16).ok()).unwrap_or_else(|| t.parse().ok())
        }
        o => o.as_i64(),
    }
}

fn sec_registry() -> Result<Vec<Value>, String> {
    let mut items = Vec::new();
    let mut hives = vec![r"HKLM:\SOFTWARE".to_string(), r"HKLM:\SOFTWARE\WOW6432Node".to_string()];
    for sid in hku_sids(false) {
        hives.push(format!(r"Registry::HKEY_USERS\{sid}\SOFTWARE"));
    }
    for h in &hives {
        for k in ["Run", "RunOnce", "RunServices", "RunServicesOnce", r"Policies\Explorer\Run"] {
            let key = format!(r"{h}\Microsoft\Windows\CurrentVersion\{k}");
            let Some(rk) = reg_open(&key) else { continue };
            for (name, v) in rk.values() {
                let val = v.to_ps_string();
                let d = describe(&val, &val);
                let g = |f: &str| d.get(f).cloned().unwrap_or(Value::Null);
                items.push(json!({"where": key, "name": if name.is_empty() { "(default)".into() } else { name }, "program": g("program"), "sig": g("sig"), "signer": g("signer"), "userFolder": g("userFolder"), "flags": g("flags"), "snippet": g("snippet"), "urlHosts": g("urlHosts")}));
            }
        }
        if let Some(wk) = reg_open(&format!(r"{h}\Microsoft\Windows NT\CurrentVersion\Winlogon")) {
            for v in ["Shell", "Userinit", "Taskman"] {
                if let Some(val) = wk.string(v).filter(|x| !x.is_empty()) {
                    items.push(json!({"where": format!(r"{h}\...\Winlogon"), "name": v, "value": redacted(&val)}));
                }
            }
        }
    }
    for base in [r"HKLM:\SOFTWARE", r"HKLM:\SOFTWARE\WOW6432Node"] {
        if let Some(ifeo) = reg_open(&format!(r"{base}\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")) {
            for exe in ifeo.subkeys() {
                let Some(e) = ifeo.subkey(&exe) else { continue };
                if let Some(d) = e.string("Debugger").filter(|x| !x.is_empty()) {
                    items.push(json!({"where": "IFEO Debugger", "name": exe, "value": redacted(&d)}));
                }
                if e.value("GlobalFlag").and_then(|v| int_of(&v)).map(|g| g & 0x200 != 0).unwrap_or(false) {
                    items.push(json!({"where": "IFEO GlobalFlag 0x200 (silent exit monitor)", "name": exe}));
                }
            }
        }
        if let Some(spe) = reg_open(&format!(r"{base}\Microsoft\Windows NT\CurrentVersion\SilentProcessExit")) {
            for exe in spe.subkeys() {
                if let Some(m) = spe.subkey(&exe).and_then(|e| e.string("MonitorProcess")).filter(|x| !x.is_empty()) {
                    items.push(json!({"where": "SilentProcessExit", "name": exe, "value": redacted(&m)}));
                }
            }
        }
        if let Some(w) = reg_open(&format!(r"{base}\Microsoft\Windows NT\CurrentVersion\Windows")) {
            if let Some(a) = w.string("AppInit_DLLs").filter(|x| !x.is_empty()) {
                let load = w.value("LoadAppInit_DLLs").map(|v| v.to_ps_string()).unwrap_or_default();
                items.push(json!({"where": format!("{base} AppInit_DLLs"), "name": format!("LoadAppInit={load}"), "value": a}));
            }
        }
    }
    if let Some(ac) = Key::open(Hive::LocalMachine, r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls") {
        for (name, v) in ac.values() {
            items.push(json!({"where": "AppCertDlls", "name": name, "value": v.to_ps_string()}));
        }
    }
    let lsa = Key::open(Hive::LocalMachine, r"SYSTEM\CurrentControlSet\Control\Lsa");
    for v in ["Authentication Packages", "Security Packages", "Notification Packages"] {
        let value = match lsa.as_ref().and_then(|k| k.value(v)) {
            Some(RegValue::Multi(m)) => m.join(", "),
            Some(o) => o.to_ps_string(),
            None => String::new(),
        };
        items.push(json!({"where": "LSA", "name": v, "value": value}));
    }
    static SYS: OnceLock<Regex> = OnceLock::new();
    let sys = re(&SYS, r"(?i)\\Windows\\(System32|SysWOW64)\\|\\Program Files");
    if let Some(a) = Key::open(Hive::LocalMachine, r"SOFTWARE\Microsoft\Active Setup\Installed Components") {
        for c in a.subkeys() {
            if let Some(sp) = a.subkey(&c).and_then(|e| e.string("StubPath")).filter(|x| !x.is_empty() && !sys.is_match(x)) {
                items.push(json!({"where": "Active Setup StubPath", "name": c, "value": redacted(&sp), "flags": flags(&sp)}));
            }
        }
    }
    for sid in hku_sids(true) {
        let Some(k) = Key::open(Hive::Users, &format!(r"{sid}\CLSID")) else { continue };
        for clsid in k.subkeys() {
            let srv = k
                .subkey(&format!(r"{clsid}\InprocServer32"))
                .and_then(|e| e.string(""))
                .filter(|x| !x.is_empty())
                .or_else(|| k.subkey(&format!(r"{clsid}\LocalServer32")).and_then(|e| e.string("")).filter(|x| !x.is_empty()));
            if let Some(srv) = srv {
                let p = program_path_ext(&srv).unwrap_or_default();
                let (st, signer) = sig(&p).unwrap_or_default();
                items.push(json!({"where": "User-hive COM override", "name": clsid, "program": p, "sig": st, "signer": signer}));
            }
        }
    }
    Ok(items)
}

fn sec_startup() -> Result<Vec<Value>, String> {
    let pd = std::env::var("ProgramData").unwrap_or_default();
    let mut dirs = vec![format!(r"{pd}\Microsoft\Windows\Start Menu\Programs\Startup")];
    for u in users() {
        dirs.push(u.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup").to_string_lossy().to_string());
    }
    let mut items = Vec::new();
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            if !e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let full = e.path().to_string_lossy().to_string();
            let (exe, args) = if full.to_lowercase().ends_with(".lnk") {
                hideout_win::links::read(&full).map(|l| (l.target, l.args)).unwrap_or_default()
            } else {
                (full.clone(), String::new())
            };
            let dsc = describe(&exe, &args);
            let g = |f: &str| dsc.get(f).cloned().unwrap_or(Value::Null);
            items.push(json!({"folder": d, "file": e.file_name().to_string_lossy(), "created": iso(e.metadata().and_then(|m| m.created())), "program": g("program"), "sig": g("sig"), "signer": g("signer"), "flags": g("flags"), "snippet": g("snippet")}));
        }
    }
    Ok(items)
}

fn sec_wmi() -> Result<Vec<Value>, String> {
    let mut items = Vec::new();
    for f in hideout_win::wmi::query(r"root\subscription", "SELECT * FROM __EventFilter", 1000)? {
        items.push(json!({"type": "filter", "name": s(&Value::Object(f.clone()), "Name"), "query": redacted(&s(&Value::Object(f), "Query"))}));
    }
    for c in hideout_win::wmi::query(r"root\subscription", "SELECT * FROM __EventConsumer", 1000)? {
        let c = Value::Object(c);
        let cmd = format!("{} {} {}", s(&c, "CommandLineTemplate"), s(&c, "ExecutablePath"), s(&c, "ScriptText"));
        items.push(json!({"type": format!("consumer:{}", s(&c, "__CLASS")), "name": s(&c, "Name"), "flags": flags(&cmd), "snippet": redacted(&cmd), "urlHosts": url_hosts(&cmd)}));
    }
    for b in hideout_win::wmi::query(r"root\subscription", "SELECT * FROM __FilterToConsumerBinding", 1000)? {
        let b = Value::Object(b);
        items.push(json!({"type": "binding", "filter": s(&b, "Filter"), "consumer": s(&b, "Consumer")}));
    }
    Ok(items)
}

fn sec_defender() -> Result<Vec<Value>, String> {
    let ns = r"root\Microsoft\Windows\Defender";
    let m = hideout_win::wmi::query(ns, "SELECT * FROM MSFT_MpComputerStatus", 2)?.into_iter().next().map(Value::Object).unwrap_or(Value::Null);
    let p = hideout_win::wmi::query(ns, "SELECT * FROM MSFT_MpPreference", 2).ok().and_then(|v| v.into_iter().next()).map(Value::Object).unwrap_or(Value::Null);
    let arr = |v: &Value, k: &str| match v.get(k) {
        Some(Value::Array(a)) => Value::Array(a.clone()),
        Some(Value::Null) | None => json!([]),
        Some(o) => json!([o]),
    };
    let mut items = vec![json!({
        "type": "status", "realtime": m.get("RealTimeProtectionEnabled"), "antivirus": m.get("AntivirusEnabled"), "tamperProtected": m.get("IsTamperProtected"),
        "signatureAgeDays": m.get("AntivirusSignatureAge"), "lastQuick": wmi_iso(m.get("QuickScanEndTime")), "lastFull": wmi_iso(m.get("FullScanEndTime")),
        "disableRealtime": p.get("DisableRealtimeMonitoring"), "disableBehavior": p.get("DisableBehaviorMonitoring"), "disableIOAV": p.get("DisableIOAVProtection"),
        "exclusionPaths": arr(&p, "ExclusionPath"), "exclusionProcesses": arr(&p, "ExclusionProcess"), "exclusionExtensions": arr(&p, "ExclusionExtension"), "exclusionIPs": arr(&p, "ExclusionIpAddress"),
    })];
    if let Ok(dets) = hideout_win::wmi::query(ns, "SELECT * FROM MSFT_MpThreatDetection", 2000) {
        for d in dets.into_iter().map(Value::Object) {
            items.push(json!({"type": "detection", "when": wmi_iso(d.get("InitialDetectionTime")), "threatId": d.get("ThreatID"), "resources": arr(&d, "Resources"), "actionSuccess": d.get("ActionSuccess")}));
        }
    }
    if let Ok(ts) = hideout_win::wmi::query(ns, "SELECT * FROM MSFT_MpThreat", 2000) {
        for t in ts.into_iter().map(Value::Object) {
            items.push(json!({"type": "threat", "name": t.get("ThreatName"), "severity": t.get("SeverityID"), "active": t.get("IsActive"), "resources": arr(&t, "Resources")}));
        }
    }
    Ok(items)
}

fn sec_certs() -> Result<Vec<Value>, String> {
    use hideout_win::certs::{list, Location};
    let mut items = Vec::new();
    for (loc, name, label) in [(Location::LocalMachine, "Root", r"Cert:\LocalMachine\Root"), (Location::CurrentUser, "Root", r"Cert:\CurrentUser\Root"), (Location::LocalMachine, "AuthRoot", r"Cert:\LocalMachine\AuthRoot")] {
        for c in list(loc, name)? {
            let d = |t: u64| hideout_win::time::local_from_filetime(t).map(|l| l.date()).unwrap_or_default();
            items.push(json!({"store": label, "subject": c.subject, "issuer": c.issuer, "notBefore": d(c.not_before), "notAfter": d(c.not_after), "thumbprint": c.thumbprint}));
        }
    }
    Ok(items)
}

/// Running processes from WMI (ProcessId -> row). Command lines stay in memory only.
fn processes() -> Result<HashMap<u32, Value>, String> {
    let rows = hideout_win::wmi::query(r"root\cimv2", "SELECT Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate FROM Win32_Process", 20_000)?;
    Ok(rows.into_iter().map(Value::Object).filter_map(|r| r.get("ProcessId").and_then(|v| v.as_u64()).map(|p| (p as u32, r))).collect())
}

fn sec_network(procs: &HashMap<u32, Value>, starts: &HashMap<String, Vec<String>>) -> Result<Vec<Value>, String> {
    static PRIVATE: OnceLock<Regex> = OnceLock::new();
    let private = re(&PRIVATE, r"(?i)^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.0\.0\.0|::1$|::$|fe80:|fd)");
    let conns = hideout_win::net::tcp()?;
    let mut items = Vec::new();
    for c in conns.into_iter().filter(|c| c.state == "Listen" || c.state == "Established") {
        if c.state == "Established" && private.is_match(&c.remote_addr) {
            continue;
        }
        let pr = procs.get(&c.pid);
        let path = pr.map(|p| s(p, "ExecutablePath")).unwrap_or_default();
        let (st, signer) = sig(&path).unwrap_or_default();
        let mut o = json!({
            "state": c.state, "local": format!("{}:{}", c.local_addr, c.local_port),
            "remote": if c.state == "Established" { format!("{}:{}", c.remote_addr, c.remote_port) } else { String::new() },
            "process": pr.map(|p| s(p, "Name")).unwrap_or_else(|| format!("pid {}", c.pid)), "path": path, "sig": st, "signer": signer,
        });
        // Which start-up items launch this program: a program phoning home is shown
        // together with whatever brings it back after a restart.
        if let Some(srcs) = starts.get(&path.to_lowercase()).filter(|v| !path.is_empty() && !v.is_empty()) {
            o["startsBy"] = json!(srcs);
        }
        items.push(o);
    }
    Ok(items)
}

fn sec_processes(procs: &HashMap<u32, Value>) -> Result<Vec<Value>, String> {
    let mut list: Vec<&Value> = procs.values().collect();
    list.sort_by_key(|p| p.get("ProcessId").and_then(|v| v.as_u64()).unwrap_or(0));
    let rows = par::map(&list, |p| {
        let path = s(p, "ExecutablePath");
        if path.is_empty() {
            return None;
        }
        let (st, signer) = sig(&path).unwrap_or_default();
        let fl = flags(&s(p, "CommandLine"));
        let odd = user_writable(&path) || st != "Valid";
        if !odd && !fl.iter().any(|f| ["encoded-command", "download", "eval", "long-base64"].contains(&f.as_str())) {
            return None;
        }
        let ppid = p.get("ParentProcessId").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let parent = procs.get(&ppid).map(|pp| s(pp, "Name")).unwrap_or_else(|| format!("pid {ppid} (gone)"));
        let mut o = json!({"name": s(p, "Name"), "pid": p.get("ProcessId"), "path": path, "sig": st, "signer": signer, "started": wmi_iso(p.get("CreationDate")), "parent": parent});
        if !fl.is_empty() {
            o["flags"] = json!(fl);
            o["snippet"] = json!(redacted(&s(p, "CommandLine")));
        }
        if st != "Valid" {
            o["sha256"] = json!(sha256_upper(&path));
        }
        Some(o)
    });
    Ok(rows.into_iter().flatten().flatten().collect())
}

const RECENT_EXTS: [&str; 19] = [".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl", ".msi", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".lnk", ".jar"];

fn walk(dir: &Path, depth: i32, out: &mut Vec<(PathBuf, std::fs::Metadata)>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        let p = e.path();
        if ft.is_dir() && !ft.is_symlink() {
            // Folder junctions and links are not followed (they loop, or lead off the disk).
            if depth > 0 {
                walk(&p, depth - 1, out);
            }
        } else if ft.is_file() || (ft.is_symlink() && std::fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false)) {
            // A linked FILE counts (package managers put their programs behind links); its
            // own dates are the link's, as Get-ChildItem reports them.
            if let Ok(m) = e.metadata() {
                out.push((p, m));
            }
        }
    }
}

fn sec_recent(days: u32) -> Result<Vec<Value>, String> {
    static SKIP: OnceLock<Regex> = OnceLock::new();
    let skip = re(&SKIP, r"(?i)\\(node_modules|\.git|INetCache|Packages|WinSxS|npm-cache|_npx|pip\\cache|Code Cache|GPUCache|Service Worker|CacheStorage|User Data\\[^\\]+\\(Cache|Code Cache))\\|\\Temp\\claude\\|\\Microsoft\\WindowsApps\\");
    let cut = std::time::SystemTime::now() - std::time::Duration::from_secs(days as u64 * 86400);
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let mut roots: Vec<(PathBuf, i32)> = vec![(PathBuf::from(env("ProgramData")), 3), (PathBuf::from(env("WINDIR")).join("Temp"), 2), (PathBuf::from(env("PUBLIC")), 3)];
    for u in users() {
        roots.push((u.join(r"AppData\Roaming"), 4));
        roots.push((u.join(r"AppData\Local"), 3));
        roots.push((u.join(r"AppData\LocalLow"), 3));
        roots.push((u.join("Downloads"), 2));
        roots.push((u.join("Desktop"), 1));
    }
    let mut picked: Vec<(String, std::fs::Metadata)> = Vec::new();
    'roots: for (r, d) in roots {
        let mut files = Vec::new();
        walk(&r, d, &mut files);
        for (p, m) in files {
            let full = p.to_string_lossy().to_string();
            let ext = p.extension().map(|e| format!(".{}", e.to_string_lossy().to_lowercase())).unwrap_or_default();
            let created = m.created().unwrap_or(std::time::UNIX_EPOCH);
            if created < cut || !RECENT_EXTS.contains(&ext.as_str()) || skip.is_match(&full) {
                continue;
            }
            picked.push((full, m));
            if picked.len() >= 5000 {
                break 'roots;
            }
        }
    }
    let rows = par::map(&picked, |(full, m)| {
        let l = full.to_lowercase();
        let is_pe = [".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl"].iter().any(|e| l.ends_with(e));
        let created = iso(m.created());
        if is_pe {
            let (st, _) = sig(full).unwrap_or_default();
            if st == "Valid" {
                return None;
            }
            Some(json!({"kind": "program", "path": full, "created": created, "size": m.len(), "sig": st, "sha256": sha256_upper(full)}))
        } else {
            Some(json!({"kind": "script-or-shortcut", "path": full, "created": created, "size": m.len()}))
        }
    });
    Ok(rows.into_iter().flatten().flatten().collect())
}

fn sec_profiles() -> Result<Vec<Value>, String> {
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let pshome = format!(r"{windir}\System32\WindowsPowerShell\v1.0");
    let mut files: Vec<PathBuf> = vec![PathBuf::from(&pshome).join("profile.ps1"), PathBuf::from(&pshome).join("Microsoft.PowerShell_profile.ps1")];
    for u in users() {
        for sub in [r"Documents\WindowsPowerShell", r"Documents\PowerShell", r"OneDrive\Documents\WindowsPowerShell", r"OneDrive\Documents\PowerShell"] {
            if let Ok(rd) = std::fs::read_dir(u.join(sub)) {
                for e in rd.flatten() {
                    if e.file_name().to_string_lossy().to_lowercase().ends_with("profile.ps1") {
                        files.push(e.path());
                    }
                }
            }
        }
    }
    let mut seen = BTreeSet::new();
    let mut items = Vec::new();
    for f in files {
        let Ok(m) = std::fs::metadata(&f) else { continue };
        if !m.is_file() || !seen.insert(f.to_string_lossy().to_lowercase()) {
            continue;
        }
        // Read for its flags only; the text itself never leaves this function.
        let text = std::fs::read(&f).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        let full = f.to_string_lossy().to_string();
        items.push(json!({"path": full, "size": m.len(), "modified": iso(m.modified()), "sha256": sha256_upper(&full), "flags": flags(&text), "urlHosts": url_hosts(&text)}));
    }
    Ok(items)
}

const CHROMIUM: [(&str, &str); 4] = [(r"Google\Chrome", r"Google\Chrome"), (r"Microsoft\Edge", r"Microsoft\Edge"), (r"BraveSoftware\Brave-Browser", r"BraveSoftware\Brave-Browser"), ("Vivaldi", "Vivaldi")];

/// Every Chromium profile folder: (user, browser, profile name, path).
fn chromium_profiles() -> Vec<(String, String, String, PathBuf)> {
    let mut out = Vec::new();
    for u in users() {
        let user = u.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        for (b, label) in CHROMIUM {
            let ud = u.join(r"AppData\Local").join(b).join("User Data");
            let Ok(rd) = std::fs::read_dir(&ud) else { continue };
            for e in rd.flatten() {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    out.push((user.clone(), label.to_string(), e.file_name().to_string_lossy().to_string(), e.path()));
                }
            }
        }
    }
    out
}

/// One installed extension folder (`Extensions\<id>`): its newest version's manifest,
/// reduced to name, version, update URL and the permissions that matter.
pub fn read_extension(ext_dir: &Path) -> Option<(String, String, String, Vec<String>)> {
    const RISKY: [&str; 12] = ["<all_urls>", "webRequest", "webRequestBlocking", "cookies", "debugger", "nativeMessaging", "proxy", "declarativeNetRequest", "history", "clipboardRead", "management", "scripting"];
    let mut versions: Vec<PathBuf> = std::fs::read_dir(ext_dir).ok()?.flatten().filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false)).map(|e| e.path()).collect();
    versions.sort_by_key(|p| std::cmp::Reverse(p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default()));
    let v = versions.first()?;
    // Read with a cap: a manifest is a few KB; anything huge is not one.
    let bytes = std::fs::read(v.join("manifest.json")).ok().filter(|b| b.len() <= 4 * 1024 * 1024)?;
    let m: Value = serde_json::from_slice(strip_bom(&bytes)).ok()?;
    let mut perms: Vec<String> = Vec::new();
    for k in ["permissions", "host_permissions", "optional_permissions"] {
        for p in m.get(k).and_then(|a| a.as_array()).into_iter().flatten() {
            let p = match p {
                Value::String(x) => x.clone(),
                o => o.to_string(),
            };
            let all_hosts = p == "*://*/*" || p == "http://*/*" || p == "https://*/*";
            if (RISKY.contains(&p.as_str()) || all_hosts) && !perms.contains(&p) {
                perms.push(p);
            }
        }
    }
    Some((s(&m, "name"), s(&m, "version"), s(&m, "update_url"), perms))
}

fn sec_extensions() -> Result<Vec<Value>, String> {
    let mut items = Vec::new();
    for (user, browser, profile, path) in chromium_profiles() {
        let Ok(rd) = std::fs::read_dir(path.join("Extensions")) else { continue };
        for ext in rd.flatten().filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false)) {
            let Some((name, version, update, perms)) = read_extension(&ext.path()) else { continue };
            items.push(json!({"user": user, "browser": browser, "profile": profile, "id": ext.file_name().to_string_lossy(), "name": name, "version": version, "updateUrl": update, "riskyPermissions": perms}));
        }
    }
    Ok(items)
}

/// The entries in a hosts file: every line that is not blank or a comment. A UTF-8
/// byte-order mark at the start is not part of the first line.
pub fn hosts_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(strip_bom(bytes)).lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from).collect()
}

fn strip_bom(b: &[u8]) -> &[u8] {
    b.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(b)
}

fn sec_hosts_proxy() -> Result<Vec<Value>, String> {
    let mut items = Vec::new();
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    if let Ok(t) = std::fs::read(format!(r"{windir}\System32\drivers\etc\hosts")) {
        for l in hosts_lines(&t) {
            items.push(json!({"type": "hosts", "line": l}));
        }
    }
    let mut keys: Vec<(Hive, String, String)> = vec![(Hive::CurrentUser, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings".into(), r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings".into())];
    for sid in hku_sids(false) {
        keys.push((Hive::Users, format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Internet Settings"), format!(r"Registry::HKEY_USERS\{sid}\Software\Microsoft\Windows\CurrentVersion\Internet Settings")));
    }
    for (hive, path, label) in keys {
        let Some(k) = Key::open(hive, &path) else { continue };
        let en = k.value("ProxyEnable").and_then(|v| v.as_i64()).unwrap_or(0);
        let server = k.string("ProxyServer").unwrap_or_default();
        let pac = k.string("AutoConfigURL").unwrap_or_default();
        if en != 0 || !server.is_empty() || !pac.is_empty() {
            items.push(json!({"type": "proxy", "where": label, "enabled": en, "server": server, "autoConfigUrl": pac}));
        }
    }
    Ok(items)
}

fn sec_accounts() -> Result<Vec<Value>, String> {
    let now = hideout_win::time::now_unix();
    let mut items: Vec<Value> = hideout_win::accounts::users()?
        .into_iter()
        .map(|u| {
            let t = |x: Option<i64>| x.and_then(hideout_win::time::local_from_unix).map(|l| l.sortable()).unwrap_or_default();
            json!({"type": "user", "name": u.name, "enabled": u.enabled, "lastLogon": t(u.last_logon), "passwordSet": t(Some(now - u.password_age as i64)), "description": u.description})
        })
        .collect();
    let me = std::env::var("COMPUTERNAME").unwrap_or_default();
    for m in hideout_win::accounts::administrators()? {
        let dom = m.name.split('\\').next().unwrap_or("").to_string();
        // Windows' own answer first (a local account linked to a Microsoft account is
        // "MicrosoftAccount"); the name's domain only when Windows will not say.
        let source = if !m.source.is_empty() {
            m.source.as_str()
        } else if dom.eq_ignore_ascii_case("MicrosoftAccount") {
            "MicrosoftAccount"
        } else if dom.eq_ignore_ascii_case("AzureAD") {
            "AzureAD"
        } else if dom.eq_ignore_ascii_case(&me) || dom.eq_ignore_ascii_case("BUILTIN") || dom.eq_ignore_ascii_case("NT AUTHORITY") {
            "Local"
        } else {
            "ActiveDirectory"
        };
        items.push(json!({"type": "administrator", "name": m.name, "source": source}));
    }
    Ok(items)
}

// ------------------------------------------------------------------ new areas

fn sec_security() -> Result<Vec<Value>, String> {
    let mut items = Vec::new();
    for (key, label) in [("DomainProfile", "Domain"), ("StandardProfile", "Private"), ("PublicProfile", "Public")] {
        let base = Key::open(Hive::LocalMachine, &format!(r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{key}")).and_then(|k| k.value("EnableFirewall")).and_then(|v| v.as_i64());
        let policy = Key::open(Hive::LocalMachine, &format!(r"SOFTWARE\Policies\Microsoft\WindowsFirewall\{key}")).and_then(|k| k.value("EnableFirewall")).and_then(|v| v.as_i64());
        let on = policy.or(base);
        items.push(json!({"type": "firewall", "profile": label, "enabled": on.map(|x| x != 0), "setByPolicy": policy.is_some()}));
    }
    let sys = Key::open(Hive::LocalMachine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
    let g = |n: &str| sys.as_ref().and_then(|k| k.value(n)).and_then(|v| v.as_i64());
    items.push(json!({"type": "uac", "enabled": g("EnableLUA").map(|x| x != 0), "consentPromptBehaviorAdmin": g("ConsentPromptBehaviorAdmin"), "secureDesktop": g("PromptOnSecureDesktop").map(|x| x != 0)}));
    match hideout_win::wmi::query(r"root\SecurityCenter2", "SELECT displayName, productState, pathToSignedProductExe FROM AntiVirusProduct", 50) {
        Ok(rows) => {
            for r in rows.into_iter().map(Value::Object) {
                let st = r.get("productState").and_then(|v| v.as_i64()).unwrap_or(0);
                // productState: byte 2 = scanner (0x10/0x11 on), byte 1 = definitions (0x00 up to date).
                let scanner = (st >> 8) & 0xFF;
                let defs = st & 0xFF;
                items.push(json!({"type": "antivirus", "name": s(&r, "displayName"), "enabled": scanner == 0x10 || scanner == 0x11, "upToDate": defs == 0, "path": s(&r, "pathToSignedProductExe")}));
            }
        }
        Err(e) => items.push(json!({"type": "antivirus", "error": e})),
    }
    let ts = Key::open(Hive::LocalMachine, r"SYSTEM\CurrentControlSet\Control\Terminal Server");
    let deny = ts.as_ref().and_then(|k| k.value("fDenyTSConnections")).and_then(|v| v.as_i64());
    let nla = Key::open(Hive::LocalMachine, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").and_then(|k| k.value("UserAuthentication")).and_then(|v| v.as_i64());
    items.push(json!({"type": "remoteDesktop", "enabled": deny.map(|d| d == 0), "networkLevelAuth": nla.map(|n| n != 0)}));
    Ok(items)
}

fn sec_remote(g: &quick::Gathered, procs: &HashMap<u32, Value>) -> Result<Vec<Value>, String> {
    let mut installed: Vec<(String, String)> = Vec::new();
    for (hive, path) in [
        (Hive::LocalMachine, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (Hive::LocalMachine, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (Hive::CurrentUser, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ] {
        let Some(k) = Key::open(hive, path) else { continue };
        for sub in k.subkeys() {
            if let Some(e) = k.subkey(&sub) {
                if let Some(n) = e.string("DisplayName").filter(|n| !n.is_empty()) {
                    installed.push((n, e.string("InstallDate").unwrap_or_default()));
                }
            }
        }
    }
    let squash = |t: &str| t.to_lowercase().replace(' ', "");
    let mut items = Vec::new();
    for tool in REMOTE_TOOLS {
        let t = tool.to_lowercase();
        let tq = squash(tool);
        let inst: Vec<&(String, String)> = installed.iter().filter(|(n, _)| n.to_lowercase().contains(&t)).collect();
        let running: Vec<String> = procs.values().map(|p| s(p, "Name")).filter(|n| squash(n).contains(&tq)).collect::<BTreeSet<_>>().into_iter().collect();
        let starts: Vec<String> = g
            .entries
            .iter()
            .filter(|e| squash(&e.name).contains(&tq) || e.program.as_deref().map(|p| squash(p).contains(&tq)).unwrap_or(false))
            .map(|e| format!("{}: {}", e.source, e.name))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if inst.is_empty() && running.is_empty() && starts.is_empty() {
            continue;
        }
        let date = inst.iter().map(|(_, d)| d.clone()).find(|d| d.len() == 8 && d.chars().all(|c| c.is_ascii_digit())).map(|d| format!("{}-{}-{}", &d[..4], &d[4..6], &d[6..]));
        items.push(json!({"tool": tool, "installed": inst.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(), "installedOn": date, "running": running, "startsByItself": starts}));
    }
    Ok(items)
}

/// Well-known banks and payment services: brand word -> the domains that are really
/// theirs. A bookmark whose host has the brand as a whole label but is none of these
/// domains is a look-alike worth a second look.
const BANKS: [(&str, &[&str]); 26] = [
    ("chase", &["chase.com"]),
    ("bankofamerica", &["bankofamerica.com", "bofa.com"]),
    ("wellsfargo", &["wellsfargo.com", "wf.com"]),
    ("citi", &["citi.com", "citibank.com"]),
    ("citibank", &["citi.com", "citibank.com"]),
    ("capitalone", &["capitalone.com"]),
    ("usbank", &["usbank.com"]),
    ("pnc", &["pnc.com"]),
    ("truist", &["truist.com"]),
    ("tdbank", &["td.com", "tdbank.com"]),
    ("navyfederal", &["navyfederal.org", "navyfcu.org"]),
    ("usaa", &["usaa.com"]),
    ("paypal", &["paypal.com", "paypal.me"]),
    ("venmo", &["venmo.com"]),
    ("zelle", &["zellepay.com", "zelle.com"]),
    ("americanexpress", &["americanexpress.com", "aexp.com"]),
    ("amex", &["americanexpress.com", "amex.com"]),
    ("discover", &["discover.com"]),
    ("schwab", &["schwab.com"]),
    ("fidelity", &["fidelity.com"]),
    ("vanguard", &["vanguard.com"]),
    ("coinbase", &["coinbase.com"]),
    ("ally", &["ally.com"]),
    ("regions", &["regions.com"]),
    ("hsbc", &["hsbc.com", "hsbc.co.uk", "us.hsbc.com"]),
    ("barclays", &["barclays.co.uk", "barclays.com", "barclaycardus.com"]),
];

pub fn lookalike_bank(host: &str) -> Option<&'static str> {
    let h = host.trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = h.split(['.', '-']).collect();
    for (brand, domains) in BANKS {
        if !labels.contains(&brand) {
            continue;
        }
        let real = domains.iter().any(|d| h == *d || h.ends_with(&format!(".{d}")));
        if !real {
            return Some(brand);
        }
    }
    None
}

fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    host.split(':').next().unwrap_or("").to_lowercase()
}

const KNOWN_SEARCH: [&str; 12] = ["google.", "bing.com", "duckduckgo.com", "yahoo.com", "ecosia.org", "search.brave.com", "startpage.com", "yandex.", "baidu.com", "naver.com", "qwant.com", "you.com"];

fn sec_browser_settings() -> Result<Vec<Value>, String> {
    let mut items = Vec::new();
    for (user, browser, profile, path) in chromium_profiles() {
        if let Some(p) = std::fs::read(path.join("Preferences")).ok().and_then(|b| serde_json::from_slice::<Value>(strip_bom(&b)).ok()) {
            let restore = p.pointer("/session/restore_on_startup").and_then(|v| v.as_i64()).unwrap_or(0);
            let startup: Vec<String> = if restore == 4 { p.pointer("/session/startup_urls").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default() } else { vec![] };
            let search_url = p.pointer("/default_search_provider_data/template_url_data/url").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let search_name = p.pointer("/default_search_provider_data/template_url_data/short_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let sh = host_of(&search_url);
            let unusual = !sh.is_empty() && !KNOWN_SEARCH.iter().any(|k| sh.contains(k));
            items.push(json!({"type": "settings", "user": user, "browser": browser, "profile": profile, "homepage": p.pointer("/homepage").and_then(|v| v.as_str()).unwrap_or(""), "startupPages": startup, "searchEngine": search_name, "searchHost": sh, "unusualSearch": unusual}));
        }
        if let Some(b) = std::fs::read(path.join("Bookmarks")).ok().and_then(|b| serde_json::from_slice::<Value>(strip_bom(&b)).ok()) {
            let mut urls = Vec::new();
            collect_bookmarks(&b, &mut urls, 0);
            for (name, url) in urls {
                if let Some(brand) = lookalike_bank(&host_of(&url)) {
                    items.push(json!({"type": "lookalikeBookmark", "user": user, "browser": browser, "profile": profile, "name": name, "host": host_of(&url), "looksLike": brand}));
                }
            }
        }
    }
    // Signs that saved passwords were exported: a file NAMED like a password export.
    // Only the name and date are recorded; the file is never opened.
    static PW: OnceLock<Regex> = OnceLock::new();
    let pw = re(&PW, r"(?i)(password|passwords|passwort|logins?|credentials)[^\\]*\.(csv|txt|json|xlsx?)$");
    for u in users() {
        for sub in ["Downloads", "Desktop", "Documents"] {
            let Ok(rd) = std::fs::read_dir(u.join(sub)) else { continue };
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if e.file_type().map(|t| t.is_file()).unwrap_or(false) && pw.is_match(&n) {
                    items.push(json!({"type": "passwordExport", "path": e.path().to_string_lossy(), "modified": iso(e.metadata().and_then(|m| m.modified()))}));
                }
            }
        }
    }
    Ok(items)
}

fn collect_bookmarks(v: &Value, out: &mut Vec<(String, String)>, depth: u32) {
    if depth > 64 || out.len() > 100_000 {
        return;
    }
    match v {
        Value::Object(m) => {
            if m.get("type").and_then(|t| t.as_str()) == Some("url") {
                out.push((s(v, "name"), s(v, "url")));
            }
            for (_, c) in m {
                collect_bookmarks(c, out, depth + 1);
            }
        }
        Value::Array(a) => a.iter().for_each(|c| collect_bookmarks(c, out, depth + 1)),
        _ => {}
    }
}

// ------------------------------------------------------------------ run

type SectionFn = fn() -> Result<Vec<Value>, String>;

fn os_build() -> String {
    let k = Key::open(Hive::LocalMachine, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
    let g = |n: &str| k.as_ref().and_then(|k| k.value(n)).map(|v| v.to_ps_string()).unwrap_or_default();
    format!("{}.{}.{}.0", g("CurrentMajorVersionNumber"), g("CurrentMinorVersionNumber"), g("CurrentBuildNumber"))
}

/// Run every section, timing each; `progress` gets one line per finished section (the
/// same wording hunt.ps1 printed).
pub fn run(days: u32, mut progress: impl FnMut(&str)) -> Value {
    let started = hideout_win::time::now_local();
    let t0 = Instant::now();
    sigcache::clear();
    let mut sections = Map::new();
    let mut record = |name: &str, t: Instant, r: std::thread::Result<Result<Vec<Value>, String>>, sections: &mut Map<String, Value>| {
        let secs = (t.elapsed().as_secs_f64() * 10.0).round() / 10.0;
        let (ok, items, err) = match r {
            Ok(Ok(items)) => (true, items, None),
            Ok(Err(e)) => (false, vec![], Some(e)),
            Err(_) => (false, vec![], Some("this area stopped with an internal error".to_string())),
        };
        progress(&format!("  {:<22} {:>5} item(s)  {}s{}", name, items.len(), secs, err.as_ref().map(|e| format!("  ERROR: {e}")).unwrap_or_default()));
        let mut o = json!({"ok": ok, "items": items, "seconds": secs});
        if let Some(e) = err {
            o["error"] = json!(e);
        }
        sections.insert(name.to_string(), o);
    };
    let catch = |f: &dyn Fn() -> Result<Vec<Value>, String>| std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

    // Shared inputs, read once.
    let g = quick::gather();
    let procs = processes();
    let mut starts: HashMap<String, Vec<String>> = HashMap::new();
    for e in &g.entries {
        if let Some(p) = &e.program {
            let full = quick::resolve_bare(p).unwrap_or_else(|| p.clone()).to_lowercase();
            let v = starts.entry(full).or_default();
            let label = format!("{}: {}", e.source, e.name);
            if !v.contains(&label) && v.len() < 10 {
                v.push(label);
            }
        }
    }
    let empty = HashMap::new();
    let procs_ok = procs.as_ref().unwrap_or(&empty);

    let t = Instant::now();
    record("hideout", t, catch(&|| sec_hideout(&g)), &mut sections);
    let simple: [(&str, SectionFn); 13] = [
        ("scheduledTasks", sec_tasks),
        ("services", sec_services),
        ("drivers", sec_drivers),
        ("registryAutoruns", sec_registry),
        ("startupFolders", sec_startup),
        ("wmiSubscriptions", sec_wmi),
        ("defender", sec_defender),
        ("rootCertificates", sec_certs),
        ("powershellProfiles", sec_profiles),
        ("browserExtensions", sec_extensions),
        ("hostsAndProxy", sec_hosts_proxy),
        ("accounts", sec_accounts),
        ("securitySettings", sec_security),
    ];
    for (name, f) in simple.iter().take(8) {
        let t = Instant::now();
        record(name, t, catch(&|| f()), &mut sections);
    }
    let t = Instant::now();
    record("network", t, catch(&|| match &procs { Ok(p) => sec_network(p, &starts), Err(e) => Err(e.clone()) }), &mut sections);
    let t = Instant::now();
    record("processes", t, catch(&|| match &procs { Ok(p) => sec_processes(p), Err(e) => Err(e.clone()) }), &mut sections);
    let t = Instant::now();
    record("recentFiles", t, catch(&|| sec_recent(days)), &mut sections);
    for (name, f) in simple.iter().skip(8) {
        let t = Instant::now();
        record(name, t, catch(&|| f()), &mut sections);
    }
    let t = Instant::now();
    record("remoteAccess", t, catch(&|| sec_remote(&g, procs_ok)), &mut sections);
    let t = Instant::now();
    record("browserSettings", t, catch(&sec_browser_settings), &mut sections);

    json!({
        "app": "Hideout hunt", "version": 1, "engine": "rust",
        "computer": std::env::var("COMPUTERNAME").unwrap_or_default(), "admin": hideout_win::admin::is_elevated(),
        "started": started.sortable(), "seconds": t0.elapsed().as_secs(), "osBuild": os_build(), "recentDays": days,
        "sections": sections,
    })
}

// ------------------------------------------------------------------ summary + changes

fn items<'a>(s: &'a Value, name: &str) -> Vec<&'a Value> {
    s.pointer(&format!("/sections/{name}/items")).and_then(|v| v.as_array()).map(|a| a.iter().collect()).unwrap_or_default()
}

fn collected(s: &Value, name: &str) -> bool {
    s.pointer(&format!("/sections/{name}/ok")).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn pick(o: &Value, keys: &[&str]) -> Value {
    let mut m = Map::new();
    for k in keys {
        if let Some(v) = o.get(*k) {
            let empty = v.is_null() || v.as_str() == Some("") || v.as_array().map(|a| a.is_empty()).unwrap_or(false);
            if !empty {
                m.insert(k.to_string(), v.clone());
            }
        }
    }
    Value::Object(m)
}

const BAD_FLAGS: [&str; 6] = ["encoded-command", "download", "eval", "long-base64", "policy-bypass", "hidden-window"];

fn odd_sig(v: &Value) -> bool {
    v.as_str().map(|x| !x.is_empty() && x != "Valid").unwrap_or(false)
}

/// What the guide gets from a deep check: the notable parts, plus counts so "nothing
/// unusual" is a statement with a size. A port of worker.mjs summarizeHunt, extended
/// with the new areas.
pub fn summarize(s: &Value) -> Value {
    let sec = |name: &str, notable: Vec<Value>, extra: Value| {
        let mut o = json!({"checked": items(s, name).len(), "collected": collected(s, name), "notable": notable});
        if let (Value::Object(a), Value::Object(b)) = (&mut o, extra) {
            a.extend(b);
        }
        o
    };
    let tasks: Vec<&Value> = items(s, "scheduledTasks").into_iter().filter(|t| !s_str(t, "path").starts_with(r"\Microsoft\")).collect();
    let odd_tasks: Vec<Value> = tasks
        .iter()
        .filter(|t| {
            t["hidden"].as_bool().unwrap_or(false)
                || t["actions"].as_array().map(|a| a.iter().any(|x| x["userFolder"].as_bool().unwrap_or(false) || x["flags"].as_array().map(|f| f.iter().any(|v| BAD_FLAGS.contains(&v.as_str().unwrap_or("")))).unwrap_or(false) || x["sig"] == "HashMismatch" || x["sig"] == "NotSigned")).unwrap_or(false)
        })
        .take(40)
        .map(|t| {
            let mut o = pick(t, &["name", "state", "author", "registered", "hidden", "runAs", "lastRun"]);
            o["actions"] = json!(t["actions"].as_array().map(|a| a.iter().map(|x| pick(x, &["program", "sig", "signer", "userFolder", "flags", "urlHosts"])).collect::<Vec<_>>()).unwrap_or_default());
            o
        })
        .collect();
    let defender = items(s, "defender");
    let status = defender.iter().find(|d| d["type"] == "status").map(|v| (*v).clone()).unwrap_or(Value::Null);
    static TASK_PATH: OnceLock<Regex> = OnceLock::new();
    let user_path = re(&TASK_PATH, r"(?i)\\(AppData|ProgramData|Temp)\\");
    // Process names come back with ".exe" ("svchost.exe"); the system-listener list is
    // matched without it. (worker.mjs compared "svchost.exe" to "svchost" and so listed
    // every system listener as notable.)
    let system_listener = |p: &str| ["svchost", "system", "lsass", "wininit", "services", "spoolsv"].contains(&p.to_lowercase().trim_end_matches(".exe"));
    let recent = items(s, "recentFiles");
    let mut progs: Vec<&&Value> = recent.iter().filter(|f| f["kind"] == "program").collect();
    progs.sort_by_key(|f| std::cmp::Reverse(s_str(f, "created")));
    json!({
        "computerIsAdminRun": s["admin"].as_bool().unwrap_or(false),
        "collectedAt": s["started"],
        "hideoutFindings": items(s, "hideout").iter().map(|f| pick(f, &["severity", "kind", "name", "state", "program", "folder", "signer", "arrived", "reasons"])).collect::<Vec<_>>(),
        "scheduledTasks": sec("scheduledTasks", odd_tasks, json!({"nonMicrosoft": tasks.len()})),
        "services": sec("services", items(s, "services").into_iter().filter(|x| x["userFolder"].as_bool().unwrap_or(false) || (odd_sig(&x["sig"]) && x["sig"] != "FileMissing") || odd_sig(&x["serviceDllSig"])).take(30).map(|x| pick(x, &["name", "display", "state", "start", "program", "sig", "signer", "serviceDll", "serviceDllSig"])).collect(), json!({})),
        "drivers": sec("drivers", items(s, "drivers").into_iter().take(20).cloned().collect(), json!({})),
        "registryAutoruns": sec("registryAutoruns", items(s, "registryAutoruns").into_iter().take(60).map(|x| pick(x, &["where", "name", "program", "sig", "signer", "userFolder", "flags", "value", "urlHosts"])).collect(), json!({})),
        "startupFolders": sec("startupFolders", items(s, "startupFolders").into_iter().map(|x| pick(x, &["file", "created", "program", "sig", "signer", "flags"])).collect(), json!({})),
        "wmiSubscriptions": sec("wmiSubscriptions", items(s, "wmiSubscriptions").into_iter().cloned().collect(), json!({})),
        "defender": sec("defender", defender.iter().filter(|d| d["type"] != "status").map(|d| (*d).clone()).collect(), json!({"status": status})),
        "rootCertificates": sec("rootCertificates", items(s, "rootCertificates").into_iter().filter(|c| c["subject"] == c["issuer"] && s_str(c, "notBefore").get(..4).and_then(|y| y.parse::<i32>().ok()).unwrap_or(0) >= 2023).cloned().collect(), json!({})),
        "network": sec("network", items(s, "network").into_iter().filter(|n| (n["state"] == "Established" && (odd_sig(&n["sig"]) || user_path.is_match(&s_str(n, "path")))) || (n["state"] == "Listen" && (s_str(n, "local").starts_with("0.0.0.0:") || s_str(n, "local").starts_with(":::")) && !system_listener(&s_str(n, "process")))).take(30).cloned().collect(), json!({})),
        "processes": sec("processes", items(s, "processes").into_iter().take(30).map(|p| pick(p, &["name", "path", "sig", "signer", "started", "parent", "flags"])).collect(), json!({})),
        "recentFiles": sec("recentFiles", progs.into_iter().take(30).map(|f| pick(f, &["path", "created", "sig", "size"])).collect(), json!({"scriptsOrShortcuts": recent.iter().filter(|f| f["kind"] != "program").count()})),
        "powershellProfiles": sec("powershellProfiles", items(s, "powershellProfiles").into_iter().filter(|p| p["flags"].as_array().map(|a| !a.is_empty()).unwrap_or(false)).cloned().collect(), json!({})),
        "browserExtensions": sec("browserExtensions", items(s, "browserExtensions").into_iter().filter(|e| e["riskyPermissions"].as_array().map(|a| !a.is_empty()).unwrap_or(false)).map(|e| pick(e, &["browser", "name", "version", "updateUrl", "riskyPermissions"])).collect(), json!({})),
        "hostsAndProxy": sec("hostsAndProxy", items(s, "hostsAndProxy").into_iter().cloned().collect(), json!({})),
        "accounts": sec("accounts", items(s, "accounts").into_iter().cloned().collect(), json!({})),
        "securitySettings": sec("securitySettings", items(s, "securitySettings").into_iter().filter(|x| security_notable(x)).cloned().collect(), json!({})),
        "remoteAccess": sec("remoteAccess", items(s, "remoteAccess").into_iter().cloned().collect(), json!({})),
        "browserSettings": sec("browserSettings", items(s, "browserSettings").into_iter().filter(|x| x["type"] != "settings" || x["unusualSearch"].as_bool().unwrap_or(false)).cloned().collect(), json!({})),
    })
}

fn s_str(v: &Value, k: &str) -> String {
    s(v, k)
}

/// A security setting a person (or the guide) should look at.
pub fn security_notable(x: &Value) -> bool {
    match x["type"].as_str().unwrap_or("") {
        "firewall" => x["enabled"] == json!(false),
        "uac" => x["enabled"] == json!(false) || x["consentPromptBehaviorAdmin"] == json!(0),
        "antivirus" => x["enabled"] == json!(false) || x["upToDate"] == json!(false) || x.get("error").is_some(),
        "remoteDesktop" => x["enabled"] == json!(true),
        _ => false,
    }
}

/// A stable key for an item, per section, for "what changed". Things that change on
/// their own every minute (established connections, process ids) are left out.
fn change_key(section: &str, it: &Value) -> Option<String> {
    let k = |f: &[&str]| f.iter().map(|x| s(it, x)).collect::<Vec<_>>().join(" | ");
    Some(match section {
        "hideout" => k(&["kind", "name", "folder"]),
        "scheduledTasks" => format!("{}{}", s(it, "path"), s(it, "name")),
        "services" => k(&["name", "program", "serviceDll"]),
        "drivers" => k(&["name", "path", "sig"]),
        "registryAutoruns" => k(&["where", "name", "program", "value"]),
        "startupFolders" => k(&["folder", "file", "program"]),
        "wmiSubscriptions" => k(&["type", "name", "filter", "consumer"]),
        "defender" if it["type"] == "status" => return None,
        "defender" => k(&["type", "threatId", "name", "when"]),
        "rootCertificates" => k(&["store", "thumbprint", "subject"]),
        "network" if it["state"] == "Listen" => k(&["local", "process"]),
        "network" | "processes" => return None,
        "recentFiles" => k(&["path"]),
        "powershellProfiles" => k(&["path", "sha256"]),
        "browserExtensions" => k(&["browser", "profile", "id"]),
        "hostsAndProxy" => k(&["type", "line", "where", "server", "autoConfigUrl"]),
        "accounts" => k(&["type", "name", "enabled"]),
        "securitySettings" => it.to_string(),
        "remoteAccess" => k(&["tool"]),
        "browserSettings" => it.to_string(),
        _ => it.to_string(),
    })
}

/// What appeared and what went away since `prev` (an earlier deep check of this PC).
pub fn changes(prev: &Value, cur: &Value) -> Value {
    let mut out = Map::new();
    let names: Vec<&str> = SECTIONS.iter().chain(EXTRA_SECTIONS.iter()).copied().collect();
    for name in names {
        // A section that was not read on either side says nothing about change.
        if !collected(prev, name) || !collected(cur, name) {
            continue;
        }
        let keys = |s: &Value| -> BTreeSet<String> { items(s, name).iter().filter_map(|it| change_key(name, it)).collect() };
        let (a, b) = (keys(prev), keys(cur));
        let added: Vec<&String> = b.difference(&a).take(50).collect();
        let removed: Vec<&String> = a.difference(&b).take(50).collect();
        if !added.is_empty() || !removed.is_empty() {
            out.insert(name.into(), json!({"added": added, "removed": removed}));
        }
    }
    json!({"since": prev["started"], "sections": out})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_match_hunt_ps1() {
        assert_eq!(flags("powershell -enc AAAA "), vec!["encoded-command"]);
        assert!(flags("powershell -ExecutionPolicy Bypass -w hidden -c iex(x)").iter().any(|f| f == "policy-bypass"));
        assert!(flags("powershell -ExecutionPolicy Bypass -w hidden -c iex(x)").iter().any(|f| f == "hidden-window"));
        assert!(flags("powershell -ExecutionPolicy Bypass -w hidden -c iex(x)").iter().any(|f| f == "eval"));
        assert!(flags("certutil -urlcache -f http://x/y").iter().any(|f| f == "download"));
        assert!(flags(r"C:\Users\Bob\AppData\Roaming\x.exe").iter().any(|f| f == "user-folder-path"));
        assert!(flags("RUNDLL32.EXE x.dll,Run").iter().any(|f| f == "lolbin"));
        assert!(flags(&"A".repeat(130)).iter().any(|f| f == "long-base64"));
        assert!(flags("notepad.exe file.txt").is_empty());
    }

    #[test]
    fn redaction_hides_tokens_and_caps_length() {
        let r = redacted("app.exe --token ghp_abcdefghijklmnopqrstuvwxyz0123456789 --x 1");
        assert!(!r.contains("ghp_abcdefghijklmnop"), "{r}");
        assert!(r.contains("[redacted 40 chars]"), "{r}");
        let long = redacted(&"word ".repeat(100));
        assert!(long.ends_with("...") && long.chars().count() == 243);
    }

    #[test]
    fn url_hosts_are_unique() {
        assert_eq!(url_hosts("get http://a.example/x https://b.example:8443/y http://a.example/z"), vec!["a.example", "b.example"]);
    }

    #[test]
    fn lookalike_banks() {
        assert_eq!(lookalike_bank("chase-secure-login.com"), Some("chase"));
        assert_eq!(lookalike_bank("secure.chase.com"), None);
        assert_eq!(lookalike_bank("chase.com"), None);
        assert_eq!(lookalike_bank("purchase.com"), None, "a word that merely contains a brand is not a look-alike");
        assert_eq!(lookalike_bank("paypal.account-verify.net"), Some("paypal"));
        assert_eq!(lookalike_bank("www.paypal.com"), None);
        assert_eq!(lookalike_bank("example.com"), None);
    }

    #[test]
    fn security_settings_rules() {
        assert!(security_notable(&json!({"type": "firewall", "enabled": false})));
        assert!(!security_notable(&json!({"type": "firewall", "enabled": true})));
        assert!(security_notable(&json!({"type": "uac", "enabled": true, "consentPromptBehaviorAdmin": 0})));
        assert!(security_notable(&json!({"type": "remoteDesktop", "enabled": true})));
        assert!(security_notable(&json!({"type": "antivirus", "enabled": true, "upToDate": false})));
    }

    // ---- one test per area (the Stage 1 coverage table points at these) ----

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hideout-hunt-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The whole deep check on this PC: every one of the 19 areas reports, and an area
    /// that could not be read says why - never an empty "ok".
    #[test]
    fn every_area_reports_on_this_pc() {
        let r = run(30, |_| {});
        for name in SECTIONS.iter().chain(EXTRA_SECTIONS.iter()) {
            let sec = &r["sections"][name];
            assert!(sec.is_object(), "{name} missing");
            if !sec["ok"].as_bool().unwrap() {
                assert!(!s(sec, "error").is_empty(), "{name} failed without saying why");
            }
        }
        let n = |name: &str| r["sections"][name]["items"].as_array().map(|a| a.len()).unwrap_or(0);
        // Things every Windows PC has.
        assert!(n("scheduledTasks") > 20 && n("services") > 50 && n("rootCertificates") > 5, "{}", r["sections"]);
        assert!(items(&r, "registryAutoruns").iter().filter(|i| i["where"] == "LSA").count() == 3, "the three LSA package lists are always reported");
        assert!(items(&r, "defender").iter().any(|d| d["type"] == "status") || !collected(&r, "defender"));
        assert!(items(&r, "accounts").iter().any(|a| a["type"] == "administrator"));
        assert!(items(&r, "securitySettings").iter().filter(|x| x["type"] == "firewall").count() == 3);
        assert!(items(&r, "scheduledTasks").iter().all(|t| s(t, "path").ends_with('\\')));
        assert!(items(&r, "drivers").iter().all(|d| d["sig"] != "Valid" || !s(d, "path").to_lowercase().contains(r"\windows\system32\drivers\")), "valid drivers in the normal place are left out");
        assert_eq!(r["recentDays"], 30);
    }

    #[test]
    fn recent_files_finds_a_new_unsigned_program() {
        let d = tmp("recent");
        let exe = d.join("updater.exe");
        let noise: Vec<u8> = (0..8192u32).map(|i| (i * 31 % 251) as u8).collect();
        std::fs::write(&exe, &noise).unwrap();
        std::fs::write(d.join("run.vbs"), "WScript.Echo 1").unwrap();
        let items = sec_recent(1).unwrap();
        let hit = items.iter().find(|i| s(i, "path").eq_ignore_ascii_case(&exe.to_string_lossy())).expect("the new program is listed");
        assert_eq!(hit["kind"], "program");
        assert_ne!(hit["sig"], "Valid");
        assert_eq!(s(hit, "sha256"), hideout_win::crypto::hex(&hideout_win::crypto::sha256(&noise)).to_uppercase());
        assert!(items.iter().any(|i| s(i, "path").ends_with("run.vbs") && i["kind"] == "script-or-shortcut"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn extension_permissions_are_read_from_the_newest_version() {
        let d = tmp("ext").join("abcdefghijklmnopabcdefghijklmnop");
        std::fs::create_dir_all(d.join("1.0.0_0")).unwrap();
        std::fs::create_dir_all(d.join("2.0.0_0")).unwrap();
        std::fs::write(d.join("1.0.0_0").join("manifest.json"), r#"{"name":"Old","version":"1.0.0","permissions":["storage"]}"#).unwrap();
        let mut m = b"\xEF\xBB\xBF".to_vec();
        m.extend_from_slice(br#"{"name":"Coupon Helper","version":"2.0.0","update_url":"https://u.example/x","permissions":["cookies","storage","<all_urls>"],"host_permissions":["*://*/*"]}"#);
        std::fs::write(d.join("2.0.0_0").join("manifest.json"), m).unwrap();
        let (name, version, update, perms) = read_extension(&d).unwrap();
        assert_eq!((name.as_str(), version.as_str(), update.as_str()), ("Coupon Helper", "2.0.0", "https://u.example/x"));
        assert_eq!(perms, vec!["cookies", "<all_urls>", "*://*/*"]);
        std::fs::remove_dir_all(d.parent().unwrap()).ok();
    }

    #[test]
    fn hosts_file_entries_skip_comments_and_the_bom() {
        let mut t = b"\xEF\xBB\xBF# Copyright\r\n\r\n  127.0.0.1 localhost\r\n# 1.2.3.4 nope\r\n10.0.0.9  mybank.example\r\n".to_vec();
        assert_eq!(hosts_lines(&t), vec!["127.0.0.1 localhost", "10.0.0.9  mybank.example"]);
        t.clear();
        assert!(hosts_lines(&t).is_empty());
    }

    #[test]
    fn network_lists_our_own_listener_with_its_program() {
        let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let procs = processes().unwrap();
        let me = std::env::current_exe().unwrap().to_string_lossy().to_lowercase();
        let mut starts = HashMap::new();
        starts.insert(me.clone(), vec!["Test: pretend start-up item".to_string()]);
        let items = sec_network(&procs, &starts).unwrap();
        let hit = items.iter().find(|i| s(i, "local") == format!("0.0.0.0:{port}")).expect("our listener");
        assert_eq!(s(hit, "path").to_lowercase(), me);
        assert_eq!(hit["startsBy"], json!(["Test: pretend start-up item"]), "a connection is linked to what starts its program");
    }

    #[test]
    fn processes_flags_a_program_running_from_a_user_folder() {
        let d = tmp("proc");
        let exe = d.join("helper.exe");
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        std::fs::copy(format!(r"{windir}\System32\cmd.exe"), &exe).unwrap();
        let mut child = std::process::Command::new(&exe).args(["/c", "for /l %i in (1,1,300000) do rem"]).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let items = sec_processes(&processes().unwrap()).unwrap();
        let _ = child.kill();
        let _ = child.wait();
        let hit = items.iter().find(|i| s(i, "path").eq_ignore_ascii_case(&exe.to_string_lossy()));
        assert!(hit.is_some(), "a program running from %TEMP% is listed");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn accounts_and_certificates_and_settings_read() {
        let a = sec_accounts().unwrap();
        assert!(a.iter().any(|x| x["type"] == "user"));
        assert!(a.iter().filter(|x| x["type"] == "administrator").all(|x| ["Local", "MicrosoftAccount", "AzureAD", "ActiveDirectory"].contains(&x["source"].as_str().unwrap())));
        let c = sec_certs().unwrap();
        assert!(c.iter().all(|x| s(x, "thumbprint").len() == 40 && s(x, "notBefore").len() == 10));
        let sec = sec_security().unwrap();
        assert!(sec.iter().any(|x| x["type"] == "uac") && sec.iter().any(|x| x["type"] == "remoteDesktop"));
    }

    #[test]
    fn describe_redacts_and_flags_like_hunt_ps1() {
        let d = describe(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA");
        assert_eq!(d["sig"], "Valid");
        assert!(d["flags"].as_array().unwrap().iter().any(|f| f == "encoded-command"));
        assert!(s(&Value::Object(d.clone()), "snippet").contains("[redacted"), "{d:?}");
        let none = describe(r"C:\Windows\System32\notepad.exe", "");
        assert!(none.get("flags").is_none() && none.get("snippet").is_none());
    }

    #[test]
    fn changes_find_added_and_removed_but_ignore_unread_sections() {
        let mk = |tasks: Vec<&str>, ok: bool| json!({"started": "t", "sections": {"scheduledTasks": {"ok": ok, "items": tasks.iter().map(|n| json!({"path": "\\", "name": n})).collect::<Vec<_>>()}}});
        let c = changes(&mk(vec!["a", "b"], true), &mk(vec!["b", "c"], true));
        assert_eq!(c["sections"]["scheduledTasks"]["added"], json!(["\\c"]));
        assert_eq!(c["sections"]["scheduledTasks"]["removed"], json!(["\\a"]));
        let c2 = changes(&mk(vec!["a"], true), &mk(vec![], false));
        assert!(c2["sections"].as_object().unwrap().is_empty(), "an unread section is not 'everything removed'");
    }
}
