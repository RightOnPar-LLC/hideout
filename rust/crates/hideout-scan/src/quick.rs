//! The quick scan: everything set to start by itself, and the sideloading check on the
//! programs that live in user-writable folders. A port of hideout.ps1.
//!
//! The JSON it produces has the same shape and field names as `hideout.ps1 -Json`, so
//! the app, the report page and the guide read either one.
//!
//! Where hideout.ps1 had a blind spot, this port does NOT copy it, and the parity
//! harness lists each one as an explained difference:
//!   * a Run value whose name starts with "PS" was skipped (it filtered PowerShell's own
//!     PSPath/PSChildName properties with -like 'PS*');
//!   * hidden files were skipped in the Startup folders and in a program's folder
//!     (Get-ChildItem without -Force).

use crate::rules::*;
use hideout_win::authenticode::{self, SigStatus};
use hideout_win::registry::{Hive, Key};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Target {
    pub kind: String,
    pub name: String,
    pub state: String,
    pub exe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Reason {
    pub tag: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub severity: String,
    pub score: u32,
    pub kind: String,
    pub name: String,
    pub state: String,
    pub program: String,
    pub folder: String,
    pub signer: String,
    pub arrived: String,
    pub reasons: Vec<Reason>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Unchecked {
    pub kind: String,
    pub name: String,
    pub program: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Checked {
    pub start_items: usize,
    pub in_user_folders: usize,
    pub by_kind: Map<String, Value>,
    pub could_not_check: Vec<Unchecked>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Defender {
    pub realtime: bool,
    pub signature_age_days: Value,
    pub last_quick_scan: String,
    pub last_full_scan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QuickReport {
    pub app: String,
    pub version: u32,
    pub scanned_at: String,
    pub computer: String,
    pub admin: bool,
    pub checked: Checked,
    pub defender: Option<Defender>,
    pub findings: Vec<Finding>,
}

// ------------------------------------------------------------------ targets

/// Where hideout.ps1 looked: scheduled tasks, Run/RunOnce keys, both Startup folders,
/// services. Each failure to read a source is returned so it can be reported.
pub fn gather_targets() -> (Vec<Target>, Vec<String>) {
    let mut out = Vec::new();
    let mut problems = Vec::new();
    let mut add = |kind: &str, name: &str, state: &str, exe: Option<String>| {
        if let Some(e) = exe.filter(|e| !e.is_empty()) {
            out.push(Target { kind: kind.into(), name: name.into(), state: state.into(), exe: e });
        }
    };

    match hideout_win::tasks::list() {
        Ok(l) => {
            for t in &l.tasks {
                for a in &t.actions {
                    if let hideout_win::tasks::Action::Exec { path, args } = a {
                        let mut p = program_path(path);
                        if p.as_deref().map(is_host).unwrap_or(false) {
                            if let Some(inner) = target_from_args(args) {
                                p = Some(inner);
                            }
                        }
                        add("Scheduled task", &t.name, &t.state, p);
                    }
                }
            }
            for f in l.unreadable_folders {
                problems.push(format!("scheduled tasks: {f}"));
            }
        }
        Err(e) => problems.push(format!("scheduled tasks: {e}")),
    }

    let run_keys = [
        (Hive::CurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (Hive::CurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (Hive::LocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (Hive::LocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (Hive::LocalMachine, "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ];
    for (hive, path) in run_keys {
        let Some(k) = Key::open(hive, path) else { continue };
        for (name, v) in k.values() {
            let s = v.to_ps_string();
            let mut p = program_path(&s);
            if p.as_deref().map(is_host).unwrap_or(false) {
                if let Some(inner) = target_from_args(&s) {
                    p = Some(inner);
                }
            }
            let shown = if name.is_empty() { "(default)".to_string() } else { name };
            add("Startup (registry)", &shown, "Enabled", p);
        }
    }

    for dir in [hideout_win::env::startup_folder(), hideout_win::env::common_startup_folder()].into_iter().flatten() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            if !e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let full = e.path().to_string_lossy().to_string();
            let fname = e.file_name().to_string_lossy().to_string();
            let p = if full.to_lowercase().ends_with(".lnk") {
                hideout_win::links::read(&full).map(|s| s.target)
            } else {
                Some(full.clone())
            };
            add("Startup folder", &fname, "Enabled", p);
        }
    }

    match hideout_win::services::list(hideout_win::services::Kind::Win32) {
        Ok(v) => {
            for s in v {
                add("Service", &s.name, &s.state, program_path(&s.path));
            }
        }
        Err(e) => problems.push(format!("services: {e}")),
    }
    (out, problems)
}

// ------------------------------------------------------------------ installed programs

/// What Windows says is installed (the Uninstall keys), for the two "is this a real
/// install" checks.
#[derive(Debug, Default, Clone)]
pub struct Installed {
    /// "DisplayName | Publisher" per entry, joined by newlines (searched as one text).
    pub text: String,
    /// InstallLocation of each entry, trimmed of spaces, quotes and a trailing "\".
    pub locations: Vec<String>,
}

impl Installed {
    pub fn read() -> Installed {
        let mut lines = Vec::new();
        let mut locations = Vec::new();
        let roots = [
            (Hive::LocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (Hive::LocalMachine, "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (Hive::CurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        ];
        for (hive, path) in roots {
            let Some(k) = Key::open(hive, path) else { continue };
            for sub in k.subkeys() {
                let Some(e) = k.subkey(&sub) else { continue };
                let vals = e.values();
                if vals.is_empty() {
                    continue;
                }
                let get = |n: &str| vals.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.to_ps_string()).unwrap_or_default();
                lines.push(format!("{} | {}", get("DisplayName"), get("Publisher")));
                let loc = get("InstallLocation");
                let loc = loc.trim().trim_matches('"').trim_end_matches('\\').to_string();
                if loc.chars().count() > 3 {
                    locations.push(loc);
                }
            }
        }
        Installed { text: lines.join("\n"), locations }
    }

    /// Test-VendorInstalled: is anything from this signer installed?
    pub fn vendor_installed(&self, org: &str) -> bool {
        if org.is_empty() {
            return true;
        }
        match vendor_word(org) {
            None => true,
            Some(w) => contains_ci(&self.text, &w),
        }
    }

    /// Test-RegisteredInstall: does an installer claim this folder (or a parent of it)?
    pub fn registered(&self, dir: &str) -> bool {
        let d = dir.trim_end_matches('\\').to_lowercase();
        self.locations.iter().any(|loc| {
            let l = loc.to_lowercase();
            d == l || d.starts_with(&format!("{l}\\"))
        })
    }
}

// ------------------------------------------------------------------ the folder check

#[derive(Debug, Clone)]
pub struct FolderVerdict {
    pub score: u32,
    pub severity: String,
    pub signer: String,
    pub reasons: Vec<Reason>,
    pub folder: String,
    pub arrived: String,
}

fn is_bin(name: &str) -> bool {
    let l = name.to_lowercase();
    [".dll", ".exe", ".ocx", ".cpl"].iter().any(|e| l.ends_with(e))
}

/// Test-Folder: the sideloading check on one program's folder.
pub fn check_folder(exe: &str, installed: &Installed) -> FolderVerdict {
    let dir = parent(exe);
    let es = authenticode::check(Path::new(exe));
    let signer = org_from_subject(&es.subject);
    let exe_signed = es.status == SigStatus::Valid;
    let exe_leaf = leaf(exe).to_string();
    let mut score = 0u32;
    let mut reasons = Vec::new();

    let mut tampered: Vec<String> = Vec::new();
    let mut unsigned: Vec<String> = Vec::new();
    let mut entries: Vec<(String, u64, bool)> = Vec::new(); // (name, size, is_file)
    if let Ok(rd) = fs::read_dir(&dir) {
        for e in rd.flatten() {
            let is_file = e.file_type().map(|t| t.is_file()).unwrap_or(false);
            let name = e.file_name().to_string_lossy().to_string();
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            entries.push((name, size, is_file));
        }
    }
    let bins: Vec<&(String, u64, bool)> = entries.iter().filter(|(n, _, f)| *f && is_bin(n)).collect();
    for (name, _, _) in &bins {
        let p = Path::new(&dir).join(name);
        match authenticode::check(&p).status {
            SigStatus::HashMismatch => tampered.push(name.clone()),
            SigStatus::NotSigned | SigStatus::UnknownError | SigStatus::NotSupportedFileFormat => unsigned.push(name.clone()),
            _ => {}
        }
    }
    if !tampered.is_empty() {
        score += 5;
        reasons.push(Reason { tag: "Tampered file".into(), text: format!("Changed after it was signed: {}", tampered.join(", ")) });
    }
    if !exe_signed && !tampered.iter().any(|t| t.eq_ignore_ascii_case(&exe_leaf)) {
        score += 3;
        reasons.push(Reason { tag: "Unsigned program".into(), text: format!("The program itself has no valid signature ({}).", es.status.as_str()) });
    }
    let registered = installed.registered(&dir);
    let unsigned_others: Vec<&String> = unsigned.iter().filter(|u| !u.eq_ignore_ascii_case(&exe_leaf)).collect();
    if exe_signed && !unsigned_others.is_empty() && !registered {
        score += 2;
        let list: Vec<&str> = unsigned_others.iter().map(|s| s.as_str()).collect();
        reasons.push(Reason { tag: "Unsigned DLLs".into(), text: format!("Unsigned files beside a signed program: {}", list.join(", ")) });
    }
    if exe_signed && !signer.is_empty() && !installed.vendor_installed(&signer) {
        score += 2;
        reasons.push(Reason { tag: "No matching install".into(), text: format!("Signed by {signer}, but nothing from {signer} is installed.") });
    }
    let folder_name = leaf(&dir).to_string();
    if is_random_name(&folder_name) && !registered {
        score += 1;
        reasons.push(Reason { tag: "Random folder".into(), text: format!("Folder name looks machine-generated: {folder_name}") });
    }
    if !bins.is_empty() && !registered {
        let blobs: Vec<&str> = entries.iter().filter(|(n, s, f)| *f && payload_ext(n) && *s > 100 * 1024).map(|(n, _, _)| n.as_str()).collect();
        if !blobs.is_empty() {
            score += 1;
            reasons.push(Reason { tag: "Hidden payload".into(), text: format!("Large data files beside program code: {}", blobs.join(", ")) });
        }
    }
    let severity = match score {
        s if s >= 5 => "high",
        s if s >= 3 => "medium",
        s if s >= 2 => "low",
        _ => "",
    };
    let arrived = fs::metadata(&dir)
        .and_then(|m| m.created())
        .ok()
        .and_then(hideout_win::time::local_from_system_time)
        .map(|l| l.minutes())
        .unwrap_or_default();
    FolderVerdict { score, severity: severity.into(), signer, reasons, folder: dir, arrived }
}

// ------------------------------------------------------------------ defender

/// Defender's own status (Get-MpComputerStatus). None if Defender is not answering
/// (another antivirus in charge, or the service stopped).
pub fn defender_status() -> Option<Defender> {
    let rows = hideout_win::wmi::query(
        "root\\Microsoft\\Windows\\Defender",
        "SELECT RealTimeProtectionEnabled, AntivirusSignatureAge, QuickScanEndTime, FullScanEndTime FROM MSFT_MpComputerStatus",
        2,
    )
    .ok()?;
    let r = rows.into_iter().next()?;
    let day = |k: &str| {
        r.get(k)
            .and_then(|v| v.as_str())
            .and_then(hideout_win::wmi::wmi_datetime_to_unix)
            .and_then(hideout_win::time::local_from_unix)
            .map(|l| l.date())
            .unwrap_or_default()
    };
    Some(Defender {
        realtime: r.get("RealTimeProtectionEnabled").and_then(|v| v.as_bool()).unwrap_or(false),
        signature_age_days: r.get("AntivirusSignatureAge").cloned().unwrap_or(Value::Null),
        last_quick_scan: day("QuickScanEndTime"),
        last_full_scan: day("FullScanEndTime"),
    })
}

// ------------------------------------------------------------------ the scan

/// Run the quick scan over `targets` (from the PC, or from a test file).
pub fn scan(targets: &[Target], installed: &Installed) -> QuickReport {
    let mut by_kind = Map::new();
    for t in targets {
        let n = by_kind.get(&t.kind).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        by_kind.insert(t.kind.clone(), Value::from(n));
    }
    let mut cache: HashMap<String, Option<FolderVerdict>> = HashMap::new();
    let mut findings = Vec::new();
    let mut unchecked = Vec::new();
    let mut in_user = 0usize;
    for t in targets {
        if t.exe.is_empty() || !user_writable(&t.exe) || fs::metadata(&t.exe).is_err() {
            continue;
        }
        // Programs only: scripts are never code-signed, so every check would fire on
        // them. Store-app aliases cannot be opened at all.
        if !program_ext(&t.exe) || store_alias(&t.exe) {
            continue;
        }
        in_user += 1;
        let key = parent(&t.exe).to_lowercase();
        let v = cache
            .entry(key)
            .or_insert_with(|| std::panic::catch_unwind(|| check_folder(&t.exe, installed)).ok())
            .clone();
        // A check that failed is reported, never counted as clean.
        let Some(f) = v else {
            unchecked.push(Unchecked { kind: t.kind.clone(), name: t.name.clone(), program: leaf(&t.exe).into() });
            continue;
        };
        if f.severity.is_empty() {
            continue;
        }
        findings.push(Finding {
            severity: f.severity,
            score: f.score,
            kind: t.kind.clone(),
            name: t.name.clone(),
            state: t.state.clone(),
            program: leaf(&t.exe).into(),
            folder: f.folder,
            signer: f.signer,
            arrived: f.arrived,
            reasons: f.reasons,
        });
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.score));
    QuickReport {
        app: "Hideout".into(),
        version: 1,
        scanned_at: hideout_win::time::now_local().minutes(),
        computer: hideout_win::env::var("COMPUTERNAME"),
        admin: hideout_win::admin::is_elevated(),
        checked: Checked { start_items: targets.len(), in_user_folders: in_user, by_kind, could_not_check: unchecked },
        defender: defender_status(),
        findings,
    }
}

/// Targets from a JSON file (hideout.ps1's -TestTargets format: one object or a list).
pub fn targets_from_json(text: &str) -> Result<Vec<Target>, String> {
    let text = text.trim_start_matches('\u{feff}');
    let v: Value = serde_json::from_str(text).map_err(|e| format!("targets file is not JSON: {e}"))?;
    let arr = match v {
        Value::Array(a) => a,
        o @ Value::Object(_) => vec![o],
        _ => return Err("targets file must hold an object or a list".into()),
    };
    arr.into_iter()
        .map(|o| {
            let s = |k: &str| o.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            Ok(Target { kind: s("kind"), name: s("name"), state: s("state"), exe: s("exe") })
        })
        .collect()
}
