//! The quick scan: everything set to start by itself, and the sideloading check on the
//! programs that live in user-writable folders. Grew out of a port of hideout.ps1.
//!
//! The JSON keeps hideout.ps1's shape and field names (the app, the report page and
//! the guide read either), and adds:
//!   * `items`: every start-up item, its source, a verdict (threat / worth-a-look /
//!     clean / could-not-check) and the facts behind it;
//!   * `checked.bySource`, `checked.sourcesNotRead`.
//!
//! Where hideout.ps1 had a blind spot, this engine does NOT copy it, and the parity
//! harness lists each one as an explained difference:
//!   * a Run value whose name starts with "PS" was skipped (it filtered PowerShell's own
//!     PSPath/PSChildName properties with -like 'PS*');
//!   * hidden files were skipped in the Startup folders and in a program's folder;
//!   * services whose WMI path comes back empty were skipped;
//!   * it read four sources; this reads the whole start-up surface (autostart.rs);
//!   * a data file next to a program that is really a program was not noticed.

use crate::autostart::{self, Entry};
use crate::rules::*;
use crate::{par, pe, sigcache};
use hideout_win::authenticode::SigStatus;
use hideout_win::registry::{Hive, Key};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Target {
    pub kind: String,
    pub name: String,
    pub state: String,
    pub exe: String,
    /// Where it was found (empty in hideout.ps1's own target files).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// "wider" for a place hideout.ps1 never looked (the parity harness uses this).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
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
    #[serde(default)]
    pub by_source: Map<String, Value>,
    /// Places that could not be read at all (e.g. WMI subscriptions without admin).
    #[serde(default)]
    pub sources_not_read: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Defender {
    pub realtime: bool,
    pub signature_age_days: Value,
    pub last_quick_scan: String,
    pub last_full_scan: String,
}

/// What Hideout knows about one program on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Facts {
    pub exists: bool,
    /// Where a bare program name ("powershell.exe") was found, the way Windows looks.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub resolved: String,
    /// Why the file could not be read, when it is there but closed to Hideout.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub unreadable: String,
    /// Valid, NotSigned, HashMismatch, ... (empty when the file is not there).
    pub signature: String,
    pub signer: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub sha256: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub created: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub modified: String,
    /// "program", "library", "not a program" or "" (not looked at).
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub pe: String,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub overlay_bytes: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// One start-up item with its verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Item {
    pub source: String,
    pub kind: String,
    pub location: String,
    pub name: String,
    pub state: String,
    pub program: String,
    /// threat, worth-a-look, clean, could-not-check
    pub verdict: String,
    pub reasons: Vec<Reason>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub facts: Option<Facts>,
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
    #[serde(default)]
    pub items: Vec<Item>,
}

// ------------------------------------------------------------------ targets

/// The whole start-up surface, as scan targets (items that name a program) plus the
/// raw entries and the places that could not be read.
pub struct Gathered {
    pub targets: Vec<Target>,
    pub entries: Vec<Entry>,
    pub not_read: Vec<String>,
}

pub fn gather() -> Gathered {
    let s = autostart::gather();
    let targets = s
        .entries
        .iter()
        .filter_map(|e| e.program.as_ref().map(|p| Target {
            kind: e.kind.clone(),
            name: e.name.clone(),
            state: e.state.clone(),
            exe: p.clone(),
            source: e.source.clone(),
            scope: if e.ps_scope { String::new() } else { "wider".into() },
        }))
        .collect();
    Gathered { targets, entries: s.entries, not_read: s.not_read }
}

/// Back-compat for callers that only want targets.
pub fn gather_targets() -> (Vec<Target>, Vec<String>) {
    let g = gather();
    (g.targets, g.not_read)
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
            (Hive::LocalMachine, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            (Hive::LocalMachine, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (Hive::CurrentUser, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
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
    let es = sigcache::check(Path::new(exe));
    let signer = org_from_subject(&es.subject);
    let exe_signed = es.status == SigStatus::Valid;
    let exe_leaf = leaf(exe).to_string();
    let mut score = 0u32;
    let mut reasons = Vec::new();

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
    // The slow part: every program file in the folder gets its signature checked. They
    // are independent, so they run side by side; the order of the lists is kept.
    let statuses = par::map(&bins, |(name, _, _)| sigcache::check(&Path::new(&dir).join(name)).status);
    let mut tampered: Vec<String> = Vec::new();
    let mut unsigned: Vec<String> = Vec::new();
    for ((name, _, _), st) in bins.iter().zip(statuses) {
        match st {
            Some(SigStatus::HashMismatch) => tampered.push(name.clone()),
            Some(SigStatus::NotSigned | SigStatus::UnknownError | SigStatus::NotSupportedFileFormat) => unsigned.push(name.clone()),
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
        // A "data" file that is really a Windows program: code hidden from anyone who
        // only looks at file names.
        let disguised: Vec<&str> = entries
            .iter()
            .filter(|(n, s, f)| *f && payload_ext(n) && *s >= 1024 && pe::read(&Path::new(&dir).join(n)).is_ok())
            .map(|(n, _, _)| n.as_str())
            .collect();
        if !disguised.is_empty() {
            score += 3;
            reasons.push(Reason { tag: "Program dressed as media".into(), text: format!("These look like data files but are Windows programs: {}", disguised.join(", ")) });
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

// ------------------------------------------------------------------ facts

fn local_time(t: std::io::Result<std::time::SystemTime>) -> String {
    t.ok().and_then(hideout_win::time::local_from_system_time).map(|l| l.sortable()).unwrap_or_default()
}

/// Facts about one program. Hashes only programs in user-writable folders (the ones a
/// person may need to look up), and only up to 64 MB.
pub fn facts(program: &str) -> Facts {
    let resolved = resolve_bare(program);
    let path = resolved.clone().unwrap_or_else(|| program.to_string());
    let p = Path::new(&path);
    let meta = match fs::metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Facts::default(),
        // There, but closed to us (Store apps' WindowsApps folder, another user's files).
        Err(e) => return Facts { exists: true, unreadable: e.to_string(), ..Default::default() },
    };
    if !meta.is_file() {
        return Facts::default();
    }
    let sig = sigcache::check(p);
    let mut f = Facts {
        exists: true,
        resolved: resolved.unwrap_or_default(),
        signature: sig.status.as_str().into(),
        signer: org_from_subject(&sig.subject),
        created: local_time(meta.created()),
        modified: local_time(meta.modified()),
        ..Default::default()
    };
    match pe::read(p) {
        Ok(info) => {
            f.pe = if info.is_dll { "library" } else { "program" }.into();
            f.overlay_bytes = info.overlay;
        }
        Err(pe::PeError::NotPe) => f.pe = "not a program".into(),
        Err(_) => {}
    }
    if user_writable(&path) && meta.len() <= 64 * 1024 * 1024 {
        f.sha256 = hideout_win::crypto::sha256_file_upper(p, 64 * 1024 * 1024).unwrap_or_default();
    }
    f
}

/// A bare program name ("powershell.exe", "explorer.exe") found the way Windows finds
/// it when it starts a program: System32, the Windows folder, then each PATH folder.
/// None when the name already has a folder, or is found nowhere.
pub fn resolve_bare(program: &str) -> Option<String> {
    if program.contains('\\') || program.contains('/') || program.is_empty() {
        return None;
    }
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let mut dirs = vec![format!(r"{windir}\System32"), windir.clone()];
    dirs.extend(std::env::var("PATH").unwrap_or_default().split(';').filter(|d| !d.trim().is_empty()).map(|d| d.trim().to_string()));
    let names: Vec<String> = if program.contains('.') { vec![program.to_string()] } else { vec![format!("{program}.exe"), program.to_string()] };
    for d in dirs {
        for n in &names {
            let c = Path::new(&d).join(n);
            if c.is_file() {
                return Some(c.to_string_lossy().to_string());
            }
        }
    }
    None
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

fn verdict_of(severity: &str) -> &'static str {
    match severity {
        "high" => "threat",
        "" => "clean",
        _ => "worth-a-look",
    }
}

/// Run the quick scan over `targets` only (a test file, or a caller that already has
/// them). No `items` beyond the targets.
pub fn scan(targets: &[Target], installed: &Installed) -> QuickReport {
    scan_full(targets, &[], &[], installed, false)
}

/// The whole scan on this PC: the full surface, items with facts, findings.
pub fn scan_pc() -> QuickReport {
    let g = gather();
    scan_with(&g, &Installed::read(), true)
}

/// The scan over an already-read surface (the deep check reads it once and shares it).
pub fn scan_with(g: &Gathered, installed: &Installed, with_facts: bool) -> QuickReport {
    scan_full(&g.targets, &g.entries, &g.not_read, installed, with_facts)
}

fn scan_full(targets: &[Target], entries: &[Entry], not_read: &[String], installed: &Installed, with_facts: bool) -> QuickReport {
    sigcache::clear();
    // Defender is a separate WMI round trip: ask it while the files are checked.
    let defender = std::thread::spawn(|| {
        hideout_win::com::init();
        defender_status()
    });
    let mut by_kind = Map::new();
    let mut by_source = Map::new();
    for t in targets {
        let n = by_kind.get(&t.kind).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        by_kind.insert(t.kind.clone(), Value::from(n));
        if !t.source.is_empty() {
            let n = by_source.get(&t.source).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
            by_source.insert(t.source.clone(), Value::from(n));
        }
    }
    // Every user-writable program folder is checked once, all of them side by side.
    let mut folders: Vec<(String, String)> = Vec::new();
    for t in targets {
        if !t.exe.is_empty() && user_writable(&t.exe) && program_ext(&t.exe) && !store_alias(&t.exe) && fs::metadata(&t.exe).is_ok() {
            let key = parent(&t.exe).to_lowercase();
            if !folders.iter().any(|(k, _)| *k == key) {
                folders.push((key, t.exe.clone()));
            }
        }
    }
    let verdicts = par::map(&folders, |(_, exe)| check_folder(exe, installed));
    let mut cache: HashMap<String, Option<FolderVerdict>> = folders.into_iter().map(|(k, _)| k).zip(verdicts).collect();
    let mut findings = Vec::new();
    let mut unchecked = Vec::new();
    let mut in_user = 0usize;
    // (kind, name, program) -> (verdict, reasons) for the items list.
    let mut item_verdicts: HashMap<(String, String, String), (String, Vec<Reason>)> = HashMap::new();
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
        let v = cache.entry(key).or_insert_with(|| std::panic::catch_unwind(|| check_folder(&t.exe, installed)).ok()).clone();
        let ikey = (t.kind.clone(), t.name.clone(), t.exe.to_lowercase());
        // A check that failed is reported, never counted as clean.
        let Some(f) = v else {
            unchecked.push(Unchecked { kind: t.kind.clone(), name: t.name.clone(), program: leaf(&t.exe).into() });
            item_verdicts.insert(ikey, ("could-not-check".into(), vec![Reason { tag: "Check failed".into(), text: "Hideout could not finish checking this program's folder.".into() }]));
            continue;
        };
        item_verdicts.insert(ikey, (verdict_of(&f.severity).into(), f.reasons.clone()));
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

    // Items that are not programs on disk but are signs on their own.
    for e in entries {
        let (severity, tag, text) = match e.kind.as_str() {
            "Browser extension (forced by policy)" => ("low", "Forced by policy", format!("A browser policy on this PC installs this extension and stops it being removed ({}).", e.name)),
            "WMI event consumer (script)" => ("medium", "Script run by Windows", "Windows runs a script whenever a chosen event happens. Rare on home PCs; some malware hides here.".to_string()),
            _ => continue,
        };
        let r = Reason { tag: tag.into(), text };
        item_verdicts.insert((e.kind.clone(), e.name.clone(), String::new()), (verdict_of(severity).into(), vec![r.clone()]));
        findings.push(Finding {
            severity: severity.into(),
            score: if severity == "medium" { 3 } else { 2 },
            kind: e.kind.clone(),
            name: e.name.clone(),
            state: e.state.clone(),
            program: String::new(),
            folder: e.location.clone(),
            signer: String::new(),
            arrived: String::new(),
            reasons: vec![r],
        });
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.score));

    let items = if with_facts { build_items(entries, &item_verdicts) } else { Vec::new() };
    QuickReport {
        app: "Hideout".into(),
        version: 1,
        scanned_at: hideout_win::time::now_local().minutes(),
        computer: hideout_win::env::var("COMPUTERNAME"),
        admin: hideout_win::admin::is_elevated(),
        checked: Checked {
            start_items: targets.len(),
            in_user_folders: in_user,
            by_kind,
            could_not_check: unchecked,
            by_source,
            sources_not_read: not_read.to_vec(),
        },
        defender: defender.join().ok().flatten(),
        findings,
        items,
    }
}

fn build_items(entries: &[Entry], verdicts: &HashMap<(String, String, String), (String, Vec<Reason>)>) -> Vec<Item> {
    // Facts once per distinct program, in parallel.
    let mut programs: BTreeMap<String, String> = BTreeMap::new();
    for e in entries {
        if let Some(p) = &e.program {
            programs.entry(p.to_lowercase()).or_insert_with(|| p.clone());
        }
    }
    let list: Vec<(String, String)> = programs.into_iter().collect();
    let got = par::map(&list, |(_, p)| facts(p));
    let facts_of: HashMap<String, Option<Facts>> = list.into_iter().map(|(k, _)| k).zip(got).collect();

    entries
        .iter()
        .map(|e| {
            let prog = e.program.clone().unwrap_or_default();
            let f = e.program.as_ref().and_then(|p| facts_of.get(&p.to_lowercase()).cloned().flatten());
            let (verdict, reasons) = match verdicts.get(&(e.kind.clone(), e.name.clone(), prog.to_lowercase())) {
                Some((v, r)) => (v.clone(), r.clone()),
                None => match &f {
                    // The program could not be looked at: never "clean".
                    None if e.program.is_some() => ("could-not-check".into(), vec![Reason { tag: "Not read".into(), text: "Hideout could not read this program's details.".into() }]),
                    Some(f) if !f.unreadable.is_empty() => ("could-not-check".into(), vec![Reason { tag: "Not readable".into(), text: format!("Windows would not let Hideout open {prog} ({}).", f.unreadable) }]),
                    Some(f) if !f.exists => ("could-not-check".into(), vec![Reason { tag: "Program missing".into(), text: format!("It points at {prog}, which is not there.") }]),
                    _ => ("clean".into(), vec![]),
                },
            };
            Item { source: e.source.clone(), kind: e.kind.clone(), location: e.location.clone(), name: e.name.clone(), state: e.state.clone(), program: prog, verdict, reasons, facts: f }
        })
        .collect()
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
            Ok(Target { kind: s("kind"), name: s("name"), state: s("state"), exe: s("exe"), source: s("source"), scope: s("scope") })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys(p: &str) -> String {
        format!(r"{}\{}", std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()), p)
    }

    #[test]
    fn bare_names_resolve_like_windows() {
        let c = resolve_bare("cmd.exe").expect("cmd.exe is in System32");
        assert!(c.to_lowercase().ends_with(r"\system32\cmd.exe"), "{c}");
        assert!(resolve_bare("cmd").is_some(), "the .exe can be left off");
        assert!(resolve_bare(r"C:\a\b.exe").is_none(), "a path is not a bare name");
        assert!(resolve_bare("definitely-not-a-program-hideout.exe").is_none());
    }

    #[test]
    fn facts_of_real_missing_and_bare() {
        let n = facts(&sys(r"System32\notepad.exe"));
        assert!(n.exists && n.signature == "Valid" && n.pe == "program", "{n:?}");
        assert!(n.sha256.is_empty(), "system programs are not hashed");
        let m = facts(r"C:\no\such\thing.exe");
        assert!(!m.exists && m.unreadable.is_empty());
        let b = facts("explorer.exe");
        assert!(b.exists && !b.resolved.is_empty(), "{b:?}");
    }

    #[test]
    fn user_folder_programs_get_a_hash() {
        let dir = std::env::temp_dir().join(format!("hideout-facts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.exe");
        std::fs::copy(sys(r"System32\notepad.exe"), &p).unwrap();
        let f = facts(&p.to_string_lossy());
        assert_eq!(f.sha256.len(), 64, "{f:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verdict_words() {
        assert_eq!(verdict_of("high"), "threat");
        assert_eq!(verdict_of("medium"), "worth-a-look");
        assert_eq!(verdict_of("low"), "worth-a-look");
        assert_eq!(verdict_of(""), "clean");
    }

    #[test]
    fn whole_pc_scan_has_items_for_every_entry() {
        let r = scan_pc();
        assert!(r.items.len() >= r.checked.start_items, "every target is an item");
        assert!(r.items.iter().all(|i| ["threat", "worth-a-look", "clean", "could-not-check"].contains(&i.verdict.as_str())));
        // Not checked is never shown as clean.
        assert!(r.items.iter().filter(|i| i.verdict == "clean" && !i.program.is_empty()).all(|i| i.facts.as_ref().map(|f| f.exists && f.unreadable.is_empty()).unwrap_or(false)));
    }
}
