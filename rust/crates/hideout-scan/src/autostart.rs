//! Everything set to start by itself, read natively (no PowerShell), each item tagged
//! with where it came from.
//!
//! The first four sources are the ones hideout.ps1 read (its items keep the same
//! `kind` labels so the two engines can be compared). The rest are the places malware
//! also uses to survive a restart:
//!
//!   scheduled tasks (programs AND COM handlers) - Run / RunOnce / RunServices /
//!   Policies\Explorer\Run for the machine and EVERY loaded user - Startup folders for
//!   every profile - services and their ServiceDll - drivers - Winlogon Shell /
//!   Userinit / Taskman - Image File Execution Options debuggers - SilentProcessExit
//!   monitors - AppInit_DLLs - AppCertDlls - LSA packages - Active Setup - per-user COM
//!   overrides - WMI event consumers - browser extensions forced by policy.
//!
//! A source that cannot be read is reported as such, never skipped quietly.

use crate::rules::{is_host, program_path, program_path_ext, target_from_args};
use hideout_win::registry::{Hive, Key};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Entry {
    /// Where it was found, in words: "Run key (this user)", "Driver", ...
    pub source: String,
    /// Kind label. For the sources hideout.ps1 read, the same label it used.
    pub kind: String,
    /// Registry key, folder or task folder it lives in.
    pub location: String,
    pub name: String,
    pub state: String,
    /// The program it runs, when there is one (a path; may not exist).
    pub program: Option<String>,
    /// True when hideout.ps1 looked at this same item.
    #[serde(skip)]
    pub ps_scope: bool,
}

#[derive(Debug, Default)]
pub struct Surface {
    pub entries: Vec<Entry>,
    /// "<source>: <why>" for every place that could not be read.
    pub not_read: Vec<String>,
}

impl Surface {
    // One positional call per item reads better at the ~30 call sites than a builder.
    #[allow(clippy::too_many_arguments)]
    fn add(&mut self, source: &str, kind: &str, location: &str, name: &str, state: &str, program: Option<String>, ps_scope: bool) {
        // hideout.ps1's own sources keep its exact answer (that is what parity compares).
        // Everywhere else, text that is neither a path nor a program name ("/UserInstall"
        // in some of Windows' own Active Setup entries) is not a program.
        let program = program.filter(|p| !p.is_empty()).filter(|p| ps_scope || looks_like_program(p));
        self.entries.push(Entry { source: source.into(), kind: kind.into(), location: location.into(), name: name.into(), state: state.into(), program, ps_scope });
    }
}

fn looks_like_program(p: &str) -> bool {
    let l = p.to_lowercase();
    l.contains('\\') || [".exe", ".dll", ".sys", ".com", ".scr", ".cpl", ".ocx"].iter().any(|e| l.ends_with(e))
}

const RUN_KIND: &str = "Startup (registry)";

/// The program a command line runs, looking through rundll32/regsvr32/mshta/wscript.
fn resolve(cmd: &str, args: &str) -> Option<String> {
    let p = program_path(cmd);
    if p.as_deref().map(is_host).unwrap_or(false) {
        if let Some(inner) = target_from_args(args) {
            return Some(inner);
        }
    }
    p
}

/// The SID of the user running Hideout, found through the profile list (the profile
/// whose folder is this user's). Used so this user's hive is not read twice.
fn current_sid() -> Option<String> {
    let home = std::env::var("USERPROFILE").ok()?.to_lowercase();
    let k = Key::open(Hive::LocalMachine, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")?;
    k.subkeys().into_iter().find(|sid| {
        k.subkey(sid).and_then(|s| s.string("ProfileImagePath")).map(|p| p.to_lowercase() == home).unwrap_or(false)
    })
}

/// Every loaded user hive except the current user's (which HKCU already covers).
fn other_user_hives() -> Vec<String> {
    let me = current_sid().unwrap_or_default();
    hideout_win::registry::loaded_user_hives()
        .into_iter()
        .filter(|s| s.starts_with("S-1-5-21-") && !s.ends_with("_Classes") && !s.eq_ignore_ascii_case(&me))
        .collect()
}

fn run_keys(s: &mut Surface) {
    // (hive, prefix shown, path under hive, source label, read by hideout.ps1?)
    let mut keys: Vec<(Hive, String, String, &str, bool)> = Vec::new();
    for (sub, ps) in [("Run", true), ("RunOnce", true), ("RunServices", false), ("RunServicesOnce", false), (r"Policies\Explorer\Run", false)] {
        keys.push((Hive::CurrentUser, "HKCU".into(), format!(r"Software\Microsoft\Windows\CurrentVersion\{sub}"), "Run key (this user)", ps));
        keys.push((Hive::LocalMachine, "HKLM".into(), format!(r"Software\Microsoft\Windows\CurrentVersion\{sub}"), "Run key (all users)", ps));
        keys.push((Hive::LocalMachine, "HKLM".into(), format!(r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\{sub}"), "Run key (all users, 32-bit)", ps && sub == "Run"));
    }
    for sid in other_user_hives() {
        for sub in ["Run", "RunOnce", "RunServices", "RunServicesOnce", r"Policies\Explorer\Run"] {
            keys.push((Hive::Users, "HKU".into(), format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\{sub}"), "Run key (another user)", false));
        }
    }
    for (hive, prefix, path, source, ps) in keys {
        let Some(k) = Key::open(hive, &path) else { continue };
        let shown_path = format!("{prefix}\\{path}");
        for (name, v) in k.values() {
            let cmd = v.to_ps_string();
            let shown = if name.is_empty() { "(default)".to_string() } else { name };
            s.add(source, RUN_KIND, &shown_path, &shown, "Enabled", resolve(&cmd, &cmd), ps);
        }
    }
}

fn tasks(s: &mut Surface) {
    match hideout_win::tasks::list() {
        Ok(l) => {
            for t in &l.tasks {
                let loc = format!("{}{}", t.folder, t.name);
                for a in &t.actions {
                    match a {
                        hideout_win::tasks::Action::Exec { path, args } => {
                            s.add("Scheduled task", "Scheduled task", &loc, &t.name, &t.state, resolve(path, args), true);
                        }
                        hideout_win::tasks::Action::ComHandler { class_id } => {
                            s.add("Scheduled task (COM handler)", "Scheduled task (COM handler)", &loc, &t.name, &t.state, com_server(class_id), false);
                        }
                        hideout_win::tasks::Action::Other => {}
                    }
                }
            }
            for f in l.unreadable_folders {
                s.not_read.push(format!("scheduled tasks: {f}"));
            }
        }
        Err(e) => s.not_read.push(format!("scheduled tasks: {e}")),
    }
}

/// The DLL or program behind a COM class id: the user's own registration first (it
/// wins, which is exactly why malware puts one there), then the machine's.
fn com_server(clsid: &str) -> Option<String> {
    for (hive, base) in [(Hive::CurrentUser, r"Software\Classes\CLSID"), (Hive::LocalMachine, r"SOFTWARE\Classes\CLSID")] {
        for server in ["InprocServer32", "LocalServer32"] {
            if let Some(k) = Key::open(hive, &format!(r"{base}\{clsid}\{server}")) {
                if let Some(v) = k.string("") {
                    return program_path_ext(&v);
                }
            }
        }
    }
    None
}

/// Every profile folder that has an AppData (skipping the built-in templates).
pub fn profile_dirs() -> Vec<std::path::PathBuf> {
    let users = std::path::PathBuf::from(std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()) + "\\Users");
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&users) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if ["Default", "Default User", "All Users", "Public"].iter().any(|x| x.eq_ignore_ascii_case(&n)) {
                continue;
            }
            let p = e.path();
            if p.join("AppData").exists() {
                out.push(p);
            }
        }
    }
    out
}

fn startup_folders(s: &mut Surface) {
    let mine = hideout_win::env::startup_folder().unwrap_or_default();
    let common = hideout_win::env::common_startup_folder().unwrap_or_default();
    let mut dirs: Vec<(String, &str, bool)> = vec![(mine.clone(), "Startup folder (this user)", true), (common, "Startup folder (all users)", true)];
    for p in profile_dirs() {
        let d = p.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup").to_string_lossy().to_string();
        if !d.eq_ignore_ascii_case(&mine) {
            dirs.push((d, "Startup folder (another user)", false));
        }
    }
    for (dir, source, ps) in dirs {
        if dir.is_empty() {
            continue;
        }
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                s.not_read.push(format!("{source} {dir}: {e}"));
                continue;
            }
        };
        for e in rd.flatten() {
            if !e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let full = e.path().to_string_lossy().to_string();
            let fname = e.file_name().to_string_lossy().to_string();
            let p = if full.to_lowercase().ends_with(".lnk") { hideout_win::links::read(&full).map(|l| l.target) } else { Some(full.clone()) };
            s.add(source, "Startup folder", &dir, &fname, "Enabled", p, ps);
        }
    }
}

fn services_and_drivers(s: &mut Surface) {
    match hideout_win::services::list(hideout_win::services::Kind::Win32) {
        Ok(v) => {
            for svc in v {
                s.add("Service", "Service", r"HKLM\SYSTEM\CurrentControlSet\Services", &svc.name, &svc.state, program_path(&svc.path), true);
                if svc.path.to_lowercase().contains("svchost.exe") {
                    let key = format!(r"SYSTEM\CurrentControlSet\Services\{}\Parameters", svc.name);
                    if let Some(dll) = Key::open(Hive::LocalMachine, &key).and_then(|k| k.string("ServiceDll")) {
                        s.add("Service DLL", "Service DLL", &format!(r"HKLM\{key}"), &svc.name, &svc.state, program_path_ext(&dll), false);
                    }
                }
            }
        }
        Err(e) => s.not_read.push(format!("services: {e}")),
    }
    match hideout_win::services::list(hideout_win::services::Kind::Driver) {
        Ok(v) => {
            let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
            for d in v {
                let p = if d.path.is_empty() { Some(format!(r"{windir}\System32\drivers\{}.sys", d.name)) } else { program_path_ext(&d.path) };
                s.add("Driver", "Driver", r"HKLM\SYSTEM\CurrentControlSet\Services", &d.name, &d.state, p, false);
            }
        }
        Err(e) => s.not_read.push(format!("drivers: {e}")),
    }
}

/// Software hives to look under for machine-wide hooks: 64-bit and 32-bit views.
const SOFTWARE: [&str; 2] = ["SOFTWARE", r"SOFTWARE\WOW6432Node"];

fn hooks(s: &mut Surface) {
    // Winlogon: what Windows runs at sign-in. Normal values are explorer.exe / userinit.
    let mut wl: Vec<(Hive, String, String)> = SOFTWARE.iter().map(|b| (Hive::LocalMachine, format!(r"{b}\Microsoft\Windows NT\CurrentVersion\Winlogon"), format!(r"HKLM\{b}\...\Winlogon"))).collect();
    wl.push((Hive::CurrentUser, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon".into(), r"HKCU\...\Winlogon".into()));
    for (hive, path, shown) in wl {
        let Some(k) = Key::open(hive, &path) else { continue };
        for v in ["Shell", "Userinit", "Taskman"] {
            if let Some(val) = k.string(v).filter(|x| !x.trim().is_empty()) {
                // Several programs can be listed, comma-separated.
                for part in val.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    s.add("Winlogon", "Logon hook (Winlogon)", &shown, v, "Enabled", program_path_ext(part), false);
                }
            }
        }
    }
    for base in SOFTWARE {
        let ifeo = format!(r"{base}\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
        if let Some(k) = Key::open(Hive::LocalMachine, &ifeo) {
            for exe in k.subkeys() {
                if let Some(d) = k.subkey(&exe).and_then(|e| e.string("Debugger")).filter(|d| !d.trim().is_empty()) {
                    s.add("Image File Execution Options", "Debugger hijack (IFEO)", &format!(r"HKLM\{ifeo}"), &exe, "Enabled", program_path_ext(&d), false);
                }
            }
        }
        let spe = format!(r"{base}\Microsoft\Windows NT\CurrentVersion\SilentProcessExit");
        if let Some(k) = Key::open(Hive::LocalMachine, &spe) {
            for exe in k.subkeys() {
                if let Some(m) = k.subkey(&exe).and_then(|e| e.string("MonitorProcess")).filter(|d| !d.trim().is_empty()) {
                    s.add("SilentProcessExit", "Exit monitor (SilentProcessExit)", &format!(r"HKLM\{spe}"), &exe, "Enabled", program_path_ext(&m), false);
                }
            }
        }
        let win = format!(r"{base}\Microsoft\Windows NT\CurrentVersion\Windows");
        if let Some(k) = Key::open(Hive::LocalMachine, &win) {
            let enabled = k.value("LoadAppInit_DLLs").and_then(|v| v.as_i64()).unwrap_or(0) != 0;
            if let Some(list) = k.string("AppInit_DLLs") {
                for dll in list.split([' ', ',']).filter(|d| !d.trim().is_empty()) {
                    s.add("AppInit_DLLs", "AppInit DLL", &format!(r"HKLM\{win}"), dll, if enabled { "Enabled" } else { "Disabled" }, program_path_ext(dll), false);
                }
            }
        }
        let active = format!(r"{base}\Microsoft\Active Setup\Installed Components");
        if let Some(k) = Key::open(Hive::LocalMachine, &active) {
            for c in k.subkeys() {
                if let Some(sp) = k.subkey(&c).and_then(|e| e.string("StubPath")).filter(|d| !d.trim().is_empty()) {
                    s.add("Active Setup", "Active Setup", &format!(r"HKLM\{active}"), &c, "Enabled", resolve(&sp, &sp).or_else(|| program_path_ext(&sp)), false);
                }
            }
        }
    }
    if let Some(k) = Key::open(Hive::LocalMachine, r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls") {
        for (name, v) in k.values() {
            s.add("AppCertDlls", "AppCert DLL", r"HKLM\SYSTEM\...\AppCertDlls", &name, "Enabled", program_path_ext(&v.to_ps_string()), false);
        }
    }
    if let Some(k) = Key::open(Hive::LocalMachine, r"SYSTEM\CurrentControlSet\Control\Lsa") {
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        for v in ["Authentication Packages", "Security Packages", "Notification Packages"] {
            let names = match k.value(v) {
                Some(hideout_win::registry::Value::Multi(m)) => m,
                Some(other) => vec![other.to_ps_string()],
                None => vec![],
            };
            for n in names.into_iter().map(|n| n.trim().trim_matches('"').to_string()).filter(|n| !n.is_empty()) {
                let p = if n.contains('\\') { n.clone() } else { format!(r"{sys}\System32\{}", if n.to_lowercase().ends_with(".dll") { n.clone() } else { format!("{n}.dll") }) };
                s.add("LSA", "Security package (LSA)", &format!(r"HKLM\SYSTEM\...\Lsa\{v}"), &n, "Enabled", Some(p), false);
            }
        }
    }
}

fn user_com_overrides(s: &mut Surface) {
    let mut hives: Vec<(Hive, String, String)> = vec![(Hive::CurrentUser, r"Software\Classes\CLSID".into(), r"HKCU\Software\Classes\CLSID".into())];
    for sid in other_user_hives() {
        hives.push((Hive::Users, format!(r"{sid}_Classes\CLSID"), format!(r"HKU\{sid}_Classes\CLSID")));
    }
    for (hive, path, shown) in hives {
        let Some(k) = Key::open(hive, &path) else { continue };
        for clsid in k.subkeys() {
            for server in ["InprocServer32", "LocalServer32"] {
                if let Some(v) = k.subkey(&format!(r"{clsid}\{server}")).and_then(|e| e.string("")).filter(|v| !v.trim().is_empty()) {
                    s.add("COM override (user)", "COM override (user)", &shown, &clsid, "Enabled", program_path_ext(&v), false);
                    break;
                }
            }
        }
    }
}

fn wmi_consumers(s: &mut Surface) {
    match hideout_win::wmi::query("root\\subscription", "SELECT * FROM __EventConsumer", 500) {
        Ok(rows) => {
            for r in rows {
                let name = r.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let exe = r.get("ExecutablePath").and_then(|v| v.as_str()).unwrap_or("");
                let tpl = r.get("CommandLineTemplate").and_then(|v| v.as_str()).unwrap_or("");
                let script = r.get("ScriptText").and_then(|v| v.as_str()).map(|x| !x.is_empty()).unwrap_or(false)
                    || r.get("ScriptFileName").and_then(|v| v.as_str()).map(|x| !x.is_empty()).unwrap_or(false);
                let program = if !exe.is_empty() { program_path_ext(exe) } else if !tpl.is_empty() { resolve(tpl, tpl).or_else(|| program_path_ext(tpl)) } else { None };
                let kind = if script { "WMI event consumer (script)" } else { "WMI event consumer" };
                s.add("WMI event subscription", kind, r"root\subscription", &name, "Enabled", program, false);
            }
        }
        // Reading root\subscription usually needs admin rights.
        Err(e) => s.not_read.push(format!("WMI event subscriptions: {e}")),
    }
}

fn forced_extensions(s: &mut Surface) {
    for (vendor, browser) in [(r"Google\Chrome", "Chrome"), (r"Microsoft\Edge", "Edge"), (r"BraveSoftware\Brave", "Brave")] {
        for (hive, shown) in [(Hive::LocalMachine, "HKLM"), (Hive::CurrentUser, "HKCU")] {
            let path = format!(r"SOFTWARE\Policies\{vendor}\ExtensionInstallForcelist");
            let Some(k) = Key::open(hive, &path) else { continue };
            for (_, v) in k.values() {
                let val = v.to_ps_string();
                let id = val.split(';').next().unwrap_or("").trim().to_string();
                if !id.is_empty() {
                    s.add("Browser policy", "Browser extension (forced by policy)", &format!(r"{shown}\{path}"), &format!("{browser}: {id}"), "Enabled", None, false);
                }
            }
        }
    }
}

/// Read the whole start-up surface.
pub fn gather() -> Surface {
    // The Task Scheduler, the service list and WMI each take a round trip of their
    // own; they are read side by side, then merged in a fixed order.
    let parts: Vec<fn(&mut Surface)> = vec![tasks, run_keys, startup_folders, services_and_drivers, hooks, user_com_overrides, wmi_consumers, forced_extensions];
    let got = crate::par::map(&parts, |f| {
        let mut part = Surface::default();
        f(&mut part);
        part
    });
    let mut s = Surface::default();
    for (i, p) in got.into_iter().enumerate() {
        match p {
            Some(p) => {
                s.entries.extend(p.entries);
                s.not_read.extend(p.not_read);
            }
            None => s.not_read.push(format!("start-up source {i}: the reader stopped with an internal error")),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_surface_with_sources() {
        let s = gather();
        let has = |src: &str| s.entries.iter().any(|e| e.source == src);
        assert!(has("Scheduled task") && has("Service") && has("Driver"), "{:?}", s.entries.iter().map(|e| &e.source).collect::<std::collections::BTreeSet<_>>());
        assert!(s.entries.iter().any(|e| e.source == "Winlogon" && e.name == "Userinit"), "Userinit is always set");
        assert!(s.entries.iter().any(|e| e.source == "LSA"), "LSA packages are always set");
        // Every item in hideout.ps1's scope uses one of its four kind labels.
        for e in s.entries.iter().filter(|e| e.ps_scope) {
            assert!(["Scheduled task", "Startup (registry)", "Startup folder", "Service"].contains(&e.kind.as_str()), "{e:?}");
        }
    }

    #[test]
    fn current_user_is_found_in_the_profile_list() {
        assert!(current_sid().map(|s| s.starts_with("S-1-5-21-")).unwrap_or(false));
    }
}
