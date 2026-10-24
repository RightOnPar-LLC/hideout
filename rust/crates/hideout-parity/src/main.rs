//! hideout-parity - run the PowerShell engine (hideout.ps1) and the Rust engine
//! (hideout.exe) on the same PC and diff what they found, field by field.
//!
//! A difference is a bug until it is explained. Explained differences are listed in
//! KNOWN below, each with the reason the Rust engine is right; anything else fails.
//!
//!   hideout-parity quick [--test-targets <file>] [--report <file.json>]
//!                        [--rust <hideout.exe>] [--repo <dir with hideout.ps1>]
//!   hideout-parity fixtures [--keep] [--report <file.json>]
//!       build the planted fixture set in %TEMP%, run both engines on it, and check
//!       both against the verdicts each fixture should get
//!
//! This is a developer tool. It runs PowerShell on purpose (that is the thing being
//! compared against); the Hideout binary itself never does.

mod fixtures;
mod hunt;
mod money;

/// hunt.ps1's sixteen sections - the deep check is compared on exactly these.
pub const HUNT_SECTIONS: [&str; 16] = [
    "hideout", "scheduledTasks", "services", "drivers", "registryAutoruns", "startupFolders", "wmiSubscriptions", "defender",
    "rootCertificates", "network", "processes", "recentFiles", "powershellProfiles", "browserExtensions", "hostsAndProxy", "accounts",
];

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;

/// Differences that are understood, with the reason the Rust engine is right.
const KNOWN: &[(&str, &str)] = &[
    (
        "ps-prefixed-run-value",
        "hideout.ps1 skipped every Run/RunOnce value whose name starts with 'PS' (its -like 'PS*' filter meant PowerShell's own PSPath/PSChildName properties). Malware could hide behind that name; the Rust engine reads every value.",
    ),
    (
        "hidden-startup-file",
        "hideout.ps1 listed the Startup folders without -Force, so a hidden file there was never checked. The Rust engine checks hidden files too.",
    ),
    (
        "wmi-empty-service-path",
        "hideout.ps1 took service paths from WMI (Win32_Service.PathName), which comes back EMPTY for some services even though Windows hands their configuration out normally (sc qc works). Those services were silently skipped. The Rust engine reads the configuration from the Service Control Manager and checks them.",
    ),
    (
        "hidden-file-in-program-folder",
        "hideout.ps1 listed a program's folder without -Force, so hidden DLLs and hidden payloads beside a program were never checked. The Rust engine checks hidden files too.",
    ),
    (
        "wider-surface",
        "hideout.ps1 read four places (tasks, five Run keys, two Startup folders, services). The Rust engine reads the whole start-up surface: every user's Run keys, Policies\\Run, RunServices, Winlogon, IFEO debuggers, SilentProcessExit, AppInit/AppCert DLLs, LSA packages, Active Setup, ServiceDlls, COM task handlers and user COM overrides, WMI consumers, drivers, every profile's Startup folder, browser policy-forced extensions. Items from those places exist only on the Rust side.",
    ),
    (
        "new-check",
        "A reason the Rust engine adds that hideout.ps1 did not have (see RUST_ONLY_TAGS), e.g. a 'media' file beside a program that is really a Windows program.",
    ),
];

/// Reason tags only the Rust engine produces.
const RUST_ONLY_TAGS: &[&str] = &["Program dressed as media"];

/// Finding kinds that only exist on the Rust side (not about a program's folder).
const RUST_ONLY_KINDS: &[&str] = &["Browser extension (forced by policy)", "WMI event consumer (script)"];

#[derive(Debug)]
struct Diff {
    area: String,
    key: String,
    ps: Value,
    rust: Value,
    explained: Option<&'static str>,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("quick") => quick(&args[1..]),
        Some("fixtures") => fixture_run(&args[1..]),
        Some("hunt") => hunt_run(&args[1..]),
        Some("money") => {
            let cases = opt(&args[1..], "--cases").and_then(|c| c.parse().ok()).unwrap_or(5000);
            let code = money::run(&find_repo(opt(&args[1..], "--repo")), &temp_dir(), cases);
            code
        }
        _ => {
            eprintln!("usage: hideout-parity quick [--test-targets <file>] [--report <file.json>] [--rust <hideout.exe>] [--repo <dir>]");
            2
        }
    };
    std::process::exit(code);
}

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn find_repo(explicit: Option<String>) -> PathBuf {
    if let Some(r) = explicit {
        return PathBuf::from(r);
    }
    let mut d = std::env::current_dir().unwrap_or_default();
    loop {
        if d.join("hideout.ps1").is_file() {
            return d;
        }
        if !d.pop() {
            eprintln!("hideout-parity: cannot find hideout.ps1 above the current folder; pass --repo");
            std::process::exit(2);
        }
    }
}

fn default_rust() -> PathBuf {
    let me = std::env::current_exe().unwrap_or_default();
    me.with_file_name("hideout.exe")
}

fn temp_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("hideout-parity-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// Run a PowerShell snippet that writes UTF-8 JSON to $OutFile; read it back. Going
/// through a file (not stdout) keeps non-ASCII names intact.
fn ps_json(body: &str, work: &Path, tag: &str) -> Result<Value, String> {
    let out = work.join(format!("{tag}.json"));
    let script = work.join(format!("{tag}.ps1"));
    let full = format!("$OutFile = '{}'\r\n{}\r\n", out.display().to_string().replace('\'', "''"), body);
    std::fs::write(&script, full).map_err(|e| e.to_string())?;
    let ps = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    let st = Command::new(ps).args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]).arg(&script).status().map_err(|e| e.to_string())?;
    if !st.success() {
        return Err(format!("PowerShell {tag} exited with {st}"));
    }
    let text = std::fs::read_to_string(&out).map_err(|e| format!("{tag}: {e}"))?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| format!("{tag}: {e}"))
}

fn rust_json(exe: &Path, args: &[&str]) -> Result<Value, String> {
    let o = Command::new(exe).args(args).output().map_err(|e| format!("{}: {e}", exe.display()))?;
    if !o.status.success() {
        return Err(format!("hideout.exe {:?} exited with {}: {}", args, o.status, String::from_utf8_lossy(&o.stderr)));
    }
    serde_json::from_slice(&o.stdout).map_err(|e| e.to_string())
}

fn as_list(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Null => vec![],
        o => vec![o.clone()],
    }
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => String::new(),
        Some(o) => o.to_string(),
    }
}

/// The part of hideout.ps1 that finds start-up items, lifted out and run on its own.
fn ps_targets_script(engine: &str) -> Result<String, String> {
    let start = engine.find("function Get-ProgramPath").ok_or("Get-ProgramPath not found in hideout.ps1")?;
    let end = engine.find("$installedCache = $null").ok_or("end of Get-Targets not found in hideout.ps1")?;
    Ok(format!(
        // Assign before building the object: a generic List inside a [pscustomobject]
        // literal throws "Argument types do not match", which SilentlyContinue hides.
        "$ErrorActionPreference = 'SilentlyContinue'\r\n{}\r\n\
         $t = [object[]]@(Get-Targets)\r\n\
         $n = [object[]]@(Get-CimInstance Win32_Service | Where-Object {{ -not $_.PathName }} | ForEach-Object {{ $_.Name }})\r\n\
         $o = New-Object psobject\r\n\
         $o | Add-Member targets $t\r\n\
         $o | Add-Member wmiNoPath $n\r\n\
         $o | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutFile -Encoding UTF8\r\n",
        &engine[start..end]
    ))
}

fn is_hidden(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0).unwrap_or(false)
}

fn startup_dirs() -> Vec<PathBuf> {
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let pd = std::env::var("ProgramData").unwrap_or_default();
    vec![
        PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        PathBuf::from(pd).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
    ]
}

/// Rust-only targets that are explained, so the totals and findings that follow from
/// them can be checked after taking them out - and nothing else.
#[derive(Default)]
struct Explained {
    by_kind: Map<String, Value>,
    in_user: u64,
    /// (kind, name) lower-case, and the reason id.
    targets: Vec<(String, String, &'static str)>,
}

/// hideout.ps1's "is this a sideloading target" test, for counting explained targets.
fn counts_in_user(exe: &str) -> bool {
    let l = exe.to_lowercase();
    let b = l.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || &l[1..3] != r":\" {
        return false;
    }
    let rest = &l[3..];
    let user_dir = rest.strip_prefix(r"users\").and_then(|r| r.split_once('\\')).map(|(_, after)| {
        [r"appdata\", r"downloads\", r"desktop\", r"documents\"].iter().any(|p| after.starts_with(p))
    });
    let writable = rest.starts_with(r"programdata\") || rest.starts_with(r"users\public\") || rest.starts_with(r"windows\temp\") || user_dir == Some(true);
    let program = [".exe", ".dll", ".ocx", ".cpl", ".scr", ".com"].iter().any(|e| l.ends_with(e));
    writable && program && !l.contains(r"\appdata\local\microsoft\windowsapps\") && std::fs::metadata(exe).is_ok()
}

/// Compare the two target lists, and return what the Rust-only targets explain.
fn compare_targets(ps: &[Value], rs: &[Value], wmi_no_path: &[String], diffs: &mut Vec<Diff>) -> Explained {
    let mut ex = Explained::default();
    let key = |t: &Value| format!("{}|{}|{}", s(t, "kind"), s(t, "name"), s(t, "exe")).to_lowercase();
    let mut ps_keys: Vec<String> = ps.iter().map(key).collect();
    let mut rs_left: Vec<&Value> = Vec::new();
    for t in rs {
        let k = key(t);
        if let Some(i) = ps_keys.iter().position(|p| *p == k) {
            ps_keys.remove(i);
        } else {
            rs_left.push(t);
        }
    }
    for k in ps_keys {
        diffs.push(Diff { area: "targets".into(), key: k, ps: json!("present"), rust: json!("missing"), explained: None });
    }
    for t in rs_left {
        let kind = s(t, "kind");
        let name = s(t, "name");
        let explained = if s(t, "scope") == "wider" {
            Some("wider-surface")
        } else if kind == "Startup (registry)" && name.to_lowercase().starts_with("ps") {
            Some("ps-prefixed-run-value")
        } else if kind == "Startup folder" && startup_dirs().iter().any(|d| is_hidden(&d.join(&name))) {
            Some("hidden-startup-file")
        } else if kind == "Service" && wmi_no_path.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
            Some("wmi-empty-service-path")
        } else {
            None
        };
        if let Some(id) = explained {
            let n = ex.by_kind.get(&kind).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
            ex.by_kind.insert(kind.clone(), Value::from(n));
            if counts_in_user(&s(t, "exe")) {
                ex.in_user += 1;
            }
            ex.targets.push((kind.to_lowercase(), name.to_lowercase(), id));
        }
        diffs.push(Diff { area: "targets".into(), key: key(t), ps: json!("missing"), rust: json!("present"), explained });
    }
    ex
}

fn finding_key(f: &Value) -> String {
    format!("{}|{}|{}|{}", s(f, "kind"), s(f, "name"), s(f, "program"), s(f, "folder")).to_lowercase()
}

/// File names listed in a reason's text after the colon ("...: a.dll, b.dll").
fn listed_names(text: &str) -> Vec<String> {
    text.split_once(": ").map(|(_, rest)| rest.split(", ").map(|x| x.trim().to_string()).collect()).unwrap_or_default()
}

/// A finding differs only because the Rust engine also saw hidden files in its folder.
fn only_hidden_files_differ(ps: &Value, rs: &Value) -> bool {
    let folder = PathBuf::from(s(rs, "folder"));
    let reasons = |v: &Value| -> Map<String, Value> {
        let mut m = Map::new();
        for r in as_list(v.get("reasons").unwrap_or(&Value::Null)) {
            m.insert(s(&r, "tag"), Value::String(s(&r, "text")));
        }
        m
    };
    let (pr, rr) = (reasons(ps), reasons(rs));
    // Something has to actually differ in the reasons, or hidden files explain nothing.
    if pr == rr {
        return false;
    }
    for (tag, rtext) in &rr {
        let ptext = pr.get(tag).and_then(|v| v.as_str()).unwrap_or("");
        if ptext == rtext.as_str().unwrap_or("") {
            continue;
        }
        let pn: Vec<String> = listed_names(ptext);
        for n in listed_names(rtext.as_str().unwrap_or("")) {
            if !pn.iter().any(|p| p.eq_ignore_ascii_case(&n)) && !is_hidden(&folder.join(&n)) {
                return false;
            }
        }
    }
    pr.keys().all(|k| rr.contains_key(k))
}

/// The weights hideout.ps1 gives each reason (a finding needs 2 or more).
fn ps_weight(tag: &str) -> u32 {
    match tag {
        "Tampered file" => 5,
        "Unsigned program" => 3,
        "Unsigned DLLs" | "No matching install" => 2,
        "Random folder" | "Hidden payload" => 1,
        _ => 0,
    }
}

/// The Rust finding equals PowerShell's once the reasons only Rust has are taken out
/// (and if PowerShell had no finding, what is left would not have made one).
fn only_new_checks_differ(ps: &Value, rs: &Value) -> bool {
    let tags = |v: &Value| -> Vec<(String, String)> {
        let mut x: Vec<(String, String)> = as_list(v.get("reasons").unwrap_or(&Value::Null)).iter().map(|r| (s(r, "tag"), s(r, "text"))).collect();
        x.sort();
        x
    };
    let rt = tags(rs);
    if !rt.iter().any(|(t, _)| RUST_ONLY_TAGS.contains(&t.as_str())) {
        return false;
    }
    let rest: Vec<(String, String)> = rt.into_iter().filter(|(t, _)| !RUST_ONLY_TAGS.contains(&t.as_str())).collect();
    if ps.get("reasons").is_none() {
        return rest.iter().map(|(t, _)| ps_weight(t)).sum::<u32>() < 2;
    }
    rest == tags(ps)
}

fn compare_quick(ps: &Value, rs: &Value, ex: &Explained, diffs: &mut Vec<Diff>) {
    let explained_by_kind = &ex.by_kind;
    let mut field = |area: &str, key: &str, a: Value, b: Value| {
        if a != b {
            diffs.push(Diff { area: area.into(), key: key.into(), ps: a, rust: b, explained: None });
        }
    };
    // Totals: the Rust counts minus the explained Rust-only targets must equal PowerShell's.
    let extra: u64 = explained_by_kind.values().filter_map(|v| v.as_u64()).sum();
    let mut rs = rs.clone();
    if let Some(Value::Number(n)) = rs.pointer("/checked/startItems").cloned() {
        if let Some(c) = rs.pointer_mut("/checked/startItems") {
            *c = Value::from(n.as_u64().unwrap_or(0).saturating_sub(extra));
        }
    }
    if let Some(Value::Object(bk)) = rs.pointer_mut("/checked/byKind") {
        for (k, v) in explained_by_kind {
            if let Some(cur) = bk.get_mut(k) {
                let left = cur.as_u64().unwrap_or(0).saturating_sub(v.as_u64().unwrap_or(0));
                *cur = Value::from(left);
            }
        }
        bk.retain(|_, v| v.as_u64() != Some(0));
    }
    if let Some(c) = rs.pointer_mut("/checked/inUserFolders") {
        *c = Value::from(c.as_u64().unwrap_or(0).saturating_sub(ex.in_user));
    }
    let rs = &rs;
    for k in ["app", "version", "computer", "admin"] {
        field("report", k, ps.get(k).cloned().unwrap_or(Value::Null), rs.get(k).cloned().unwrap_or(Value::Null));
    }
    let pc = ps.get("checked").cloned().unwrap_or(Value::Null);
    let rc = rs.get("checked").cloned().unwrap_or(Value::Null);
    for k in ["startItems", "inUserFolders", "byKind"] {
        field("checked", k, pc.get(k).cloned().unwrap_or(Value::Null), rc.get(k).cloned().unwrap_or(Value::Null));
    }
    let nc = |v: &Value| {
        let mut x: Vec<String> = as_list(v.get("couldNotCheck").unwrap_or(&Value::Null)).iter().map(|u| format!("{}|{}|{}", s(u, "kind"), s(u, "name"), s(u, "program")).to_lowercase()).collect();
        x.sort();
        Value::from(x)
    };
    field("checked", "couldNotCheck", nc(&pc), nc(&rc));
    let pd = ps.get("defender").cloned().unwrap_or(Value::Null);
    let rd = rs.get("defender").cloned().unwrap_or(Value::Null);
    for k in ["realtime", "signatureAgeDays", "lastQuickScan", "lastFullScan"] {
        field("defender", k, pd.get(k).cloned().unwrap_or(Value::Null), rd.get(k).cloned().unwrap_or(Value::Null));
    }

    let pf = as_list(ps.get("findings").unwrap_or(&Value::Null));
    let mut rf = as_list(rs.get("findings").unwrap_or(&Value::Null));
    for p in &pf {
        let k = finding_key(p);
        match rf.iter().position(|r| finding_key(r) == k) {
            None => diffs.push(Diff { area: "findings".into(), key: k, ps: p.clone(), rust: json!("missing"), explained: None }),
            Some(i) => {
                let r = rf.remove(i);
                let mut same = true;
                for f in ["severity", "score", "state", "signer", "arrived"] {
                    if p.get(f) != r.get(f) {
                        same = false;
                    }
                }
                let reasons = |v: &Value| {
                    let mut x: Vec<String> = as_list(v.get("reasons").unwrap_or(&Value::Null)).iter().map(|r| format!("{}: {}", s(r, "tag"), s(r, "text"))).collect();
                    x.sort();
                    x
                };
                if reasons(p) != reasons(&r) {
                    same = false;
                }
                if !same {
                    let explained = if only_hidden_files_differ(p, &r) {
                        Some("hidden-file-in-program-folder")
                    } else if only_new_checks_differ(p, &r) {
                        Some("new-check")
                    } else {
                        None
                    };
                    diffs.push(Diff { area: "findings".into(), key: k, ps: p.clone(), rust: r, explained });
                }
            }
        }
    }
    for r in rf {
        let k = finding_key(&r);
        // A finding on a target only the Rust engine could see carries that target's reason.
        let from_target = ex.targets.iter().find(|(kind, name, _)| *kind == s(&r, "kind").to_lowercase() && *name == s(&r, "name").to_lowercase()).map(|t| t.2);
        let explained = from_target
            .or_else(|| RUST_ONLY_KINDS.contains(&s(&r, "kind").as_str()).then_some("wider-surface"))
            .or_else(|| only_hidden_files_differ(&json!({}), &r).then_some("hidden-file-in-program-folder"))
            .or_else(|| only_new_checks_differ(&json!({}), &r).then_some("new-check"));
        diffs.push(Diff { area: "findings".into(), key: k, ps: json!("missing"), rust: r, explained });
    }
}

/// "DisplayName | Publisher" of everything in the Uninstall keys - only used to pick a
/// signed file whose vendor is (or is not) installed for the orphaned-signer fixture.
fn installed_text() -> String {
    use hideout_win::registry::{Hive, Key};
    let mut lines = Vec::new();
    for (hive, path) in [
        (Hive::LocalMachine, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (Hive::LocalMachine, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (Hive::CurrentUser, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ] {
        let Some(k) = Key::open(hive, path) else { continue };
        for sub in k.subkeys() {
            if let Some(e) = k.subkey(&sub) {
                lines.push(format!("{} | {}", e.string("DisplayName").unwrap_or_default(), e.string("Publisher").unwrap_or_default()));
            }
        }
    }
    lines.join("\n")
}

fn fixture_run(args: &[String]) -> i32 {
    let root = std::env::temp_dir().join(format!("hideout-fixtures-{}", std::process::id()));
    let built = match fixtures::build(&root, &installed_text()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("hideout-parity: could not build fixtures: {e}");
            return 2;
        }
    };
    for s in &built.skipped {
        println!("  [skipped] {s}");
    }
    let mut qargs: Vec<String> = vec!["--test-targets".into(), built.targets.display().to_string()];
    for k in ["--rust", "--repo"] {
        if let Some(v) = opt(args, k) {
            qargs.push(k.into());
            qargs.push(v);
        }
    }
    let report_path = opt(args, "--report").unwrap_or_else(|| built.root.join("parity.json").display().to_string());
    qargs.push("--report".into());
    qargs.push(report_path.clone());
    let parity = quick(&qargs);
    let rep: Value = std::fs::read_to_string(&report_path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let mut fails = Vec::new();
    fails.extend(fixtures::check(&rep["ps"], &built.expected, "ps"));
    fails.extend(fixtures::check(&rep["rust"], &built.expected, "rust"));
    println!("fixtures: {} expected verdict(s) checked on both engines, {} skipped, {} failure(s)", built.expected.len(), built.skipped.len(), fails.len());
    for f in &fails {
        println!("  FAIL {f}");
    }
    if !args.iter().any(|a| a == "--keep") {
        let _ = Command::new("attrib").args(["-h", "/s"]).arg(built.root.join("*")).status();
        let _ = std::fs::remove_dir_all(&built.root);
    } else {
        println!("fixtures kept in {}", built.root.display());
    }
    if parity == 0 && fails.is_empty() { 0 } else { 1 }
}

/// The organisation in a certificate subject (O=, else CN=), as both engines read it.
fn org(subject: &str) -> String {
    let lower = subject.to_lowercase();
    for key in ["o=", "cn="] {
        if let Some(i) = lower.find(key) {
            let rest = &subject[i + key.len()..];
            let rest = rest.strip_prefix('"').unwrap_or(rest);
            return rest[..rest.find([',', '"']).unwrap_or(rest.len())].trim().to_string();
        }
    }
    String::new()
}

/// True when this file's catalog signer is `ps` and its own (embedded) signer is `rust`.
fn signer_proof(path: &str, ps: &str, rust: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let (emb, cat) = hideout_win::authenticode::check_each(Path::new(path));
    let Some(cat) = cat else { return false };
    org(&cat.subject).eq_ignore_ascii_case(ps) && org(&emb.subject).eq_ignore_ascii_case(rust)
}

fn wmi_rows(ns: &str, q: &str) -> Vec<Map<String, Value>> {
    hideout_win::wmi::query(ns, q, 50_000).unwrap_or_default()
}

/// `hideout-parity hunt`: hunt.ps1 then `hideout hunt`, compared section by section.
fn hunt_run(args: &[String]) -> i32 {
    let repo = find_repo(opt(args, "--repo"));
    let rust = opt(args, "--rust").map(PathBuf::from).unwrap_or_else(default_rust);
    let work = temp_dir();
    let (ps_out, rs_out) = (work.join("ps-hunt.json"), work.join("rust-hunt.json"));
    let ps_started = hideout_win::time::now_local().sortable();
    let ps = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let t0 = std::time::Instant::now();
    let st = Command::new(ps).args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]).arg(repo.join("hunt.ps1")).arg("-Out").arg(&ps_out).stdout(std::process::Stdio::null()).status();
    let ps_secs = t0.elapsed().as_secs_f64();
    if !st.map(|s| s.success()).unwrap_or(false) || !ps_out.exists() {
        eprintln!("hideout-parity: hunt.ps1 did not finish");
        return 2;
    }
    let t1 = std::time::Instant::now();
    let st = Command::new(&rust).arg("hunt").arg("--out").arg(&rs_out).stdout(std::process::Stdio::null()).status();
    let rs_secs = t1.elapsed().as_secs_f64();
    if !st.map(|s| s.success()).unwrap_or(false) || !rs_out.exists() {
        eprintln!("hideout-parity: hideout hunt did not finish");
        return 2;
    }
    let read = |p: &Path| -> Value { std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok()).unwrap_or(Value::Null) };
    let (pv, rv) = (read(&ps_out), read(&rs_out));
    // Evidence, taken right after both runs.
    let alive = wmi_rows(r"root\cimv2", "SELECT ProcessId, Name, CreationDate FROM Win32_Process")
        .into_iter()
        .filter_map(|r| {
            let created = r.get("CreationDate").and_then(|v| v.as_str()).and_then(hideout_win::wmi::wmi_datetime_to_unix).and_then(hideout_win::time::local_from_unix).map(|l| l.sortable()).unwrap_or_default();
            Some((r.get("ProcessId")?.as_u64()?, (r.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string(), created)))
        })
        .collect();
    // What hunt.ps1's own cmdlets see (Get-CimInstance can return less than WMI does).
    let cim = ps_json(
        "$d = [object[]]@(Get-CimInstance Win32_SystemDriver | ForEach-Object { $_.Name })\r\n\
         $n = [object[]]@(Get-CimInstance Win32_Service | Where-Object { -not $_.PathName } | ForEach-Object { $_.Name })\r\n\
         $o = New-Object psobject; $o | Add-Member drivers $d; $o | Add-Member noPath $n\r\n\
         $o | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $OutFile -Encoding UTF8",
        &work,
        "cim",
    )
    .unwrap_or(Value::Null);
    let strs = |v: &Value| as_list(v).iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>();
    let cx = hunt::Context { ps_started, alive, wmi_drivers: strs(&cim["drivers"]), wmi_no_path: strs(&cim["noPath"]), signer_proof };
    let (diffs, counts) = hunt::compare(&pv, &rv, &cx);
    let unexplained: Vec<&hunt::D> = diffs.iter().filter(|d| d.explained.is_none()).collect();
    println!("timing: hunt.ps1 {ps_secs:.1}s, hideout hunt {rs_secs:.1}s");
    println!("{:<20} {:>6} {:>6} {:>8} {:>10} {:>12}", "section", "ps", "rust", "matched", "explained", "UNEXPLAINED");
    for (sec, (p, r, m)) in &counts {
        let e = diffs.iter().filter(|d| &d.section == sec && d.explained.is_some()).count();
        let u = diffs.iter().filter(|d| &d.section == sec && d.explained.is_none()).count();
        println!("{sec:<20} {p:>6} {r:>6} {m:>8} {e:>10} {u:>12}");
    }
    let mut by_id: BTreeMap<&str, usize> = BTreeMap::new();
    for id in diffs.iter().filter_map(|d| d.explained) {
        *by_id.entry(id).or_default() += 1;
    }
    for (id, n) in &by_id {
        println!("  explained {id}: {n}");
    }
    for d in unexplained.iter().take(80) {
        println!("  UNEXPLAINED [{}] {} - {}", d.section, d.key, d.what);
    }
    println!("parity hunt: {} difference(s), {} explained, {} UNEXPLAINED", diffs.len(), diffs.len() - unexplained.len(), unexplained.len());
    if let Some(path) = opt(args, "--report") {
        let rep = json!({
            "known": hunt::KNOWN.iter().map(|(id, why)| json!({"id": id, "why": why})).collect::<Vec<_>>(),
            "seconds": {"ps": ps_secs, "rust": rs_secs},
            "sections": counts.iter().map(|(k, (p, r, m))| json!({"section": k, "ps": p, "rust": r, "matched": m})).collect::<Vec<_>>(),
            "differences": diffs.iter().map(|d| json!({"section": d.section, "key": d.key, "what": d.what, "explained": d.explained})).collect::<Vec<_>>(),
            "ps": pv, "rust": rv,
        });
        let _ = std::fs::write(&path, serde_json::to_string_pretty(&rep).unwrap_or_default());
    }
    let _ = std::fs::remove_dir_all(&work);
    if unexplained.is_empty() { 0 } else { 1 }
}

fn quick(args: &[String]) -> i32 {
    let repo = find_repo(opt(args, "--repo"));
    let rust = opt(args, "--rust").map(PathBuf::from).unwrap_or_else(default_rust);
    let test_targets = opt(args, "--test-targets");
    let work = temp_dir();
    let engine_path = repo.join("hideout.ps1");
    let engine = match std::fs::read_to_string(&engine_path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("hideout-parity: {}: {e}", engine_path.display());
            return 2;
        }
    };
    let ep = engine_path.display().to_string().replace('\'', "''");

    let mut diffs = Vec::new();
    let mut explained = Explained::default();
    let t0 = std::time::Instant::now();
    let (ps_report, rs_report);
    if let Some(tt) = &test_targets {
        let tq = tt.replace('\'', "''");
        ps_report = ps_json(&format!("& '{ep}' -Json -TestTargets '{tq}' | Set-Content -LiteralPath $OutFile -Encoding UTF8"), &work, "ps-quick");
        let ps_secs = t0.elapsed().as_secs_f64();
        let t1 = std::time::Instant::now();
        rs_report = rust_json(&rust, &["scan", "--json", "--test-targets", tt]);
        eprintln!("timing: powershell {ps_secs:.1}s, rust {:.1}s", t1.elapsed().as_secs_f64());
    } else {
        let script = match ps_targets_script(&engine) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("hideout-parity: {e}");
                return 2;
            }
        };
        match (ps_json(&script, &work, "ps-targets"), rust_json(&rust, &["scan", "--list-targets"])) {
            (Ok(p), Ok(r)) => {
                let no_path: Vec<String> = as_list(p.get("wmiNoPath").unwrap_or(&Value::Null)).iter().filter_map(|v| v.as_str().map(String::from)).collect();
                explained = compare_targets(&as_list(p.get("targets").unwrap_or(&Value::Null)), &as_list(&r), &no_path, &mut diffs);
            }
            (a, b) => {
                eprintln!("hideout-parity: target listing failed: ps={:?} rust={:?}", a.err(), b.err());
                return 2;
            }
        }
        let t0 = std::time::Instant::now();
        ps_report = ps_json(&format!("& '{ep}' -Json | Set-Content -LiteralPath $OutFile -Encoding UTF8"), &work, "ps-quick");
        let ps_secs = t0.elapsed().as_secs_f64();
        let t1 = std::time::Instant::now();
        rs_report = rust_json(&rust, &["scan", "--json"]);
        eprintln!("timing: powershell {ps_secs:.1}s, rust {:.1}s", t1.elapsed().as_secs_f64());
    }
    let (ps_report, rs_report) = match (ps_report, rs_report) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            eprintln!("hideout-parity: a scan failed: ps={:?} rust={:?}", a.err(), b.err());
            return 2;
        }
    };
    compare_quick(&ps_report, &rs_report, &explained, &mut diffs);

    let unexplained = diffs.iter().filter(|d| d.explained.is_none()).count();
    println!(
        "parity quick: {} start items (ps) / {} (rust); {} finding(s) (ps) / {} (rust); {} difference(s), {} explained, {} UNEXPLAINED",
        ps_report.pointer("/checked/startItems").cloned().unwrap_or(Value::Null),
        rs_report.pointer("/checked/startItems").cloned().unwrap_or(Value::Null),
        as_list(ps_report.get("findings").unwrap_or(&Value::Null)).len(),
        as_list(rs_report.get("findings").unwrap_or(&Value::Null)).len(),
        diffs.len(),
        diffs.len() - unexplained,
        unexplained
    );
    for d in &diffs {
        let tag = d.explained.map(|e| format!("explained: {e}")).unwrap_or_else(|| "UNEXPLAINED".into());
        println!("  [{}] {} {}\n      ps:   {}\n      rust: {}", tag, d.area, d.key, d.ps, d.rust);
    }
    if let Some(path) = opt(args, "--report") {
        let rep = json!({
            "mode": if test_targets.is_some() { "test-targets" } else { "this-pc" },
            "computer": std::env::var("COMPUTERNAME").unwrap_or_default(),
            "known": KNOWN.iter().map(|(id, why)| json!({"id": id, "why": why})).collect::<Vec<_>>(),
            "differences": diffs.iter().map(|d| json!({"area": d.area, "key": d.key, "ps": d.ps, "rust": d.rust, "explained": d.explained})).collect::<Vec<_>>(),
            "unexplained": unexplained,
            "ps": ps_report,
            "rust": rs_report,
        });
        let _ = std::fs::write(&path, serde_json::to_string_pretty(&rep).unwrap_or_default());
    }
    let _ = std::fs::remove_dir_all(&work);
    if unexplained == 0 { 0 } else { 1 }
}

// Negative controls: the harness must go red when the engines disagree, when an
// engine misses a planted threat, and when it flags something it should not.
#[cfg(test)]
mod tests {
    use super::*;

    fn report(findings: Value) -> Value {
        json!({"app": "Hideout", "version": 1, "computer": "PC", "admin": false,
               "checked": {"startItems": 1, "inUserFolders": 1, "byKind": {"Scheduled task": 1}, "couldNotCheck": []},
               "defender": null, "findings": findings})
    }
    fn finding(sev: &str, tags: &[&str]) -> Value {
        json!({"severity": sev, "score": 5, "kind": "Scheduled task", "name": "t", "state": "Ready", "program": "App.exe",
               "folder": r"C:\Users\X\AppData\Local\Temp\f\PlainTool", "signer": "S", "arrived": "",
               "reasons": tags.iter().map(|t| json!({"tag": t, "text": format!("{t}: x.dll")})).collect::<Vec<_>>()})
    }

    #[test]
    fn identical_reports_have_no_differences() {
        let r = report(json!([finding("high", &["Tampered file"])]));
        let mut d = Vec::new();
        compare_quick(&r, &r, &Explained::default(), &mut d);
        assert!(d.is_empty(), "{d:?}");
    }

    #[test]
    fn a_severity_change_is_unexplained() {
        let mut d = Vec::new();
        compare_quick(&report(json!([finding("high", &["Tampered file"])])), &report(json!([finding("medium", &["Tampered file"])])), &Explained::default(), &mut d);
        assert_eq!(d.iter().filter(|x| x.explained.is_none()).count(), 1);
    }

    #[test]
    fn a_missing_finding_is_unexplained() {
        let mut d = Vec::new();
        compare_quick(&report(json!([finding("high", &["Tampered file"])])), &report(json!([])), &Explained::default(), &mut d);
        assert_eq!(d.iter().filter(|x| x.explained.is_none()).count(), 1);
    }

    #[test]
    fn count_drift_is_unexplained() {
        let mut a = report(json!([]));
        let b = report(json!([]));
        a["checked"]["startItems"] = json!(2);
        let mut d = Vec::new();
        compare_quick(&a, &b, &Explained::default(), &mut d);
        assert!(d.iter().any(|x| x.key == "startItems" && x.explained.is_none()));
    }

    #[test]
    fn expectation_check_catches_miss_and_extra() {
        let expected = vec![json!({"id": "F2", "folder": "PlainTool", "program": "App.exe", "severity": "high", "tags": ["Tampered file"]})];
        // Missed entirely.
        let miss = fixtures::check(&report(json!([])), &expected, "rust");
        assert!(miss.iter().any(|f| f.contains("MISSED")), "{miss:?}");
        // Right verdict, wrong reason.
        let wrong = fixtures::check(&report(json!([finding("high", &["Random folder"])])), &expected, "rust");
        assert!(wrong.iter().any(|f| f.contains("missing reason")), "{wrong:?}");
        // Right.
        assert!(fixtures::check(&report(json!([finding("high", &["Tampered file"])])), &expected, "rust").is_empty());
        // Something flagged that no fixture expects.
        let mut extra = finding("low", &["Unsigned DLLs"]);
        extra["folder"] = json!(r"C:\elsewhere\Other");
        let x = fixtures::check(&report(json!([finding("high", &["Tampered file"]), extra])), &expected, "rust");
        assert!(x.iter().any(|f| f.contains("EXTRA")), "{x:?}");
    }
}

#[cfg(test)]
mod count_tests {
    #[test]
    fn counts_in_user_matches_the_engine_rule() {
        let tmp = std::env::temp_dir().join("hideout-parity-count.exe");
        std::fs::write(&tmp, b"x").unwrap();
        // %TEMP% is under the user's AppData: counted.
        assert!(super::counts_in_user(&tmp.to_string_lossy()));
        std::fs::remove_file(&tmp).ok();
        assert!(!super::counts_in_user("C:/nope.exe"));
    }
}
