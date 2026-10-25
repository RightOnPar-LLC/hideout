//! Planted fixtures: one folder per trick the scan must catch (or must NOT flag), built
//! from a real embedded-signed program on this PC, plus the verdict each one should
//! get. The expected verdicts are written here, from the rules, BEFORE either engine
//! runs - so the engines are checked against the spec, not just against each other.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Built {
    pub root: PathBuf,
    pub targets: PathBuf,
    pub expected: Vec<Value>,
    pub skipped: Vec<String>,
}

/// Small embedded-signed (not catalog-signed) programs: a flipped byte in one of these
/// gives a true HashMismatch, which is what a tampered sideloaded DLL looks like.
fn find_signed(installed_text: &str, want_orphan: bool) -> Option<(PathBuf, String)> {
    let pf = std::env::var("ProgramFiles").unwrap_or_default();
    let pf86 = std::env::var("ProgramFiles(x86)").unwrap_or_default();
    let dirs = [
        format!("{pf}\\Windows Defender"),
        format!("{pf}\\Git\\mingw64\\bin"),
        format!("{pf}\\nodejs"),
        format!("{pf}\\Microsoft OneDrive"),
        format!("{pf86}\\Microsoft\\Edge\\Application"),
        format!("{pf}\\Windows Defender Advanced Threat Protection"),
        format!("{pf}\\Common Files\\microsoft shared\\ClickToRun"),
        pf.clone(),
        pf86.clone(),
    ];
    let mut seen = 0;
    for d in dirs.iter() {
        let mut stack = vec![(PathBuf::from(d), 0u32)];
        while let Some((dir, depth)) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_dir() {
                    if depth < 3 {
                        stack.push((p, depth + 1));
                    }
                    continue;
                }
                let name = p.to_string_lossy().to_lowercase();
                if !(name.ends_with(".exe") || name.ends_with(".dll")) {
                    continue;
                }
                let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                if !(50 * 1024..8 * 1024 * 1024).contains(&len) {
                    continue;
                }
                seen += 1;
                if seen > 4000 {
                    return None;
                }
                let s = hideout_win::authenticode::check(&p);
                if s.status != hideout_win::authenticode::SigStatus::Valid || s.from_catalog {
                    continue;
                }
                let org = org_of(&s.subject);
                let word = org.split(|c: char| c.is_whitespace() || c == ',' || c == '(').next().unwrap_or("").to_string();
                let orphan = word.chars().count() >= 3 && !installed_text.to_lowercase().contains(&word.to_lowercase());
                if orphan == want_orphan {
                    return Some((p, org));
                }
            }
        }
    }
    None
}

fn org_of(subject: &str) -> String {
    // Same rule as the engine (O= first, CN= second); kept local so the fixture builder
    // does not depend on the code it is testing.
    let lower = subject.to_lowercase();
    for key in ["o=", "cn="] {
        if let Some(i) = lower.find(key) {
            let rest = &subject[i + key.len()..];
            let rest = rest.strip_prefix('"').unwrap_or(rest);
            let end = rest.find([',', '"']).unwrap_or(rest.len());
            return rest[..end].trim().to_string();
        }
    }
    String::new()
}

/// Deterministic pseudo-random bytes (xorshift), so fixtures are the same every run.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn flipped(src: &Path) -> Vec<u8> {
    let mut b = std::fs::read(src).expect("read signed file");
    let mid = b.len() / 2;
    b[mid] ^= 0xFF;
    b
}

fn hide(p: &Path) {
    let _ = Command::new("attrib").arg("+h").arg(p).status();
}

pub fn build(root: &Path, installed_text: &str) -> Result<Built, String> {
    let (signed, signed_org) = find_signed(installed_text, false).ok_or("no embedded-signed program found on this PC to build fixtures from")?;
    let orphan = find_signed(installed_text, true);
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let mk = |name: &str| -> PathBuf {
        let d = root.join(name);
        std::fs::create_dir_all(&d).expect("fixture dir");
        d
    };
    let copy = |to: &Path| std::fs::copy(&signed, to).map(|_| ()).map_err(|e| e.to_string());
    let mut targets = Vec::new();
    let mut expected = Vec::new();
    let mut skipped = Vec::new();
    let t = |kind: &str, name: &str, exe: &Path| json!({"kind": kind, "name": name, "state": "Ready", "exe": exe.to_string_lossy()});

    // F1 - the real case: a signed program in a machine-named ProgramData-style folder,
    // a sibling DLL changed after signing, three unsigned DLLs, payloads dressed as media.
    let d = mk("qXkRzTwP4m");
    copy(&d.join("Player.exe"))?;
    std::fs::write(d.join("codec.dll"), flipped(&signed)).map_err(|e| e.to_string())?;
    for (i, n) in ["helper.dll", "render.dll", "net.dll"].iter().enumerate() {
        std::fs::write(d.join(n), noise(4096, 7 + i as u64)).map_err(|e| e.to_string())?;
    }
    std::fs::write(d.join("intro.wav"), noise(200 * 1024, 9)).map_err(|e| e.to_string())?;
    std::fs::write(d.join("data.raw"), noise(300 * 1024, 11)).map_err(|e| e.to_string())?;
    std::fs::write(d.join("run.vbs"), "WScript.Echo 1").map_err(|e| e.to_string())?;
    targets.push(t("Scheduled task", "Evil <img src=x onerror=alert(1)> task", &d.join("Player.exe")));
    // Same folder, second program: the folder verdict is shared.
    targets.push(t("Service", "second entry same folder", &d.join("render.dll")));
    targets.push(t("Startup folder", "a script", &d.join("run.vbs")));
    expected.push(json!({"id": "F1-real-case", "folder": "qXkRzTwP4m", "program": "Player.exe", "severity": "high", "tags": ["Tampered file", "Unsigned DLLs", "Random folder", "Hidden payload"]}));
    expected.push(json!({"id": "F1b-same-folder", "folder": "qXkRzTwP4m", "program": "render.dll", "severity": "high", "tags": ["Tampered file", "Unsigned DLLs", "Random folder", "Hidden payload"]}));

    // F2 - tampered only.
    let d = mk("PlainTool");
    copy(&d.join("App.exe"))?;
    std::fs::write(d.join("core.dll"), flipped(&signed)).map_err(|e| e.to_string())?;
    targets.push(t("Scheduled task", "F2 tampered", &d.join("App.exe")));
    expected.push(json!({"id": "F2-tampered", "folder": "PlainTool", "program": "App.exe", "severity": "high", "tags": ["Tampered file"], "notTags": ["Unsigned program", "Random folder"]}));

    // F3 - an unsigned DLL beside a signed program.
    let d = mk("MediaKit");
    copy(&d.join("App.exe"))?;
    std::fs::write(d.join("plugin.dll"), noise(8192, 21)).map_err(|e| e.to_string())?;
    targets.push(t("Startup (registry)", "F3 unsigned neighbour", &d.join("App.exe")));
    expected.push(json!({"id": "F3-unsigned-neighbour", "folder": "MediaKit", "program": "App.exe", "severity": "low", "tags": ["Unsigned DLLs"], "notTags": ["Tampered file"]}));

    // F4 - a payload alone is a weak signal: shown nowhere on its own (score 1).
    let d = mk("VideoTool");
    copy(&d.join("App.exe"))?;
    std::fs::write(d.join("movie.dat"), noise(300 * 1024, 31)).map_err(|e| e.to_string())?;
    targets.push(t("Scheduled task", "F4 payload only", &d.join("App.exe")));
    expected.push(json!({"id": "F4-payload-alone", "folder": "VideoTool", "program": "App.exe", "severity": ""}));

    // F5 - a machine-made folder name alone: weak signal, no finding.
    let d = mk("kLmQzRtPx8");
    copy(&d.join("App.exe"))?;
    targets.push(t("Scheduled task", "F5 random folder only", &d.join("App.exe")));
    expected.push(json!({"id": "F5-random-folder-alone", "folder": "kLmQzRtPx8", "program": "App.exe", "severity": ""}));

    // F6 - signed by a vendor with nothing installed here.
    match &orphan {
        Some((src, org)) => {
            let d = mk("OrphanApp");
            let ext = src.extension().and_then(|e| e.to_str()).unwrap_or("exe");
            let p = d.join(format!("Tool.{ext}"));
            std::fs::copy(src, &p).map_err(|e| e.to_string())?;
            targets.push(t("Service", "F6 orphaned signer", &p));
            expected.push(json!({"id": "F6-orphaned-signer", "folder": "OrphanApp", "program": format!("Tool.{ext}"), "severity": "low", "tags": ["No matching install"], "signer": org}));
        }
        None => skipped.push("F6-orphaned-signer: every signed program found on this PC belongs to an installed vendor".into()),
    }

    // F7 - the program itself is not signed.
    let d = mk("Helper");
    std::fs::write(d.join("Run.exe"), noise(16384, 41)).map_err(|e| e.to_string())?;
    targets.push(t("Startup folder", "F7 unsigned program", &d.join("Run.exe")));
    expected.push(json!({"id": "F7-unsigned-program", "folder": "Helper", "program": "Run.exe", "severity": "medium", "tags": ["Unsigned program"]}));

    // F8 - clean.
    let d = mk("PlainApp");
    copy(&d.join("App.exe"))?;
    targets.push(t("Scheduled task", "F8 clean", &d.join("App.exe")));
    expected.push(json!({"id": "F8-clean", "folder": "PlainApp", "program": "App.exe", "severity": ""}));

    // F9 - a tampered DLL that is also HIDDEN. hideout.ps1 never looked at hidden files;
    // the Rust engine must still catch it.
    let d = mk("HiddenKit");
    copy(&d.join("App.exe"))?;
    let hidden = d.join("codec.dll");
    std::fs::write(&hidden, flipped(&signed)).map_err(|e| e.to_string())?;
    hide(&hidden);
    targets.push(t("Scheduled task", "F9 hidden tampered dll", &d.join("App.exe")));
    expected.push(json!({"id": "F9-hidden-tampered", "folder": "HiddenKit", "program": "App.exe", "severity": "high", "tags": ["Tampered file"], "rustOnly": true}));

    // F10 - a "voice recording" that is really a Windows program. hideout.ps1 only saw a
    // large data file (one weak signal, no finding); the Rust engine reads its header.
    let d = mk("CodecPack");
    copy(&d.join("App.exe"))?;
    // The program plus padding: still a program, and well over the 100 KB payload size.
    let mut wav = std::fs::read(&signed).map_err(|e| e.to_string())?;
    wav.extend(noise(200 * 1024, 51));
    std::fs::write(d.join("voice.wav"), wav).map_err(|e| e.to_string())?;
    targets.push(t("Scheduled task", "F10 program dressed as media", &d.join("App.exe")));
    expected.push(json!({"id": "F10-program-dressed-as-media", "folder": "CodecPack", "program": "App.exe", "severity": "medium", "tags": ["Program dressed as media", "Hidden payload"], "psSeverity": ""}));

    // F11 - a small renamed program (under the 100 KB payload size) still counts.
    let d = mk("ToolBox");
    copy(&d.join("App.exe"))?;
    let small = std::fs::read(&signed).map_err(|e| e.to_string())?;
    std::fs::write(d.join("skin.dat"), &small[..small.len().min(64 * 1024)]).map_err(|e| e.to_string())?;
    targets.push(t("Scheduled task", "F11 small program as data", &d.join("App.exe")));
    expected.push(json!({"id": "F11-small-program-as-data", "folder": "ToolBox", "program": "App.exe", "severity": "medium", "tags": ["Program dressed as media"], "notTags": ["Hidden payload"], "psSeverity": ""}));

    // Not a sideloading target: a Windows program outside user folders.
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    targets.push(json!({"kind": "Service", "name": "system program", "state": "Running", "exe": format!("{windir}\\System32\\svchost.exe")}));

    let tpath = root.join("targets.json");
    std::fs::write(&tpath, serde_json::to_string_pretty(&targets).unwrap_or_default()).map_err(|e| e.to_string())?;
    let _ = signed_org;
    Ok(Built { root: root.to_path_buf(), targets: tpath, expected, skipped })
}

/// Check one engine's findings against the expected verdicts. Returns failures.
pub fn check(report: &Value, expected: &[Value], engine: &str) -> Vec<String> {
    let findings: Vec<Value> = report.get("findings").and_then(|f| f.as_array()).cloned().unwrap_or_default();
    let mut fails = Vec::new();
    for e in expected {
        let id = e["id"].as_str().unwrap_or("?");
        if engine == "ps" && e.get("rustOnly").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }
        let folder = e["folder"].as_str().unwrap_or("");
        let program = e["program"].as_str().unwrap_or("");
        let hit = findings.iter().find(|f| {
            f["program"].as_str().map(|p| p.eq_ignore_ascii_case(program)).unwrap_or(false)
                && f["folder"].as_str().map(|p| p.to_lowercase().ends_with(&format!("\\{}", folder.to_lowercase()))).unwrap_or(false)
        });
        // Where hideout.ps1 is expected to answer differently (a check it never had).
        let want = if engine == "ps" { e.get("psSeverity").and_then(|v| v.as_str()).or(e["severity"].as_str()).unwrap_or("") } else { e["severity"].as_str().unwrap_or("") };
        match (want, hit) {
            ("", None) => {}
            ("", Some(f)) => fails.push(format!("{engine} {id}: expected no finding, got {} {:?}", f["severity"], tags(f))),
            (_, None) => fails.push(format!("{engine} {id}: MISSED - expected {want}")),
            (_, Some(f)) => {
                if f["severity"].as_str() != Some(want) {
                    fails.push(format!("{engine} {id}: severity {} (expected {want}), tags {:?}", f["severity"], tags(f)));
                }
                let got = tags(f);
                for need in e.get("tags").and_then(|t| t.as_array()).cloned().unwrap_or_default() {
                    if !got.iter().any(|g| Some(g.as_str()) == need.as_str()) {
                        fails.push(format!("{engine} {id}: missing reason {need}, got {got:?}"));
                    }
                }
                for not in e.get("notTags").and_then(|t| t.as_array()).cloned().unwrap_or_default() {
                    if got.iter().any(|g| Some(g.as_str()) == not.as_str()) {
                        fails.push(format!("{engine} {id}: should not have reason {not}"));
                    }
                }
            }
        }
    }
    // Nothing outside the fixture set may be flagged (the fixture targets are all there is).
    for f in &findings {
        let ok = expected.iter().any(|e| {
            f["program"].as_str().map(|p| p.eq_ignore_ascii_case(e["program"].as_str().unwrap_or(""))).unwrap_or(false)
                && f["folder"].as_str().map(|p| p.to_lowercase().ends_with(&format!("\\{}", e["folder"].as_str().unwrap_or("").to_lowercase()))).unwrap_or(false)
        });
        if !ok {
            fails.push(format!("{engine}: EXTRA finding {} in {}", f["program"], f["folder"]));
        }
    }
    let nc = report.pointer("/checked/couldNotCheck").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
    if nc != 0 {
        fails.push(format!("{engine}: {nc} target(s) could not be checked"));
    }
    if report.pointer("/checked/inUserFolders").and_then(|v| v.as_u64()) != Some(expected_in_user(expected)) {
        fails.push(format!(
            "{engine}: inUserFolders = {} (expected {}: scripts and system programs are not sideloading targets)",
            report.pointer("/checked/inUserFolders").cloned().unwrap_or(Value::Null),
            expected_in_user(expected)
        ));
    }
    fails
}

fn expected_in_user(expected: &[Value]) -> u64 {
    // One target per expected entry; the script and svchost targets are not counted.
    expected.len() as u64
}

fn tags(f: &Value) -> Vec<String> {
    f["reasons"].as_array().map(|a| a.iter().filter_map(|r| r["tag"].as_str().map(String::from)).collect()).unwrap_or_default()
}
