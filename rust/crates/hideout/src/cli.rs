//! `hideout scan ...` - the quick scan from the command line, with the same switches
//! as hideout.ps1 so the parity harness can drive both the same way:
//!
//!   hideout scan --json                     findings as JSON on stdout
//!   hideout scan --test-targets <file>      scan a given target list instead of the PC
//!   hideout scan --out <file.html> [--open] write the report page (and open it)
//!   hideout scan --list-targets             print what would be scanned (parity harness)

use hideout_scan::quick;
use std::path::PathBuf;

pub fn scan(args: &[String]) -> i32 {
    let mut json = false;
    let mut open = false;
    let mut list_targets = false;
    let mut out: Option<PathBuf> = None;
    let mut test_targets: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" | "-Json" => json = true,
            "--open" | "-Open" => open = true,
            // For the parity harness: print what would be scanned, and stop.
            "--list-targets" => list_targets = true,
            "--out" | "-Out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            "--test-targets" | "-TestTargets" => {
                i += 1;
                test_targets = args.get(i).map(PathBuf::from);
            }
            other => {
                eprintln!("hideout scan: unknown option {other}");
                return 2;
            }
        }
        i += 1;
    }

    let targets = match &test_targets {
        Some(p) => match std::fs::read_to_string(p).map_err(|e| e.to_string()).and_then(|t| quick::targets_from_json(&t)) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("hideout scan: {e}");
                return 2;
            }
        },
        None => {
            let (t, problems) = quick::gather_targets();
            for p in problems {
                eprintln!("hideout scan: could not read {p}");
            }
            t
        }
    };
    if list_targets {
        println!("{}", serde_json::to_string_pretty(&targets).unwrap_or_else(|_| "[]".into()));
        return 0;
    }
    let report = quick::scan(&targets, &quick::Installed::read());

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => {
                println!("{s}");
                return 0;
            }
            Err(e) => {
                eprintln!("hideout scan: {e}");
                return 1;
            }
        }
    }
    let out = out.unwrap_or_else(|| PathBuf::from("out").join("report.html"));
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("hideout scan: could not create {}: {e}", dir.display());
            return 1;
        }
    }
    let data = serde_json::to_string(&report).unwrap_or_else(|_| "null".into());
    if let Err(e) = std::fs::write(&out, hideout_scan::report::render(&data)) {
        eprintln!("hideout scan: could not write {}: {e}", out.display());
        return 1;
    }
    println!("Hideout: {} finding(s) - report: {}", report.findings.len(), out.display());
    if open {
        let _ = std::process::Command::new("explorer.exe").arg(&out).spawn();
    }
    0
}
