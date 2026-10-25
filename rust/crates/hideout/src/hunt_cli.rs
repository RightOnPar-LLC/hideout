//! `hideout hunt [--out <file.json>] [--days N]` - the deep check from the command line,
//! the same switches hunt.ps1 took. Also what "Deep check (admin)" runs elevated: the
//! very same binary, so there is no separate script on disk to swap.

use std::path::PathBuf;

pub fn default_out() -> PathBuf {
    let l = hideout_win::time::now_local();
    let stamp = format!("{:04}{:02}{:02}-{:02}{:02}", l.year, l.month, l.day, l.hour, l.minute);
    PathBuf::from("out").join(format!("hunt-{}-{stamp}.json", std::env::var("COMPUTERNAME").unwrap_or_default()))
}

pub fn run(args: &[String]) -> i32 {
    let mut out: Option<PathBuf> = None;
    let mut days = 180u32;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" | "-Out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            "--days" | "-Days" => {
                i += 1;
                match args.get(i).and_then(|d| d.parse().ok()) {
                    Some(d) if (1..=3650).contains(&d) => days = d,
                    _ => {
                        eprintln!("hideout hunt: --days needs a number of days (1-3650)");
                        return 2;
                    }
                }
            }
            other => {
                eprintln!("hideout hunt: unknown option {other}");
                return 2;
            }
        }
        i += 1;
    }
    let out = out.unwrap_or_else(default_out);
    println!("Hideout hunt - {} - admin={}", std::env::var("COMPUTERNAME").unwrap_or_default(), hideout_win::admin::is_elevated());
    let report = hideout_scan::hunt::run(days, |line| println!("{line}"));
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("hideout hunt: could not create {}: {e}", dir.display());
            return 1;
        }
    }
    let text = serde_json::to_string_pretty(&report).unwrap_or_default();
    if let Err(e) = std::fs::write(&out, text) {
        eprintln!("hideout hunt: could not write {}: {e}", out.display());
        return 1;
    }
    println!("Hideout hunt done in {}s - {}", report["seconds"], out.display());
    0
}
