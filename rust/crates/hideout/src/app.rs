//! App mode: one Hideout per data folder, a loopback server, the window, the first scan.

use crate::server::{self, Config};
use crate::worker::{self, Worker};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::Duration;

/// The window's page: the same file the Node app serves, compiled in.
const UI_HTML: &str = include_str!("../../../../app/ui/index.html");

/// %LOCALAPPDATA%\Hideout - the same folder the Node app uses.
pub fn data_dir() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into())).join("AppData").join("Local"));
    let d = base.join("Hideout");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// The single-instance pipe for a data folder, named exactly as main.mjs names it, so
/// the Rust and Node builds of Hideout never run at once on the same memory.
pub fn pipe_name(dir: &Path) -> String {
    let h = hideout_win::crypto::sha256(dir.to_string_lossy().to_lowercase().as_bytes());
    format!("\\\\.\\pipe\\hideout-{}", &hideout_win::crypto::hex(&h)[..16])
}

fn logger(dir: &Path) -> Arc<dyn Fn(&str) + Send + Sync> {
    let file = dir.join("hideout.log");
    Arc::new(move |m: &str| {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&file) {
            let _ = writeln!(f, "{} {m}", hideout_win::time::now_local().sortable());
        }
    })
}

/// Open the app window: a dedicated Edge profile in app mode (no extensions, no shared
/// cookies), or the default browser if Edge is missing.
pub fn open_window(url: &str, profile: &Path) {
    let candidates = [
        PathBuf::from(std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| "C:\\Program Files (x86)".into())).join("Microsoft\\Edge\\Application\\msedge.exe"),
        PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into())).join("Microsoft\\Edge\\Application\\msedge.exe"),
    ];
    if let Some(edge) = candidates.iter().find(|p| p.is_file()) {
        let _ = std::process::Command::new(edge)
            .arg(format!("--app={url}"))
            .arg(format!("--user-data-dir={}", profile.display()))
            .args(["--no-first-run", "--no-default-browser-check", "--window-size=1240,840"])
            .spawn();
    } else {
        let _ = std::process::Command::new("explorer.exe").arg(url).spawn();
    }
}

pub fn run(args: &[String]) -> i32 {
    let no_open = args.iter().any(|a| a == "--no-open");
    let print_url = args.iter().any(|a| a == "--print-url");
    let dir = data_dir();
    let log = logger(&dir);
    let pipe = pipe_name(&dir);

    if hideout_win::pipe::signal_existing(&pipe) {
        log("second launch - showed the open window");
        println!("Hideout is already open - bringing its window forward.");
        return 0;
    }
    let Some(listener) = hideout_win::pipe::claim(&pipe) else {
        log("could not claim the single-instance pipe");
        eprintln!("Hideout could not start (another copy is starting up).");
        return 1;
    };

    let (etx, erx) = channel();
    let w = Worker::start(worker::real_scan(), worker::real_hunt(dir.clone()), etx);
    let money = Arc::new(std::sync::Mutex::new(hideout_money::money::Money::new(None, Box::new(|| hideout_win::time::now_local().date()))));
    let pc = Arc::new(crate::guide_app::AppPc::new(w.clone()));
    let guide = Arc::new(hideout_guide::guide::Guide::new(crate::guide_app::make_transport(&dir, &*log), crate::guide_app::redactor(), pc.clone(), money.clone(), log.clone()));
    let mode = guide.mode();
    let cfg = Config {
        ui_html: UI_HTML,
        version: env!("CARGO_PKG_VERSION").into(),
        idle_exit: Duration::from_secs(90),
        log: log.clone(),
        money: money.clone(),
        open_url: Arc::new(server::open_external),
        guide,
        look_for_leaks: Arc::new(move || pc.look_for_leaks()),
    };
    let running = match server::start(w.clone(), erx, cfg) {
        Ok(r) => r,
        Err(e) => {
            log(&format!("could not start: {e}"));
            eprintln!("Hideout could not start.");
            return 1;
        }
    };
    let profile = dir.join("window");
    let url = running.launch_url.clone();
    let (p2, u2) = (profile.clone(), url.clone());
    std::thread::Builder::new()
        .name("hideout-pipe".into())
        .spawn(move || listener.serve(move || if !no_open { open_window(&u2, &p2) }))
        .ok();
    log(&format!("started v{} on 127.0.0.1:{} (ai={mode}, memory=false, engine=rust)", env!("CARGO_PKG_VERSION"), running.port));
    if !no_open {
        open_window(&url, &profile);
    }
    if print_url {
        println!("{url}");
    } else {
        println!("Hideout is running (window opened). Close the window to quit.");
    }
    let _ = w.enqueue("scan"); // the first look happens on its own
    // Installed programs (read-only), for "on your PC and on your bill" and remote-access tools.
    let (m2, w2, log2) = (money.clone(), w.clone(), log.clone());
    std::thread::Builder::new()
        .name("hideout-installed".into())
        .spawn(move || {
            let list = installed_programs();
            log2(&format!("installed programs: {}", list.len()));
            m2.lock().unwrap_or_else(|p| p.into_inner()).installed = Some(list);
            w2.notify_state();
        })
        .ok();
    let _ = running.idle.recv();
    log("window closed - exiting");
    0
}

/// The three Uninstall lists: name, publisher, install date. Read-only.
fn installed_programs() -> Vec<hideout_money::money::Installed> {
    use hideout_win::registry::{Hive, Key};
    let mut entries = Vec::new();
    for (hive, path) in [
        (Hive::LocalMachine, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (Hive::LocalMachine, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (Hive::CurrentUser, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ] {
        let Some(k) = Key::open(hive, path) else { continue };
        for sub in k.subkeys() {
            if let Some(e) = k.subkey(&sub) {
                let g = |n: &str| e.string(n).unwrap_or_default();
                entries.push((g("DisplayName"), g("Publisher"), g("InstallDate")));
            }
        }
    }
    hideout_money::money::installed_from(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_matches_the_node_app() {
        // main.mjs: "\\.\pipe\hideout-" + sha256(dir.toLowerCase()).hex.slice(0, 16)
        let n = pipe_name(Path::new("C:\\Users\\Someone\\AppData\\Local\\Hideout"));
        let want = hideout_win::crypto::hex(&hideout_win::crypto::sha256(b"c:\\users\\someone\\appdata\\local\\hideout"));
        assert_eq!(n, format!("\\\\.\\pipe\\hideout-{}", &want[..16]));
    }

    #[test]
    fn ui_is_the_shared_page() {
        assert!(UI_HTML.contains("/api/events") && UI_HTML.contains("/api/state"));
        assert!(!UI_HTML.contains("innerHTML"), "the window renders with textContent only");
    }
}
