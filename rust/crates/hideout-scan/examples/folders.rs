//! Dev tool: time the folder check per user-folder program.
use std::time::Instant;
fn main() {
    hideout_win::com::init();
    let g = hideout_scan::quick::gather();
    let inst = hideout_scan::quick::Installed::read();
    let mut seen = std::collections::HashSet::new();
    for t in &g.targets {
        if !hideout_scan::rules::user_writable(&t.exe) || !hideout_scan::rules::program_ext(&t.exe) || std::fs::metadata(&t.exe).is_err() { continue; }
        let dir = hideout_scan::rules::parent(&t.exe).to_lowercase();
        if !seen.insert(dir.clone()) { continue; }
        let n = std::fs::read_dir(&dir).map(|r| r.count()).unwrap_or(0);
        let t0 = Instant::now();
        let _ = hideout_scan::quick::check_folder(&t.exe, &inst);
        eprintln!("{:>6} ms  {:>4} files  {}", t0.elapsed().as_millis(), n, hideout_scan::rules::leaf(&dir));
    }
}
