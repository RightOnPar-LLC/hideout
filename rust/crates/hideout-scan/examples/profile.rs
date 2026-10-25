//! Dev tool: time each part of the quick scan on this PC.
use std::time::Instant;
fn main() {
    hideout_win::com::init();
    let t = Instant::now();
    let g = hideout_scan::quick::gather();
    eprintln!("gather        {:>6} ms  ({} entries, {} targets)", t.elapsed().as_millis(), g.entries.len(), g.targets.len());
    let t = Instant::now();
    let inst = hideout_scan::quick::Installed::read();
    eprintln!("installed     {:>6} ms", t.elapsed().as_millis());
    let t = Instant::now();
    let r = hideout_scan::quick::scan(&g.targets, &inst);
    eprintln!("folder checks {:>6} ms  (findings {})", t.elapsed().as_millis(), r.findings.len());
    let mut progs: Vec<String> = g.entries.iter().filter_map(|e| e.program.clone()).collect();
    progs.sort_by_key(|p| p.to_lowercase());
    progs.dedup_by_key(|p| p.to_lowercase());
    let t = Instant::now();
    let f = hideout_scan::par::map(&progs, |p| hideout_scan::quick::facts(p));
    eprintln!("facts         {:>6} ms  ({} programs)", t.elapsed().as_millis(), f.len());
    let t = Instant::now();
    let _ = hideout_scan::par::map(&progs, |p| hideout_win::authenticode::check(std::path::Path::new(p)));
    eprintln!("  sigs again  {:>6} ms", t.elapsed().as_millis());
    let t = Instant::now();
    let r = hideout_scan::quick::scan_pc();
    eprintln!("scan_pc       {:>6} ms  (items {})", t.elapsed().as_millis(), r.items.len());
}
