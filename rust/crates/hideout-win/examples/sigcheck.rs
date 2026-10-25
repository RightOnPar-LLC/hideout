//! Dev tool: one line per path on stdin -> "status<TAB>subject<TAB>path". Used to
//! calibrate hideout-win's Authenticode answers against Get-AuthenticodeSignature.
use std::io::BufRead;
fn main() {
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        let p = line.trim();
        if p.is_empty() { continue; }
        let s = hideout_win::authenticode::check(std::path::Path::new(p));
        println!("{}\t{}\t{}", s.status.as_str(), s.subject, p);
    }
}
