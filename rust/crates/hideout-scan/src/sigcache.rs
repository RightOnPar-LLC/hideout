//! One signature check per file per scan. The folder check and the item facts both
//! ask about the same programs; the answer is computed once and shared.

use hideout_win::authenticode::{self, Signature};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

fn cache() -> &'static Mutex<HashMap<String, Signature>> {
    static C: OnceLock<Mutex<HashMap<String, Signature>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The signature of `path`, from this scan's cache when already checked.
pub fn check(path: &Path) -> Signature {
    let key = path.to_string_lossy().to_lowercase();
    if let Some(s) = cache().lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
        return s.clone();
    }
    let s = authenticode::check(path);
    cache().lock().unwrap_or_else(|p| p.into_inner()).insert(key, s.clone());
    s
}

/// Forget everything: each scan starts fresh (a file can change between scans).
pub fn clear() {
    cache().lock().unwrap_or_else(|p| p.into_inner()).clear();
}
