//! A tiny parallel map on scoped threads (no thread-pool crate). Signature checks are
//! the slow part of a scan and are independent, so they run side by side. Order is kept.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

pub fn workers() -> usize {
    if let Some(n) = std::env::var("HIDEOUT_WORKERS").ok().and_then(|v| v.parse::<usize>().ok()) {
        return n.clamp(1, 64);
    }
    // Measured: Windows' signature verifier stops scaling past about 8 threads (an
    // internal lock), and more only adds contention.
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 8)
}

/// `f` over every item, on up to `workers()` threads. A panic in `f` for one item gives
/// None for that item only.
pub fn map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<Option<R>> {
    if items.len() <= 1 {
        return items.iter().map(|t| std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(t))).ok()).collect();
    }
    let next = AtomicUsize::new(0);
    let out: Vec<Mutex<Option<R>>> = (0..items.len()).map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..workers().min(items.len()) {
            s.spawn(|| {
                hideout_win::com::init();
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= items.len() {
                        break;
                    }
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&items[i]))).ok();
                    *out[i].lock().unwrap_or_else(|p| p.into_inner()) = r;
                }
            });
        }
    });
    out.into_iter().map(|m| m.into_inner().unwrap_or_else(|p| p.into_inner())).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn keeps_order_and_isolates_panics() {
        let v: Vec<u32> = (0..100).collect();
        let r = super::map(&v, |x| {
            if *x == 42 {
                panic!("bad item");
            }
            x * 2
        });
        assert_eq!(r.len(), 100);
        assert_eq!(r[10], Some(20));
        assert_eq!(r[42], None);
        assert_eq!(r[99], Some(198));
    }
}
