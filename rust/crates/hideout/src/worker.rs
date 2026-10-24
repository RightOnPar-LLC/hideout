//! The background worker: runs scans as jobs, one at a time, while the person keeps
//! using the window. Every job is READ-ONLY.
//!
//!   scan        quick check of everything set to start by itself
//!   hunt        deep check as the current user        (ported in Phase 3)
//!   hunt-admin  deep check with admin rights          (ported in Phase 3)
//!
//! The state it reports has the same shape as worker.mjs, so the window reads either.

use hideout_scan::quick;
use serde_json::{json, Value};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

pub const KINDS: [&str; 3] = ["scan", "hunt", "hunt-admin"];

#[derive(Debug, Clone)]
pub struct Job {
    pub id: u64,
    pub kind: String,
    pub state: String,
    pub started: Option<String>,
    pub finished: Option<String>,
    pub message: String,
    pub progress: Vec<String>,
}

impl Job {
    fn public(&self) -> Value {
        json!({"id": self.id, "kind": self.kind, "state": self.state, "message": self.message, "progress": self.progress.last().cloned().unwrap_or_default()})
    }
    fn summary(&self) -> Value {
        let p: Vec<&String> = self.progress.iter().rev().take(3).collect::<Vec<_>>().into_iter().rev().collect();
        json!({"id": self.id, "kind": self.kind, "state": self.state, "started": self.started, "finished": self.finished, "message": self.message, "progress": p})
    }
}

/// What the worker tells the server: a job changed, or the whole state did.
#[derive(Debug, Clone)]
pub enum Event {
    Job(Value),
    State,
}

#[derive(Default)]
struct Inner {
    jobs: Vec<Job>,
    seq: u64,
    active: Option<u64>,
    latest_scan: Option<Value>,
    latest_hunt: Option<Value>,
}

/// Runs the scan for real. Swappable so the server tests do not scan the PC.
pub type ScanFn = Arc<dyn Fn() -> Result<Value, String> + Send + Sync>;

pub fn real_scan() -> ScanFn {
    Arc::new(|| {
        // Places that could not be read travel in checked.sourcesNotRead.
        serde_json::to_value(quick::scan_pc()).map_err(|e| e.to_string())
    })
}

#[derive(Clone)]
pub struct Worker {
    inner: Arc<Mutex<Inner>>,
    queue: Sender<u64>,
    events: Sender<Event>,
}

fn now() -> String {
    let l = hideout_win::time::now_local();
    l.sortable()
}

impl Worker {
    pub fn start(scan: ScanFn, events: Sender<Event>) -> Worker {
        let (tx, rx) = channel::<u64>();
        let w = Worker { inner: Arc::new(Mutex::new(Inner::default())), queue: tx, events };
        let me = w.clone();
        std::thread::Builder::new().name("hideout-worker".into()).spawn(move || me.pump(rx, scan)).expect("worker thread");
        w
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock means a job panicked mid-update; the data is still usable.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn busy(&self) -> bool {
        self.lock().active.is_some()
    }

    pub fn state(&self) -> Value {
        let i = self.lock();
        let start = i.jobs.len().saturating_sub(8);
        json!({
            "busy": i.active.is_some(),
            "jobs": i.jobs[start..].iter().map(Job::summary).collect::<Vec<_>>(),
            "latestScan": i.latest_scan,
            "latestHunt": i.latest_hunt,
        })
    }

    /// Queue a job. The same kind already waiting or running is handed back instead of
    /// stacking a duplicate. Err for an unknown kind.
    pub fn enqueue(&self, kind: &str) -> Result<(u64, String), String> {
        if !KINDS.contains(&kind) {
            return Err(format!("unknown job kind: {kind}"));
        }
        let mut i = self.lock();
        if let Some(j) = i.jobs.iter().find(|j| j.kind == kind && (j.state == "queued" || j.state == "running")) {
            return Ok((j.id, j.state.clone()));
        }
        i.seq += 1;
        let job = Job { id: i.seq, kind: kind.into(), state: "queued".into(), started: None, finished: None, message: String::new(), progress: Vec::new() };
        let (id, public) = (job.id, job.public());
        i.jobs.push(job);
        let excess = i.jobs.len().saturating_sub(64);
        if excess > 0 {
            i.jobs.drain(..excess);
        }
        drop(i);
        let _ = self.events.send(Event::Job(public));
        let _ = self.queue.send(id);
        Ok((id, "queued".into()))
    }

    fn update(&self, id: u64, f: impl FnOnce(&mut Job)) {
        let public = {
            let mut i = self.lock();
            let Some(j) = i.jobs.iter_mut().find(|j| j.id == id) else { return };
            f(j);
            j.public()
        };
        let _ = self.events.send(Event::Job(public));
    }

    fn pump(&self, rx: Receiver<u64>, scan: ScanFn) {
        while let Ok(id) = rx.recv() {
            let kind = {
                let mut i = self.lock();
                i.active = Some(id);
                i.jobs.iter().find(|j| j.id == id).map(|j| j.kind.clone()).unwrap_or_default()
            };
            self.update(id, |j| {
                j.state = "running".into();
                j.started = Some(now());
            });
            let result: Result<String, String> = match kind.as_str() {
                "scan" => {
                    self.update(id, |j| j.progress.push("Checking everything set to start by itself...".into()));
                    let s = scan.clone();
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s())) {
                        Ok(Ok(mut report)) => {
                            let n = report.get("findings").and_then(|f| f.as_array()).map(|a| a.len()).unwrap_or(0);
                            if let Value::Object(m) = &mut report {
                                let mut with_at = serde_json::Map::new();
                                with_at.insert("at".into(), json!(now()));
                                with_at.extend(m.clone());
                                report = Value::Object(with_at);
                            }
                            self.lock().latest_scan = Some(report);
                            Ok(format!("{n} finding(s)"))
                        }
                        Ok(Err(e)) => Err(format!("scan did not finish ({e})")),
                        Err(_) => Err("scan did not finish (an internal error stopped it)".into()),
                    }
                }
                _ => Err("the deep check is not in this build yet - use the quick scan for now".into()),
            };
            self.update(id, |j| {
                match &result {
                    Ok(m) => {
                        j.state = "done".into();
                        j.message = m.clone();
                    }
                    Err(e) => {
                        j.state = "failed".into();
                        j.message = e.chars().take(300).collect();
                    }
                }
                j.finished = Some(now());
            });
            self.lock().active = None;
            let _ = self.events.send(Event::State);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fake(findings: usize) -> ScanFn {
        Arc::new(move || {
            std::thread::sleep(Duration::from_millis(50));
            Ok(json!({"app": "Hideout", "findings": vec![json!({"severity": "high"}); findings]}))
        })
    }

    fn wait_done(w: &Worker, id: u64) -> Value {
        for _ in 0..200 {
            let s = w.state();
            if let Some(j) = s["jobs"].as_array().unwrap().iter().find(|j| j["id"] == id) {
                if j["state"] == "done" || j["state"] == "failed" {
                    return j.clone();
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("job {id} never finished");
    }

    #[test]
    fn runs_a_scan_and_keeps_the_result() {
        let (tx, _rx) = channel();
        let w = Worker::start(fake(2), tx);
        let (id, st) = w.enqueue("scan").unwrap();
        assert_eq!(st, "queued");
        let j = wait_done(&w, id);
        assert_eq!(j["state"], "done");
        assert_eq!(j["message"], "2 finding(s)");
        let s = w.state();
        assert_eq!(s["latestScan"]["findings"].as_array().unwrap().len(), 2);
        assert!(s["latestScan"]["at"].is_string());
        assert_eq!(s["busy"], false);
    }

    #[test]
    fn duplicate_kind_is_not_stacked() {
        let (tx, _rx) = channel();
        let w = Worker::start(fake(0), tx);
        let (a, _) = w.enqueue("scan").unwrap();
        let (b, _) = w.enqueue("scan").unwrap();
        assert_eq!(a, b);
        wait_done(&w, a);
    }

    #[test]
    fn unknown_kind_is_refused_and_hunt_fails_honestly() {
        let (tx, _rx) = channel();
        let w = Worker::start(fake(0), tx);
        assert!(w.enqueue("delete-everything").is_err());
        let (id, _) = w.enqueue("hunt").unwrap();
        let j = wait_done(&w, id);
        assert_eq!(j["state"], "failed");
        assert!(j["message"].as_str().unwrap().contains("not in this build"));
    }

    #[test]
    fn a_failing_or_panicking_scan_is_failed_not_clean() {
        let (tx, _rx) = channel();
        let w = Worker::start(Arc::new(|| Err("could not read services".into())), tx.clone());
        let (id, _) = w.enqueue("scan").unwrap();
        assert_eq!(wait_done(&w, id)["state"], "failed");
        assert!(w.state()["latestScan"].is_null(), "a failed scan must not look like a result");
        let w2 = Worker::start(Arc::new(|| panic!("boom")), tx);
        let (id2, _) = w2.enqueue("scan").unwrap();
        assert_eq!(wait_done(&w2, id2)["state"], "failed");
    }
}
