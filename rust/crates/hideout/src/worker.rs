//! The background worker: runs scans as jobs, one at a time, while the person keeps
//! using the window. Every job is READ-ONLY.
//!
//!   scan        quick check of everything set to start by itself
//!   hunt        deep check as the current user
//!   hunt-admin  deep check with admin rights - Windows asks the person to click Yes
//!
//! The state it reports has the same shape as worker.mjs, so the window reads either.

use hideout_scan::{hunt, quick};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
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

/// Runs a deep check (admin or not), reporting progress lines. Returns the snapshot and
/// the previous one from this PC (for "what changed"), if there was one.
pub type HuntFn = Arc<dyn Fn(bool, &dyn Fn(String)) -> Result<(Value, Option<Value>), String> + Send + Sync>;

/// The newest earlier deep check saved in `dir`.
fn previous_hunt(dir: &Path) -> Option<Value> {
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .filter_map(|e| e.metadata().and_then(|m| m.modified()).ok().map(|t| (t, e.path())))
        .collect();
    files.sort();
    let (_, p) = files.pop()?;
    serde_json::from_slice(&std::fs::read(p).ok()?).ok()
}

pub fn real_hunt(data_dir: PathBuf) -> HuntFn {
    Arc::new(move |admin: bool, progress: &dyn Fn(String)| {
        let dir = data_dir.join("hunts");
        std::fs::create_dir_all(&dir).map_err(|e| format!("could not create the deep-check folder: {e}"))?;
        let prev = previous_hunt(&dir);
        let l = hideout_win::time::now_local();
        let out = dir.join(format!("hunt-{}{}.json", l.sortable().replace(':', "-"), if admin { "-admin" } else { "" }));
        if !admin {
            let report = hunt::run(180, |line| progress(line.split_whitespace().collect::<Vec<_>>().join(" ")));
            std::fs::write(&out, serde_json::to_string_pretty(&report).unwrap_or_default()).map_err(|e| format!("could not save the deep check: {e}"))?;
            return Ok((report, prev));
        }
        // Elevation hands admin rights to exactly this program - the same binary that is
        // running now, read-only, with no script beside it that could be swapped.
        let me = std::env::current_exe().map_err(|e| e.to_string())?;
        progress("Windows will ask for permission - click Yes to continue.".into());
        let params = format!("hunt --out \"{}\"", out.display());
        match hideout_win::elevate::run_as_admin(&me.to_string_lossy(), &params, 20 * 60 * 1000) {
            hideout_win::elevate::Elevated::Declined => return Err("admin permission wasn't given (the Windows prompt was declined or timed out)".into()),
            hideout_win::elevate::Elevated::TimedOut => return Err("the deep check with admin rights did not finish in 20 minutes".into()),
            hideout_win::elevate::Elevated::Failed(e) => return Err(format!("could not start the deep check with admin rights ({e})")),
            hideout_win::elevate::Elevated::Exited(0) => {}
            hideout_win::elevate::Elevated::Exited(c) => return Err(format!("deep check did not finish (exit {c})")),
        }
        let report: Value = std::fs::read(&out).ok().and_then(|b| serde_json::from_slice(&b).ok()).ok_or("deep check did not finish (no report was written)")?;
        Ok((report, prev))
    })
}

pub fn real_scan() -> ScanFn {
    Arc::new(|| {
        // Places that could not be read travel in checked.sourcesNotRead.
        serde_json::to_value(quick::scan_pc()).map_err(|e| e.to_string())
    })
}

#[derive(Clone)]
pub struct Worker {
    inner: Arc<Mutex<Inner>>,
    hunt: HuntFn,
    queue: Sender<u64>,
    events: Sender<Event>,
}

fn now() -> String {
    let l = hideout_win::time::now_local();
    l.sortable()
}

impl Worker {
    pub fn start(scan: ScanFn, hunt: HuntFn, events: Sender<Event>) -> Worker {
        let (tx, rx) = channel::<u64>();
        let w = Worker { inner: Arc::new(Mutex::new(Inner::default())), hunt, queue: tx, events };
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
                k => {
                    let admin = k == "hunt-admin";
                    let me = self.clone();
                    let progress = move |line: String| me.update(id, |j| j.progress.push(line.chars().take(120).collect()));
                    let h = self.hunt.clone();
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h(admin, &progress))) {
                        Ok(Ok((snapshot, prev))) => {
                            let summary = hunt::summarize(&snapshot);
                            let changes = prev.as_ref().map(|p| hunt::changes(p, &snapshot));
                            let was_admin = snapshot["admin"].as_bool().unwrap_or(false);
                            self.lock().latest_hunt = Some(json!({"at": now(), "admin": was_admin, "summary": summary, "changes": changes}));
                            Ok(format!("deep check done{}", if was_admin { " (with admin)" } else { "" }))
                        }
                        Ok(Err(e)) => Err(e),
                        Err(_) => Err("deep check did not finish (an internal error stopped it)".into()),
                    }
                }
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

    fn fake_hunt() -> HuntFn {
        Arc::new(|admin: bool, progress: &dyn Fn(String)| {
            progress("  scheduledTasks  3 item(s)  0.1s".into());
            if admin {
                return Err("admin permission wasn't given (the Windows prompt was declined or timed out)".into());
            }
            let snap = |n: usize| json!({"admin": false, "started": "s", "sections": {"scheduledTasks": {"ok": true, "items": (0..n).map(|i| json!({"path": "\\", "name": format!("t{i}"), "hidden": i == 0})).collect::<Vec<_>>()}}});
            Ok((snap(3), Some(snap(2))))
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
        let w = Worker::start(fake(2), fake_hunt(), tx);
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
        let w = Worker::start(fake(0), fake_hunt(), tx);
        let (a, _) = w.enqueue("scan").unwrap();
        let (b, _) = w.enqueue("scan").unwrap();
        assert_eq!(a, b);
        wait_done(&w, a);
    }

    #[test]
    fn unknown_kind_is_refused() {
        let (tx, _rx) = channel();
        let w = Worker::start(fake(0), fake_hunt(), tx);
        assert!(w.enqueue("delete-everything").is_err());
    }

    #[test]
    fn deep_check_gives_summary_and_changes() {
        let (tx, _rx) = channel();
        let w = Worker::start(fake(0), fake_hunt(), tx);
        let (id, _) = w.enqueue("hunt").unwrap();
        let j = wait_done(&w, id);
        assert_eq!(j["state"], "done", "{j}");
        let h = &w.state()["latestHunt"];
        assert_eq!(h["summary"]["scheduledTasks"]["checked"], 3);
        assert_eq!(h["summary"]["scheduledTasks"]["notable"].as_array().unwrap().len(), 1, "the hidden task");
        assert_eq!(h["changes"]["sections"]["scheduledTasks"]["added"], json!([r"\t2"]));
    }

    #[test]
    fn declined_admin_prompt_is_a_clear_failure() {
        let (tx, _rx) = channel();
        let w = Worker::start(fake(0), fake_hunt(), tx);
        let (id, _) = w.enqueue("hunt-admin").unwrap();
        let j = wait_done(&w, id);
        assert_eq!(j["state"], "failed");
        assert!(j["message"].as_str().unwrap().contains("admin permission wasn't given"));
        assert!(w.state()["latestHunt"].is_null());
    }

    #[test]
    fn a_failing_or_panicking_scan_is_failed_not_clean() {
        let (tx, _rx) = channel();
        let w = Worker::start(Arc::new(|| Err("could not read services".into())), fake_hunt(), tx.clone());
        let (id, _) = w.enqueue("scan").unwrap();
        assert_eq!(wait_done(&w, id)["state"], "failed");
        assert!(w.state()["latestScan"].is_null(), "a failed scan must not look like a result");
        let w2 = Worker::start(Arc::new(|| panic!("boom")), fake_hunt(), tx);
        let (id2, _) = w2.enqueue("scan").unwrap();
        assert_eq!(wait_done(&w2, id2)["state"], "failed");
    }
}
