//! The guide, wired into the app: the one door out (hideout-win's WinHTTP door), the
//! per-install pass for the gateway, who is on this PC (for the redactor), and this PC's
//! scans and jobs for the guide's tools. A port of the transport setup in main.mjs.
//!
//! How the guide reaches Claude:
//!   - gateway (the normal way): HIDEOUT_GATEWAY_URL, or the address this build was made
//!     with. The gateway holds the Claude key; this PC holds only a per-install pass.
//!   - direct (a developer's own PC): ANTHROPIC_API_KEY from the environment, held in
//!     memory only - never logged, written, or sent to the window.
//!   - neither: the offline guide (no network at all).

use crate::worker::Worker;
use hideout_guide::guide::Pc;
use hideout_guide::transport::{Direct, Gateway, TokenStore, Transport, Wire, WireFail};
use hideout_redact::{Identity, Redactor};
use hideout_win::https::{Door, Fail};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

pub struct DoorWire(Door);

impl Wire for DoorWire {
    fn host(&self) -> String {
        self.0.host().to_string()
    }
    fn post(&self, path: &str, headers: &[(&str, &str)], body: &[u8], sink: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), WireFail> {
        self.0.post(path, headers, body, sink).map_err(|f| match f {
            Fail::Refused(w) => WireFail::Refused(w),
            Fail::Network(w) => WireFail::Network(w),
            Fail::Timeout => WireFail::Timeout,
            Fail::Status(s, b) => WireFail::Status(s, b),
            Fail::TooLarge => WireFail::TooLarge,
        })
    }
}

/// %LOCALAPPDATA%\Hideout\install.json, {gateway, token}: the same file main.mjs keeps,
/// so the Rust and Node builds share one pass.
pub struct InstallFile {
    pub path: PathBuf,
    pub gateway: String,
}

impl TokenStore for InstallFile {
    fn load(&self) -> Option<String> {
        let v: Value = serde_json::from_slice(&std::fs::read(&self.path).ok()?).ok()?;
        (v["gateway"] == self.gateway.as_str()).then(|| v["token"].as_str().map(String::from)).flatten().filter(|t| !t.is_empty())
    }
    fn save(&self, token: &str) {
        let _ = std::fs::write(&self.path, json!({"gateway": self.gateway, "token": token}).to_string());
    }
    fn clear(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The gateway address: the environment first, then the one this build was made with
/// (rust/build-release.ps1 reads it from the git-ignored app/gateway-url.txt). Never a key.
pub fn gateway_url() -> Option<String> {
    std::env::var("HIDEOUT_GATEWAY_URL").ok().filter(|u| !u.trim().is_empty()).or_else(|| option_env!("HIDEOUT_GATEWAY_URL").map(String::from)).map(|u| u.trim().to_string())
}

const AGENT: &str = concat!("Hideout/", env!("CARGO_PKG_VERSION"));

pub fn make_transport(data_dir: &std::path::Path, log: &dyn Fn(&str)) -> Option<Box<dyn Transport>> {
    if let Some(gw) = gateway_url() {
        return match Door::open(&gw, AGENT) {
            Ok(door) => Some(Box::new(Gateway::new(Box::new(DoorWire(door)), Box::new(InstallFile { path: data_dir.join("install.json"), gateway: gw })))),
            Err(e) => {
                log(&format!("guide: the gateway address was refused ({e}); using the offline guide"));
                None
            }
        };
    }
    let key = std::env::var("ANTHROPIC_API_KEY").ok().filter(|k| !k.trim().is_empty())?;
    match Door::open("https://api.anthropic.com", AGENT) {
        Ok(door) => Some(Box::new(Direct::new(Box::new(DoorWire(door)), key.trim().to_string()))),
        Err(e) => {
            log(&format!("guide: direct mode unavailable ({e})"));
            None
        }
    }
}

/// The redactor for this PC: its accounts, profile folders, display name and PC name;
/// the companies' published cancellation addresses may stay.
pub fn redactor() -> Redactor {
    let who = hideout_win::identity::collect();
    let allowed = hideout_money::directory::shipped().iter().filter_map(|m| m.cancel_by_email.clone()).filter(|e| !e.is_empty()).collect();
    Redactor::new(&Identity { names: who.names, computer: who.computer, allowed_emails: allowed })
}

/// This PC, for the guide's tools.
pub struct AppPc {
    pub worker: Worker,
    pub leaks: Mutex<Option<Vec<Value>>>,
}

impl AppPc {
    pub fn new(worker: Worker) -> AppPc {
        AppPc { worker, leaks: Mutex::new(None) }
    }

    /// Run the leak look-up now (read-only) and keep what it found for the checks.
    pub fn look_for_leaks(&self) {
        let r = hideout_scan::leaks::look(&hideout_scan::leaks::default_folders());
        let v: Vec<Value> = r.leaks.iter().filter_map(|l| serde_json::to_value(l).ok()).collect();
        *self.leaks.lock().unwrap_or_else(|p| p.into_inner()) = Some(v);
    }
}

impl Pc for AppPc {
    fn latest_scan(&self) -> Option<(Value, i64)> {
        self.worker.latest_scan()
    }
    fn scan_running(&self) -> bool {
        self.worker.running("scan")
    }
    fn run_job(&self, kind: &str, wait: Duration) -> Result<(), String> {
        let (id, _) = self.worker.enqueue(kind)?;
        self.worker.wait(id, wait)
    }
    fn latest_hunt(&self) -> Option<(Value, i64)> {
        self.worker.latest_hunt()
    }
    fn leaks(&self) -> Option<Vec<Value>> {
        self.leaks.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
    fn changed(&self) {
        self.worker.notify_state();
    }
    fn now(&self) -> String {
        hideout_win::time::now_local().sortable()
    }
}
