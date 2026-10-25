//! The case file and the six-step tracker.
//!
//! The case file is the same thirteen recovery steps guide-spec.mjs defines; the guide
//! records one when the person says it is done (update_case_step). The six-step tracker
//! is the website guide's list (site/public/index.html), each step fed by the case-file
//! steps and the facts Hideout already has. The person can also tick a step themselves.
//!
//! This build has no memory sealed to the PC yet (that is Phase 6), so both last until
//! Hideout closes, and they say so.

use crate::spec;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const KEPT: &str = "kept until Hideout closes (memory sealed to this PC arrives in a later build)";

pub struct TrackerStep {
    pub title: &'static str,
    pub text: &'static str,
    /// Case-file steps that are part of this one.
    pub parts: &'static [&'static str],
}

/// The website guide's six steps, in its words.
pub const TRACKER: [TrackerStep; 6] = [
    TrackerStep {
        title: "Stop the bleeding",
        text: "End the remote session, change passwords from a clean device, turn on two-step sign-in. Then let Windows Security clean up.",
        parts: &["disconnected_internet", "hung_up_on_caller", "removed_remote_access_tool", "changed_email_password", "changed_bank_passwords", "enabled_two_step", "windows_security_folder_scan", "windows_security_full_scan", "defender_offline_scan"],
    },
    TrackerStep { title: "List what they took", text: "Money sent, cards used, accounts touched, and the date it happened.", parts: &["checked_bank_activity"] },
    TrackerStep { title: "Call your bank", text: "On the number printed on your card - not a number from the caller. Say it was a scam.", parts: &["contacted_bank", "reported_fraud"] },
    TrackerStep { title: "Check for still-charging", text: "Any company charging again after you cancelled, with the cancel date and the charge date.", parts: &[] },
    TrackerStep { title: "Send the letters", text: "One at a time. Keep copies.", parts: &[] },
    TrackerStep { title: "Watch for the second scam", text: "Anyone offering to \"recover\" your money for a fee, a gift card or remote access is a scam. Only your bank, your card company or the official fraud-reporting service can help.", parts: &["contacted_professional"] },
];

/// What Hideout already knows that bears on the tracker (from the Money tab).
#[derive(Default, Clone)]
pub struct Facts {
    pub statements: usize,
    pub incident_date: Option<String>,
    pub still_charging: usize,
}

#[derive(Default)]
pub struct CaseFile {
    opened: Option<String>,
    steps: BTreeMap<String, (String, String)>,
    ticked: [bool; 6],
    pub letters_shown: usize,
}

impl CaseFile {
    /// Record one case-file step. `step` and `status` were validated against the spec.
    pub fn record(&mut self, step: &str, status: &str, now: &str) -> bool {
        if spec::case_step_label(step).is_none() || !spec::STEP_STATUS.contains(&status) {
            return false;
        }
        self.opened.get_or_insert_with(|| now.to_string());
        self.steps.insert(step.into(), (status.into(), now.into()));
        true
    }

    /// The person ticks (or unticks) a tracker step.
    pub fn tick(&mut self, i: usize, done: bool, now: &str) -> bool {
        if i >= TRACKER.len() {
            return false;
        }
        self.opened.get_or_insert_with(|| now.to_string());
        self.ticked[i] = done;
        true
    }

    /// The case file, shaped like brain.mjs's buildCaseFile (without scans: those live in
    /// the scan results this build reads directly).
    pub fn view(&self) -> Value {
        json!({
            "opened": self.opened,
            "kept": KEPT,
            "steps": spec::case_steps().iter().map(|(id, label)| {
                let s = self.steps.get(id);
                json!({"id": id, "label": label, "status": s.map(|x| x.0.as_str()).unwrap_or("not_yet"), "at": s.map(|x| x.1.clone())})
            }).collect::<Vec<_>>(),
        })
    }

    fn part_status(&self, id: &str) -> &str {
        self.steps.get(id).map(|x| x.0.as_str()).unwrap_or("not_yet")
    }

    /// The six steps with where each stands. "Not checked" is never shown as done.
    pub fn tracker(&self, f: &Facts) -> Vec<Value> {
        TRACKER
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let done_parts = t.parts.iter().filter(|p| self.part_status(p) == "done").count();
                let na_parts = t.parts.iter().filter(|p| self.part_status(p) == "not_applicable").count();
                let all = !t.parts.is_empty() && done_parts > 0 && done_parts + na_parts == t.parts.len();
                let (status, note): (&str, String) = if self.ticked[i] {
                    ("done", "You ticked this.".into())
                } else {
                    match i {
                        1 => {
                            let have = [f.incident_date.is_some(), f.statements > 0, self.part_status("checked_bank_activity") == "done"];
                            let n = have.iter().filter(|x| **x).count();
                            let mut missing = Vec::new();
                            if f.incident_date.is_none() {
                                missing.push("the day it happened (Money tab)");
                            }
                            if f.statements == 0 {
                                missing.push("a bank statement (Money tab)");
                            }
                            if n == 3 {
                                ("done", "Date set, statements imported, bank activity checked.".into())
                            } else if n > 0 {
                                ("in-progress", if missing.is_empty() { "Check your bank and card activity.".into() } else { format!("Still to add: {}.", missing.join(", ")) })
                            } else {
                                ("not-yet", String::new())
                            }
                        }
                        3 => {
                            if f.statements == 0 {
                                ("not-checked", "Import a statement in the Money tab and Hideout checks this for you.".into())
                            } else if f.still_charging > 0 {
                                ("found", format!("{} compan{} still charging after you cancelled - the strongest case for a refund.", f.still_charging, if f.still_charging == 1 { "y is" } else { "ies are" }))
                            } else {
                                ("checked", "None still charging in the statements you imported (only cancellations you recorded are checked).".into())
                            }
                        }
                        4 => {
                            if self.letters_shown > 0 {
                                ("in-progress", format!("{} letter{} written this session - you send them yourself.", self.letters_shown, if self.letters_shown == 1 { "" } else { "s" }))
                            } else {
                                ("not-yet", String::new())
                            }
                        }
                        5 => ("keep-watching", "This one never ends: keep saying no.".into()),
                        _ => {
                            if all {
                                ("done", format!("{done_parts} of {} done.", t.parts.len() - na_parts))
                            } else if done_parts > 0 {
                                ("in-progress", format!("{done_parts} of {} done.", t.parts.len() - na_parts))
                            } else {
                                ("not-yet", String::new())
                            }
                        }
                    }
                };
                json!({
                    "step": i, "title": t.title, "text": t.text, "status": status, "note": note,
                    "parts": t.parts.iter().map(|p| json!({"id": p, "label": spec::case_step_label(p), "status": self.part_status(p)})).collect::<Vec<_>>(),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_case_step_belongs_to_exactly_one_tracker_step() {
        for (id, _) in spec::case_steps() {
            let n = TRACKER.iter().filter(|t| t.parts.contains(&id.as_str())).count();
            assert_eq!(n, 1, "{id}");
        }
    }

    #[test]
    fn steps_move_and_never_claim_unchecked_as_done() {
        let mut c = CaseFile::default();
        let f = Facts::default();
        let t = c.tracker(&f);
        assert_eq!(t[3]["status"], "not-checked", "no statement = not checked, never clean");
        assert_eq!(t[0]["status"], "not-yet");
        assert!(c.record("changed_email_password", "done", "2026-10-24 10:00"));
        assert!(!c.record("constructor", "done", "x"));
        assert_eq!(c.tracker(&f)[0]["status"], "in-progress");
        for p in TRACKER[0].parts {
            c.record(p, "done", "t");
        }
        assert_eq!(c.tracker(&f)[0]["status"], "done");
        let f2 = Facts { statements: 1, incident_date: Some("2026-08-14".into()), still_charging: 1 };
        assert_eq!(c.tracker(&f2)[3]["status"], "found");
        assert_eq!(c.tracker(&f2)[1]["status"], "in-progress");
        assert!(c.tick(2, true, "t"));
        assert_eq!(c.tracker(&f2)[2]["status"], "done");
        assert!(!c.tick(9, true, "t"));
        assert_eq!(c.view()["steps"].as_array().unwrap().len(), 13);
    }
}
