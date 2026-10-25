//! The Hideout Guide's conversation loop - a port of app/src/guide.mjs.
//!
//! Tools can read results, start read-only checks, keep the case file, and put cancel
//! steps and drafted letters in front of the person as cards. None can change the PC,
//! log in anywhere, or send anything. Everything the model sees is redacted, by type
//! (crate::wire) and by a last check before it leaves.
//!
//! Beyond guide.mjs:
//!   - the first message of every conversation says, in plain words, that this is an AI
//!     and can be wrong (from code, not left to the model)
//!   - talk of "recovering" money gets the second-scam warning, from code
//!   - with no transport, or no network, the offline guide answers instead (tracker,
//!     letters, checklists), with no network at all

use crate::case::{CaseFile, Facts};
use crate::checks::{self, Check};
use crate::letters::{self, Typed};
use crate::offline;
use crate::spec;
use crate::transport::{Transport, TurnError};
use crate::wire::{ModelBlock, Outbound, ToolResult, Turn};
use hideout_money::money::Money;
use hideout_redact::Redactor;
use regex::Regex;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

pub const MAX_TOOL_ROUNDS: usize = 6;

pub const AI_NOTICE: &str = "*I'm an AI guide, powered by Claude, and I can be wrong. Check anything important with your bank or a trusted IT professional - and never share a password or a code with anyone, me included.*\n\n";
pub const SECOND_SCAM: &str = "**Watch for the second scam:** anyone who offers to get your money back for a fee, a gift card, crypto or remote access is a scammer too. Only your bank, your card company or the official fraud-reporting service can help.\n\n";

/// What the guide can ask of this PC. The app implements it over the worker.
pub trait Pc: Send + Sync {
    /// The latest quick scan and how many minutes ago it ran.
    fn latest_scan(&self) -> Option<(Value, i64)>;
    fn scan_running(&self) -> bool;
    /// Queue a job (or join the one of that kind already running) and wait for it.
    fn run_job(&self, kind: &str, wait: Duration) -> Result<(), String>;
    /// The latest deep check ({at, admin, summary, changes}) and its age in minutes.
    fn latest_hunt(&self) -> Option<(Value, i64)>;
    /// The last leak look-up, if one ran.
    fn leaks(&self) -> Option<Vec<Value>>;
    /// Something the window shows changed (Money, the case file).
    fn changed(&self);
    /// Local time, "YYYY-MM-DD HH:MM:SS".
    fn now(&self) -> String;
}

pub type Emit<'a> = &'a mut dyn FnMut(Value);

pub struct Guide {
    transport: Option<Box<dyn Transport>>,
    redactor: Redactor,
    pc: Arc<dyn Pc>,
    money: Arc<Mutex<Money>>,
    case: Mutex<CaseFile>,
    messages: Mutex<Vec<Turn>>,
    busy: AtomicBool,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

fn second_scam_talk(text: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)(?-u:\b)(recover(y|ing)?|get (my|the|our|it|that) (money )?back|refund (company|service|agent|fee)|for a fee|fund recovery|asset recovery|chargeback (company|service|expert)|they can get it back|money back)(?-u:\b)").expect("valid")
    })
    .is_match(text)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Guide {
    pub fn new(transport: Option<Box<dyn Transport>>, redactor: Redactor, pc: Arc<dyn Pc>, money: Arc<Mutex<Money>>, log: Arc<dyn Fn(&str) + Send + Sync>) -> Guide {
        Guide { transport, redactor: redactor.with_vocabulary(spec::vocabulary()), pc, money, case: Mutex::new(CaseFile::default()), messages: Mutex::new(Vec::new()), busy: AtomicBool::new(false), log }
    }

    /// "gateway", "direct" or "offline".
    pub fn mode(&self) -> &'static str {
        self.transport.as_ref().map(|t| t.kind()).unwrap_or("offline")
    }

    /// Is an AI connected (gateway or direct)?
    pub fn ai(&self) -> bool {
        self.transport.is_some()
    }

    pub fn busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        if !self.busy() {
            lock(&self.messages).clear();
        }
    }

    /// How many turns the conversation holds (tests and the window).
    pub fn turns(&self) -> usize {
        lock(&self.messages).len()
    }

    fn facts(&self) -> Facts {
        let m = lock(&self.money);
        let s = m.summary();
        Facts { statements: m.statement_count(), incident_date: m.incident_date().map(String::from), still_charging: s.still_charging }
    }

    pub fn tracker(&self) -> Vec<Value> {
        let f = self.facts();
        lock(&self.case).tracker(&f)
    }

    pub fn tick(&self, step: usize, done: bool) -> bool {
        let ok = lock(&self.case).tick(step, done, &self.pc.now());
        if ok {
            self.pc.changed();
        }
        ok
    }

    pub fn case_file(&self) -> Value {
        lock(&self.case).view()
    }

    /// The deeper checks, from what Hideout has right now.
    pub fn deeper_checks(&self) -> Vec<Check> {
        let scan = self.pc.latest_scan().map(|x| x.0);
        let hunt = self.pc.latest_hunt().map(|x| x.0);
        let leaks = self.pc.leaks();
        let m = lock(&self.money);
        let installed = m.installed.clone();
        let incident = m.incident_date().map(String::from);
        let test_charges = m.test_charges();
        drop(m);
        checks::run(&checks::Input { incident: incident.as_deref(), scan: scan.as_ref(), hunt: hunt.as_ref(), installed: installed.as_deref(), test_charges, leaks: leaks.as_deref() })
    }

    /// A letter card from the letter builder (no AI): a repeating charge by id, or the
    /// company, amount and date the person typed.
    pub fn letter(&self, kind: &str, merchant: Option<&str>, typed: &Typed) -> Value {
        let m = lock(&self.money);
        let s = m.summary();
        let rec = merchant.and_then(|id| s.recurring.iter().find(|r| r.merchant == id));
        let email = merchant.and_then(|id| m.cancel_info(id)).and_then(|i| i["cancelByEmail"].as_str().map(String::from));
        drop(m);
        let card = letters::build(kind, rec, email.as_deref(), typed);
        lock(&self.case).letters_shown += 1;
        self.pc.changed();
        card
    }

    /// One conversational turn. `emit` streams {type: text|tool|pause|card|error|done}.
    pub fn chat(&self, user_text: &str, emit: Emit) {
        if self.busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            emit(json!({"type": "error", "message": "The guide is still answering - one moment."}));
            return;
        }
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.chat_inner(user_text, emit)));
        if r.is_err() {
            (self.log)("guide turn panicked");
            lock(&self.messages).clear();
        }
        self.busy.store(false, Ordering::SeqCst);
    }

    fn chat_inner(&self, user_text: &str, emit: Emit) {
        let mut messages = lock(&self.messages).clone();
        let new_conversation = messages.is_empty();
        let Some(transport) = self.transport.as_ref() else {
            emit(json!({"type": "text", "delta": offline::NOTICE}));
            if second_scam_talk(user_text) {
                emit(json!({"type": "text", "delta": SECOND_SCAM}));
            }
            self.offline_answer(user_text, emit);
            emit(json!({"type": "done"}));
            return;
        };
        if new_conversation {
            emit(json!({"type": "text", "delta": AI_NOTICE}));
        }
        if second_scam_talk(user_text) {
            emit(json!({"type": "text", "delta": SECOND_SCAM}));
        }
        let mark = messages.len();
        let words: String = user_text.chars().take(4000).collect();
        messages.push(Turn::Said(self.redactor.text(&words)));
        let mut json_retries = 0;
        let mut round = 0;
        let outcome: Result<(), TurnError> = loop {
            if round > MAX_TOOL_ROUNDS {
                break Ok(());
            }
            let out = match Outbound::seal(&messages, &self.redactor) {
                Ok(o) => o,
                Err(leak) => {
                    // Never sent. The conversation starts over so it cannot get stuck.
                    (self.log)(&format!("guide request refused by the last check ({leak:?}); conversation reset"));
                    lock(&self.messages).clear();
                    emit(json!({"type": "error", "message": "I stopped before sending something that looked personal, and started a fresh conversation to keep your details private. Please ask again."}));
                    return;
                }
            };
            let msg = match transport.turn(&out, &mut |delta| emit(json!({"type": "text", "delta": delta}))) {
                Ok(m) => {
                    json_retries = 0;
                    m
                }
                // An answer that could not be read at all: ask again (guide.mjs does the same).
                Err(TurnError::Protocol(_)) if json_retries < 2 => {
                    json_retries += 1;
                    continue;
                }
                Err(e) => break Err(e),
            };
            // Token counts only, never content - proves the prompt cache is actually hit.
            let u = &msg.usage;
            (self.log)(&format!(
                "guide usage model={} stop={} in={} cache_read={} cache_write={} out={}",
                msg.model,
                msg.stop_reason,
                u["input_tokens"].as_u64().unwrap_or(0),
                u["cache_read_input_tokens"].as_u64().unwrap_or(0),
                u["cache_creation_input_tokens"].as_u64().unwrap_or(0),
                u["output_tokens"].as_u64().unwrap_or(0)
            ));
            let blocks: Vec<ModelBlock> = msg.content.iter().cloned().map(ModelBlock::from_model).collect();
            if msg.stop_reason == "refusal" {
                messages.push(Turn::Model(blocks));
                emit(json!({"type": "text", "delta": "\n\nI can't help with that one. If you're dealing with an attack right now, disconnect from the internet and contact your bank or a trusted IT professional."}));
                break Ok(());
            }
            let uses: Vec<_> = blocks.iter().filter_map(|b| b.tool_use().map(|(id, name, input)| (id, name.to_string(), input.clone()))).collect();
            messages.push(Turn::Model(blocks));
            if msg.stop_reason != "tool_use" || uses.is_empty() {
                break Ok(());
            }
            if round == MAX_TOOL_ROUNDS {
                // guide.mjs stopped here with the tool calls unanswered, which leaves the
                // history ending on a tool call the next request cannot follow. Answer them.
                messages.push(Turn::Results(uses.into_iter().map(|(id, _, _)| ToolResult { id, content: self.redactor.text("Not run: the guide stopped here to check in with the person."), is_error: true }).collect()));
                emit(json!({"type": "text", "delta": "\n\n(I've looked at a lot - let me stop here. Ask me to continue if you need more.)"}));
                break Ok(());
            }
            let mut results = Vec::new();
            for (id, name, input) in uses {
                if let Some(bad) = spec::validate_tool_input(&name, &input) {
                    results.push(ToolResult { id, content: self.redactor.text(bad), is_error: true });
                    continue;
                }
                let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.run_tool(&name, &input, emit))).unwrap_or_else(|_| json!({"error": "that tool stopped unexpectedly"}));
                results.push(ToolResult { id, content: self.redactor.json(&out), is_error: false });
            }
            messages.push(Turn::Results(results));
            emit(json!({"type": "pause"})); // text before and after a tool call are separate paragraphs
            round += 1;
        };
        match outcome {
            Ok(()) => {
                *lock(&self.messages) = messages;
                emit(json!({"type": "done"}));
            }
            Err(e) => {
                // A failed turn is dropped whole (only the tail - earlier turns are never
                // edited), so the history never ends on an unanswered question.
                messages.truncate(mark);
                *lock(&self.messages) = messages;
                match e {
                    TurnError::Network(_) => {
                        // No internet: the offline guide still helps.
                        emit(json!({"type": "text", "delta": "\n\n**I can't reach the AI guide right now** - check the internet connection. Here is what Hideout can do on this PC without it:\n\n"}));
                        self.offline_answer(user_text, emit);
                        emit(json!({"type": "done"}));
                    }
                    other => emit(json!({"type": "error", "message": error_message(&other)})),
                }
            }
        }
    }

    fn offline_answer(&self, text: &str, emit: Emit) {
        // Each value on its own line: a lock guard in a struct literal would live to the
        // end of the statement, and deeper_checks() takes the same lock.
        let tracker = self.tracker();
        let money = lock(&self.money).guide_view();
        let checks = self.deeper_checks();
        let a = offline::answer(text, &offline::Context { tracker, money, scan: self.pc.latest_scan().map(|x| x.0), checks });
        emit(json!({"type": "text", "delta": a.text}));
        if let Some((kind, merchant)) = a.letter {
            let card = self.letter(&kind, merchant.as_deref(), &Typed::default());
            emit(json!({"type": "card", "card": card}));
        }
    }

    fn scan_view(&self) -> Value {
        match self.pc.latest_scan() {
            None => json!({"scan": null}),
            Some((s, age)) => json!({"scan": {"minutesAgo": age, "checked": s["checked"], "antivirus": s["defender"], "ranAsAdmin": s["admin"], "findings": s["findings"].as_array().cloned().unwrap_or_default()}}),
        }
    }

    fn run_tool(&self, name: &str, input: &Value, emit: Emit) -> Value {
        let st = |k: &str| input[k].as_str().unwrap_or("").to_string();
        match name {
            "get_scan_results" => {
                // A scan already under way is waited for, never reported as "no scan yet"
                // - that would be a false statement about the PC.
                if self.pc.latest_scan().is_none() && self.pc.scan_running() {
                    emit(json!({"type": "tool", "name": name, "status": "Waiting for the scan that's running..."}));
                    let _ = self.pc.run_job("scan", Duration::from_secs(90));
                }
                self.scan_view()
            }
            "run_quick_scan" => {
                emit(json!({"type": "tool", "name": name, "status": "Running a quick scan..."}));
                match self.pc.run_job("scan", Duration::from_secs(600)) {
                    Ok(()) => self.scan_view(),
                    Err(e) => json!({"error": e}),
                }
            }
            "start_deep_check" => {
                let admin = input["with_admin"].as_bool().unwrap_or(false);
                emit(json!({"type": "tool", "name": name, "status": if admin { "Deep check started - click Yes on the Windows prompt..." } else { "Deep check started (2-3 minutes)..." }}));
                match self.pc.run_job(if admin { "hunt-admin" } else { "hunt" }, Duration::from_secs(25 * 60)) {
                    Ok(()) => json!({"deepCheck": self.pc.latest_hunt().map(|h| h.0["summary"].clone())}),
                    Err(e) => json!({"error": e}),
                }
            }
            "get_deep_check_summary" => match self.pc.latest_hunt() {
                None => json!({"deepCheck": null, "deeperChecks": checks::guide_view(&self.deeper_checks())}),
                Some((h, age)) => {
                    let mut v = json!({"minutesAgo": age, "withAdmin": h["admin"]});
                    if let (Value::Object(a), Some(b)) = (&mut v, h["summary"].as_object()) {
                        a.extend(b.clone());
                    }
                    json!({"deepCheck": v, "deeperChecks": checks::guide_view(&self.deeper_checks())})
                }
            },
            "get_case_file" => json!({"caseFile": self.case_file(), "note": "Hideout's memory isn't sealed to this PC in this build, so this case file lasts until Hideout closes."}),
            "update_case_step" => {
                let (step, status) = (st("step"), st("status"));
                let label = spec::case_step_label(&step).unwrap_or("");
                emit(json!({"type": "tool", "name": name, "status": format!("Case file: {label} - {}", status.replacen('_', " ", 1))}));
                let ok = lock(&self.case).record(&step, &status, &self.pc.now());
                self.pc.changed();
                if ok { json!({"saved": false, "kept": crate::case::KEPT, "caseFile": self.case_file()}) } else { json!({"error": "couldn't record that step"}) }
            }
            "get_money_summary" => {
                let m = lock(&self.money);
                let mut v = m.guide_view();
                v["testCharges"] = json!(m.test_charges());
                json!({"money": v})
            }
            "set_incident_date" => {
                let d = st("date");
                let r = lock(&self.money).set_incident(&d);
                if r["ok"] != true {
                    return json!({"error": r["error"]});
                }
                self.pc.changed();
                emit(json!({"type": "tool", "name": name, "status": format!("Money: things went wrong on {d}")}));
                json!({"saved": r["saved"], "sinceIncident": lock(&self.money).guide_view()["sinceIncident"]})
            }
            "mark_canceled" => {
                let (merchant, on) = (st("merchant"), st("canceled_on"));
                let r = lock(&self.money).mark_canceled(&merchant, &on);
                if r["ok"] != true {
                    return json!({"error": r["error"]});
                }
                self.pc.changed();
                emit(json!({"type": "tool", "name": name, "status": format!("Money: cancelled on {on} - Hideout will watch for any later charge")}));
                let company = lock(&self.money).guide_view()["repeating"].as_array().and_then(|a| a.iter().find(|x| x["merchant"] == merchant.as_str()).cloned()).unwrap_or(Value::Null);
                json!({"saved": r["saved"], "company": company})
            }
            "show_cancel_steps" => {
                let Some(info) = lock(&self.money).cancel_info(&st("merchant")) else {
                    return json!({"error": "That company isn't in the repeating charges - read get_money_summary for the ids."});
                };
                let mut card = json!({"type": "cancel"});
                if let (Value::Object(c), Value::Object(i)) = (&mut card, info.clone()) {
                    c.extend(i);
                }
                emit(json!({"type": "card", "card": card}));
                let mut out = json!({"shown": true});
                if let (Value::Object(o), Value::Object(i)) = (&mut out, info) {
                    o.extend(i);
                }
                out
            }
            "offer_letter" => {
                let merchant = input.get("merchant").and_then(Value::as_str).map(String::from);
                let info = merchant.as_deref().and_then(|m| lock(&self.money).cancel_info(m));
                if merchant.is_some() && info.is_none() {
                    return json!({"error": "That company isn't in the repeating charges - read get_money_summary for the ids."});
                }
                // Only the directory supplies an address, and only for a company that
                // officially takes cancellations by email. The model never picks where a
                // letter goes.
                let kind = st("kind");
                let to = if kind == "cancel_by_email" { info.as_ref().and_then(|i| i["cancelByEmail"].as_str().map(String::from)) } else { None };
                emit(json!({"type": "card", "card": {"type": "letter", "kind": kind, "merchant": merchant, "name": info.as_ref().map(|i| i["name"].clone()), "to": to, "subject": st("subject"), "body": st("body")}}));
                lock(&self.case).letters_shown += 1;
                self.pc.changed();
                json!({"shown": true, "to": to, "note": "The person reviews and sends it themselves."})
            }
            _ => json!({"error": "unknown tool"}),
        }
    }
}

/// guide.mjs's plain words for a failed turn.
pub fn error_message(e: &TurnError) -> String {
    match e {
        TurnError::Status(429, _) | TurnError::Status(529, _) => "The guide is busy (or resting for today) - try again later.".into(),
        TurnError::Status(401, _) | TurnError::Status(403, _) => "The guide couldn't sign in.".into(),
        TurnError::Network(_) => "Couldn't reach the guide - check the internet connection.".into(),
        TurnError::Status(s, _) => format!("The guide ran into a problem ({s})."),
        TurnError::Protocol(_) | TurnError::Refused(_) => "The guide ran into a problem.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_talk_is_spotted() {
        for t in ["A company says they can recover my money for a fee", "can you get my money back", "someone from a fund recovery service called", "Recovery agents emailed me"] {
            assert!(second_scam_talk(t), "{t}");
        }
        for t in ["am I hacked?", "check my bank charges", "write a refund letter to adobe"] {
            assert!(!second_scam_talk(t), "{t}");
        }
    }
}
