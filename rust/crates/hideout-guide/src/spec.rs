//! The ONE definition of the Hideout Guide: model, instructions, tools - a port of
//! app/src/guide-spec.mjs. The cloud gateway enforces the same spec server-side (a client
//! sends only the conversation), so the instructions and tools here matter only in direct
//! mode, where they must be byte-identical to the gateway's for the same prompt cache.
//! tests/spec.rs holds this file to the JavaScript spec exactly.

use hideout_money::js;
use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

pub const MODEL: &str = "claude-opus-5";
pub const EFFORT: &str = "medium";
pub const MAX_TOKENS: u64 = 16000;
pub const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
pub const SYSTEM_PROMPT: &str = include_str!("spec/system-prompt.txt");
pub const STEP_STATUS: [&str; 3] = ["done", "not_yet", "not_applicable"];
pub const LETTER_KINDS: [&str; 3] = ["refund_request", "cancel_by_email", "bank_dispute"];

/// The tool definitions, as guide-spec.mjs's TOOLS (with eager_input_streaming).
pub fn tools() -> &'static Value {
    static T: OnceLock<Value> = OnceLock::new();
    T.get_or_init(|| serde_json::from_str(include_str!("spec/tools.json")).expect("tools.json"))
}

/// The recovery steps the case file tracks, in order: (id, label).
pub fn case_steps() -> &'static [(String, String)] {
    static S: OnceLock<Vec<(String, String)>> = OnceLock::new();
    S.get_or_init(|| {
        let v: serde_json::Map<String, Value> = serde_json::from_str(include_str!("spec/case-steps.json")).expect("case-steps.json");
        v.into_iter().map(|(k, l)| (k, l.as_str().unwrap_or("").to_string())).collect()
    })
}

pub fn case_step_label(id: &str) -> Option<&'static str> {
    case_steps().iter().find(|(k, _)| k == id).map(|(_, l)| l.as_str())
}

pub fn guide_tools() -> Vec<&'static str> {
    tools().as_array().map(|a| a.iter().filter_map(|t| t["name"].as_str()).collect()).unwrap_or_default()
}

/// Strings the guide's own vocabulary uses as values (tool names, step ids, statuses,
/// letter kinds). The redactor leaves exactly these alone.
pub fn vocabulary() -> Vec<String> {
    let mut v: Vec<String> = guide_tools().into_iter().map(String::from).collect();
    v.extend(case_steps().iter().map(|(k, _)| k.clone()));
    v.extend(STEP_STATUS.iter().chain(LETTER_KINDS.iter()).map(|s| s.to_string()));
    v
}

fn iso(s: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$").expect("valid")).is_match(s)
}

fn merchant_id(s: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z0-9 :._-]{1,64}$").expect("valid")).is_match(s)
}

/// Hand validation (tiny schemas), as guide-spec.mjs's validateToolInput: the streaming
/// parser can return a truncated object, and model output is untrusted either way.
/// None = valid, else the reason.
pub fn validate_tool_input(name: &str, input: &Value) -> Option<&'static str> {
    if !guide_tools().contains(&name) {
        return Some("unknown tool");
    }
    let Some(o) = input.as_object() else { return Some("input must be an object") };
    let only = |allowed: &[&str]| o.keys().any(|k| !allowed.contains(&k.as_str()));
    let s = |k: &str| o.get(k).and_then(Value::as_str);
    match name {
        "start_deep_check" => {
            if !o.get("with_admin").map(Value::is_boolean).unwrap_or(false) {
                return Some("with_admin must be true or false");
            }
            if only(&["with_admin"]) {
                return Some("unexpected field");
            }
        }
        "update_case_step" => {
            // Object.hasOwn(CASE_STEPS, step): a key of the list, never "constructor".
            let step = match o.get("step") {
                Some(Value::String(x)) => Some(x.clone()),
                Some(Value::Number(n)) => Some(n.to_string()),
                Some(Value::Bool(b)) => Some(b.to_string()),
                Some(Value::Null) => Some("null".into()),
                None => Some("undefined".into()),
                _ => None,
            };
            if !step.map(|x| case_step_label(&x).is_some()).unwrap_or(false) {
                return Some("unknown step");
            }
            if !s("status").map(|x| STEP_STATUS.contains(&x)).unwrap_or(false) {
                return Some("unknown status");
            }
            if only(&["step", "status"]) {
                return Some("unexpected field");
            }
        }
        "set_incident_date" => {
            if !s("date").map(iso).unwrap_or(false) {
                return Some("date must be YYYY-MM-DD");
            }
            if only(&["date"]) {
                return Some("unexpected field");
            }
        }
        "mark_canceled" => {
            if !s("merchant").map(merchant_id).unwrap_or(false) {
                return Some("merchant must be an id from get_money_summary");
            }
            if !s("canceled_on").map(iso).unwrap_or(false) {
                return Some("canceled_on must be YYYY-MM-DD");
            }
            if only(&["merchant", "canceled_on"]) {
                return Some("unexpected field");
            }
        }
        "show_cancel_steps" => {
            if !s("merchant").map(merchant_id).unwrap_or(false) {
                return Some("merchant must be an id from get_money_summary");
            }
            if only(&["merchant"]) {
                return Some("unexpected field");
            }
        }
        "offer_letter" => {
            if !s("kind").map(|k| LETTER_KINDS.contains(&k)).unwrap_or(false) {
                return Some("unknown letter kind");
            }
            if o.contains_key("merchant") && !s("merchant").map(merchant_id).unwrap_or(false) {
                return Some("merchant must be an id from get_money_summary");
            }
            let len_ok = |k: &str, max: usize| s(k).map(|x| !js::trim(x).is_empty() && x.encode_utf16().count() <= max).unwrap_or(false);
            if !len_ok("subject", 200) {
                return Some("subject must be 1-200 characters");
            }
            if !len_ok("body", 8000) {
                return Some("body must be 1-8000 characters");
            }
            if only(&["kind", "merchant", "subject", "body"]) {
                return Some("unexpected field");
            }
        }
        _ => {
            if !o.is_empty() {
                return Some("this tool takes no input");
            }
        }
    }
    None
}

/// The exact request the guide makes, minus the conversation (guide-spec.mjs's
/// requestParams). `betas` becomes the anthropic-beta header in direct mode.
pub fn request_params(messages: Value) -> Value {
    json!({
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "betas": [FALLBACK_BETA],
        "fallbacks": "default",
        "output_config": {"effort": EFFORT},
        "cache_control": {"type": "ephemeral"},
        "system": [{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
        "tools": tools(),
        "messages": messages,
    })
}
