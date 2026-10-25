//! The Rust guide's spec against app/src/guide-spec.mjs itself: spec-golden.json is
//! written by `node rust/tools/guide-golden.mjs spec`. The request must be identical (the
//! gateway and direct mode share one prompt cache), and every validation answer the same.

use hideout_guide::spec;
use serde_json::{json, Value};

fn golden() -> Value {
    serde_json::from_str(include_str!("spec-golden.json")).unwrap()
}

#[test]
fn constants_and_lists_match() {
    let g = golden();
    assert_eq!(g["MODEL"], spec::MODEL);
    assert_eq!(g["EFFORT"], spec::EFFORT);
    assert_eq!(g["MAX_TOKENS"], spec::MAX_TOKENS);
    assert_eq!(g["FALLBACK_BETA"], spec::FALLBACK_BETA);
    assert_eq!(g["STEP_STATUS"], json!(spec::STEP_STATUS));
    assert_eq!(g["LETTER_KINDS"], json!(spec::LETTER_KINDS));
    assert_eq!(g["GUIDE_TOOLS"], json!(spec::guide_tools()));
    let steps: Vec<(String, String)> = g["CASE_STEPS"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect();
    assert_eq!(steps, spec::case_steps().to_vec(), "same steps, same order");
}

#[test]
fn the_request_is_byte_identical() {
    let g = golden();
    let mine = spec::request_params(json!([{"role": "user", "content": "am I hacked?"}]));
    assert_eq!(mine.to_string(), g["requestParams"].to_string());
}

#[test]
fn every_validation_answer_matches() {
    let g = golden();
    let cases = g["validate"].as_array().unwrap();
    assert!(cases.len() > 100);
    let mut diffs = Vec::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let want = c["result"].as_str();
        let got = spec::validate_tool_input(name, &c["input"]);
        if got != want {
            diffs.push(format!("{name} {}: js {want:?} rust {got:?}", c["input"]));
        }
    }
    assert!(diffs.is_empty(), "{}", diffs.join("\n"));
}

/// guide-spec.mjs's fences F5/F6, on the prompt this build actually sends.
#[test]
fn the_prompt_keeps_its_promises() {
    let p = spec::SYSTEM_PROMPT;
    assert!(p.contains("never logs into accounts, cancels anything, or sends email"));
    assert!(p.contains("Never state a fact the person hasn't told you and Hideout doesn't show") && p.contains("[Confirm: "));
    assert!(p.contains("You are an AI, not a human technician") && p.contains("You can be wrong"));
    assert!(p.contains("not checked is not the same as clean"));
}

/// Negative control: the comparison notices a one-character change.
#[test]
fn the_comparison_is_not_vacuous() {
    let g = golden();
    let mut mine = spec::request_params(json!([{"role": "user", "content": "am I hacked?"}]));
    mine["system"][0]["text"] = json!(format!("{} ", spec::SYSTEM_PROMPT));
    assert_ne!(mine.to_string(), g["requestParams"].to_string());
}
