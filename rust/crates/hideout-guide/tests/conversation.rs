//! The guide's conversation, against a scripted transport and a fake gateway: the
//! JavaScript selftests G1-G15 (app/tests/selftest.mjs), the Money guide tests G1-G9 and
//! E1 (app/tests/money.selftest.mjs), and what Phase 5 adds - the AI notice, the
//! second-scam warning, the offline guide, the last check before sending, and the exact
//! bytes that leave the PC.

use hideout_guide::guide::{Guide, Pc, AI_NOTICE, SECOND_SCAM};
use hideout_guide::transport::{Final, Gateway, TokenStore, Transport, TurnError, Wire, WireFail};
use hideout_guide::wire::Outbound;
use hideout_money::directory::{prepare, Merchant};
use hideout_money::money::Money;
use hideout_redact::{Identity, Redactor};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------- fakes

#[derive(Default)]
struct FakePc {
    scan: Mutex<Option<Value>>,
    running: AtomicBool,
    /// When a running scan finishes, this becomes the latest scan.
    pending: Mutex<Option<Value>>,
    hunt: Mutex<Option<Value>>,
    jobs: Mutex<Vec<String>>,
    changed: AtomicUsize,
}

impl Pc for FakePc {
    fn latest_scan(&self) -> Option<(Value, i64)> {
        self.scan.lock().unwrap().clone().map(|s| (s, 3))
    }
    fn scan_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
    fn run_job(&self, kind: &str, _wait: Duration) -> Result<(), String> {
        self.jobs.lock().unwrap().push(kind.into());
        if self.running.swap(false, Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(50));
            *self.scan.lock().unwrap() = self.pending.lock().unwrap().take();
        }
        Ok(())
    }
    fn latest_hunt(&self) -> Option<(Value, i64)> {
        self.hunt.lock().unwrap().clone().map(|h| (h, 12))
    }
    fn leaks(&self) -> Option<Vec<Value>> {
        None
    }
    fn changed(&self) {
        self.changed.fetch_add(1, Ordering::SeqCst);
    }
    fn now(&self) -> String {
        "2026-10-01 12:00:00".into()
    }
}

/// A scripted model: each turn returns the next step, and records what it was sent.
struct Script {
    steps: Mutex<Vec<Result<Value, TurnError>>>,
    calls: Arc<Mutex<Vec<Value>>>,
}

fn script(steps: Vec<Result<Value, TurnError>>) -> (Box<dyn Transport>, Arc<Mutex<Vec<Value>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    (Box::new(Script { steps: Mutex::new(steps), calls: calls.clone() }), calls)
}

impl Transport for Script {
    fn kind(&self) -> &'static str {
        "direct"
    }
    fn turn(&self, out: &Outbound, on_text: &mut dyn FnMut(&str)) -> Result<Final, TurnError> {
        self.calls.lock().unwrap().push(out.messages().clone());
        let step = self.steps.lock().unwrap().remove(0)?;
        for b in step["content"].as_array().unwrap() {
            if b["type"] == "text" {
                on_text(b["text"].as_str().unwrap());
            }
        }
        Final::from_json(&step)
    }
}

fn reply(stop: &str, content: Value) -> Result<Value, TurnError> {
    Ok(json!({"stop_reason": stop, "content": content, "model": "claude-opus-5", "usage": {"input_tokens": 5, "output_tokens": 5}}))
}

fn tool(id: &str, name: &str, input: Value) -> Value {
    json!({"type": "tool_use", "id": id, "name": name, "input": input})
}

fn text(t: &str) -> Value {
    json!({"type": "text", "text": t})
}

fn red() -> Redactor {
    Redactor::new(&Identity { names: vec!["jdoe".into()], computer: "HOME-PC".into(), allowed_emails: vec!["cancel@mailco.com".into()] })
}

fn fixture(f: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../hideout-money/tests/fixtures").join(f)).unwrap()
}

fn money() -> Arc<Mutex<Money>> {
    let dir: Vec<Merchant> = serde_json::from_str(&fixture("dir.json")).unwrap();
    Arc::new(Mutex::new(Money::new(Some(prepare(dir)), Box::new(|| "2026-10-01".to_string()))))
}

fn guide(t: Option<Box<dyn Transport>>, pc: Arc<FakePc>, m: Arc<Mutex<Money>>) -> Guide {
    Guide::new(t, red(), pc, m, Arc::new(|_| {}))
}

fn chat(g: &Guide, msg: &str) -> Vec<Value> {
    let mut ev = Vec::new();
    g.chat(msg, &mut |e| ev.push(e));
    ev
}

fn texts(ev: &[Value]) -> String {
    ev.iter().filter(|e| e["type"] == "text").map(|e| e["delta"].as_str().unwrap()).collect()
}

/// The content of the last tool_result message in a recorded request.
fn last_results(call: &Value) -> Vec<Value> {
    call.as_array().unwrap().last().unwrap()["content"].as_array().unwrap().clone()
}

// ---------------------------------------------------------------- selftest.mjs G1-G15

#[test]
fn g1_to_g4_a_tool_call_runs_redacted_and_streams() {
    let pc = Arc::new(FakePc::default());
    *pc.scan.lock().unwrap() = Some(json!({"checked": {"startItems": 465}, "defender": {"realtime": true}, "admin": false, "findings": [{"severity": "high", "program": "MediaPlayerService.exe", "folder": r"C:\Users\jdoe\AppData\x"}]}));
    let (t, calls) = script(vec![reply("tool_use", json!([text("Let me look."), tool("t1", "get_scan_results", json!({}))])), reply("end_turn", json!([text("Hideout found one threat.")]))]);
    let g = guide(Some(t), pc, money());
    let ev = chat(&g, "am I hacked? my name is jdoe");
    let calls = calls.lock().unwrap();
    let res = &last_results(&calls[1])[0];
    assert!(res["type"] == "tool_result" && res["content"].as_str().unwrap().contains("MediaPlayerService"), "G1");
    let sent = calls[1].to_string().to_lowercase();
    assert!(!sent.contains("jdoe") && !sent.contains("home-pc"), "G2: {sent}");
    assert_eq!(texts(&ev), format!("{AI_NOTICE}Let me look.Hideout found one threat."), "G3");
    assert_eq!(ev.last().unwrap()["type"], "done");
    assert_eq!(g.turns(), 4, "G4 append-only, ends on the assistant");
}

#[test]
fn g5_to_g7_invented_tools_and_bad_input_never_run() {
    let pc = Arc::new(FakePc::default());
    let (t, calls) = script(vec![
        reply("tool_use", json!([tool("t1", "delete_file", json!({"path": r"C:\x"})), tool("t2", "start_deep_check", json!({"with_admin": "yes"})), tool("t3", "update_case_step", json!({"step": "constructor", "status": "done"}))])),
        reply("end_turn", json!([text("ok")])),
    ]);
    let g = guide(Some(t), pc.clone(), money());
    chat(&g, "clean it");
    let r = last_results(&calls.lock().unwrap()[1]);
    assert!(r[0]["is_error"] == true && r[0]["content"] == "unknown tool", "G5");
    assert!(r[1]["is_error"] == true && r[1]["content"].as_str().unwrap().contains("with_admin"), "G6");
    assert!(r[2]["is_error"] == true && r[2]["content"].as_str().unwrap().contains("unknown step"), "G7");
    assert!(pc.jobs.lock().unwrap().is_empty(), "nothing ran");
}

#[test]
fn g8_to_g10_the_case_file_is_kept_and_read_back() {
    let pc = Arc::new(FakePc::default());
    let (t, calls) = script(vec![
        reply("tool_use", json!([tool("t1", "update_case_step", json!({"step": "changed_email_password", "status": "done"}))])),
        reply("end_turn", json!([text("Noted.")])),
        reply("tool_use", json!([tool("t2", "get_case_file", json!({}))])),
        reply("end_turn", json!([text("x")])),
    ]);
    let g = guide(Some(t), pc, money());
    let ev = chat(&g, "I changed my email password from my phone");
    assert!(ev.iter().any(|e| e["type"] == "tool" && e["status"].as_str().unwrap().starts_with("Case file:")), "G8");
    g.reset();
    chat(&g, "where were we?");
    let r = last_results(&calls.lock().unwrap()[3]);
    let content = r[0]["content"].as_str().unwrap();
    assert!(content.contains("\"id\":\"changed_email_password\"") && content.contains("\"status\":\"done\""), "G9: {content}");
    // G10 (no memory = an honest note): this build has no sealed memory and says so.
    assert!(content.contains("lasts until Hideout closes"), "G10");
    assert_eq!(g.tracker()[0]["status"], "in-progress", "the step moved the tracker");
}

#[test]
fn g11_a_refusal_ends_with_a_safe_message() {
    let (t, _) = script(vec![reply("refusal", json!([]))]);
    let g = guide(Some(t), Arc::new(FakePc::default()), money());
    let ev = chat(&g, "x");
    assert!(texts(&ev).contains("disconnect from the internet") && ev.last().unwrap()["type"] == "done");
}

#[test]
fn g12_an_api_error_rolls_back_and_says_so_plainly() {
    let (t, _) = script(vec![Err(TurnError::Status(429, "slow".into()))]);
    let g = guide(Some(t), Arc::new(FakePc::default()), money());
    let ev = chat(&g, "hello");
    assert_eq!(g.turns(), 0);
    assert_eq!(ev.last().unwrap()["type"], "error");
    assert!(ev.last().unwrap()["message"].as_str().unwrap().contains("busy"));
}

#[test]
fn g13_a_running_scan_is_waited_for() {
    let pc = Arc::new(FakePc::default());
    pc.running.store(true, Ordering::SeqCst);
    *pc.pending.lock().unwrap() = Some(json!({"findings": [{"program": "late.exe"}]}));
    let (t, calls) = script(vec![reply("tool_use", json!([tool("t1", "get_scan_results", json!({}))])), reply("end_turn", json!([text("ok")]))]);
    let g = guide(Some(t), pc, money());
    let ev = chat(&g, "am I hacked?");
    assert!(last_results(&calls.lock().unwrap()[1])[0]["content"].as_str().unwrap().contains("late.exe"));
    assert!(ev.iter().any(|e| e["status"] == "Waiting for the scan that's running..."));
}

#[test]
fn g14_no_connection_is_the_offline_guide_not_a_crash() {
    let g = guide(None, Arc::new(FakePc::default()), money());
    assert!(!g.ai() && g.mode() == "offline");
    let ev = chat(&g, "hi");
    let t = texts(&ev);
    assert!(t.contains("offline guide - not an AI") && t.contains("The six steps"), "{t}");
    assert_eq!(ev.last().unwrap()["type"], "done");
}

#[test]
fn busy_means_one_question_at_a_time() {
    struct Slow;
    impl Transport for Slow {
        fn kind(&self) -> &'static str {
            "gateway"
        }
        fn turn(&self, _o: &Outbound, _t: &mut dyn FnMut(&str)) -> Result<Final, TurnError> {
            std::thread::sleep(Duration::from_millis(300));
            Final::from_json(&json!({"stop_reason": "end_turn", "content": [], "model": "m", "usage": {}}))
        }
    }
    let g = Arc::new(guide(Some(Box::new(Slow)), Arc::new(FakePc::default()), money()));
    let g2 = g.clone();
    let h = std::thread::spawn(move || chat(&g2, "first"));
    std::thread::sleep(Duration::from_millis(100));
    let ev = chat(&g, "second");
    assert!(ev[0]["message"].as_str().unwrap().contains("still answering"));
    h.join().unwrap();
    assert!(!g.busy());
}

// ---------------------------------------------------------------- money.selftest.mjs G1-G9

#[test]
fn money_g1_to_g6_summary_cancel_steps_and_letters() {
    let m = money();
    {
        let mut mm = m.lock().unwrap();
        assert_eq!(mm.import_statement("bofa.csv", &fixture("bofa.csv").replace("JOHN DOE", "JDOE"))["ok"], true);
        assert_eq!(mm.import_statement("chase.csv", &fixture("chase.csv"))["ok"], true);
        mm.set_incident("2026-08-14");
    }
    let (t, calls) = script(vec![
        reply("tool_use", json!([tool("t1", "get_money_summary", json!({}))])),
        reply("tool_use", json!([tool("t2", "mark_canceled", json!({"merchant": "netflix", "canceled_on": "2026-08-05"})), tool("t3", "show_cancel_steps", json!({"merchant": "netflix"}))])),
        reply("tool_use", json!([tool("t4", "offer_letter", json!({"kind": "bank_dispute", "merchant": "netflix", "subject": "Dispute: charge after cancellation", "body": "Dear [Bank],\nI cancelled Netflix on 2026-08-05 but was charged $15.49 on 2026-09-01.\n[Your name]"}))])),
        reply("end_turn", json!([text("Here's your letter.")])),
    ]);
    let pc = Arc::new(FakePc::default());
    let g = guide(Some(t), pc.clone(), m.clone());
    let ev = chat(&g, "check my bank charges");
    let calls = calls.lock().unwrap();
    let summary = last_results(&calls[1])[0]["content"].as_str().unwrap().to_string();
    assert!(summary.contains("TECH SUPPORT") && summary.contains("Zelle") && summary.contains("repeatingChargesPerMonth"), "G1");
    assert!(!summary.to_lowercase().contains("jdoe"), "G2");
    assert_eq!(m.lock().unwrap().summary().recurring.iter().find(|r| r.merchant == "netflix").unwrap().status, "still-charging", "G3");
    let cards: Vec<&Value> = ev.iter().filter(|e| e["type"] == "card").map(|e| &e["card"]).collect();
    assert!(cards[0]["type"] == "cancel" && cards[0]["canOpen"] == true && cards[0]["steps"].as_array().unwrap().len() == 3 && cards[0].get("url").is_none(), "G4 {}", cards[0]);
    assert!(cards[1]["type"] == "letter" && cards[1]["kind"] == "bank_dispute" && cards[1]["body"].as_str().unwrap().contains("2026-09-01") && cards[1]["to"].is_null(), "G5");
    assert_eq!(hideout_guide::spec::validate_tool_input("offer_letter", &json!({"kind": "refund_request", "subject": "s", "body": "b", "to": "scammer@evil.example"})), Some("unexpected field"), "G6");
    assert!(pc.changed.load(Ordering::SeqCst) >= 2, "the window is told Money changed");
    assert_eq!(g.tracker()[4]["status"], "in-progress", "a letter moves the tracker");
}

#[test]
fn money_g7_to_g9_refusals_and_addresses() {
    // money.selftest.mjs runs G7 on the Money tab G1 filled (Bank of America + Chase).
    let m = money();
    m.lock().unwrap().import_statement("bofa.csv", &fixture("bofa.csv"));
    m.lock().unwrap().import_statement("chase.csv", &fixture("chase.csv"));
    let (t, calls) = script(vec![
        reply("tool_use", json!([tool("a", "offer_letter", json!({"kind": "cancel_by_email", "merchant": "nobody", "subject": "s", "body": "b"})), tool("b", "mark_canceled", json!({"merchant": "netflix", "canceled_on": "2099-01-01"})), tool("c", "set_incident_date", json!({"date": "last week"}))])),
        reply("end_turn", json!([text("ok")])),
    ]);
    let g = guide(Some(t), Arc::new(FakePc::default()), m);
    let ev = chat(&g, "x");
    let r = last_results(&calls.lock().unwrap()[1]);
    assert!(r[0]["content"].as_str().unwrap().contains("isn't in the repeating charges") && r[1]["content"].as_str().unwrap().contains("future") && r[2]["is_error"] == true && !ev.iter().any(|e| e["type"] == "card"), "G7 {r:?}");

    let mc = money();
    mc.lock().unwrap().import_statement("m.csv", "Date,Description,Amount\n2026-09-01,MAILCO,-5.00\n2026-08-01,MAILCO,-5.00\n");
    let (t3, _) = script(vec![reply("tool_use", json!([tool("a", "offer_letter", json!({"kind": "cancel_by_email", "merchant": "mailco", "subject": "Cancel", "body": "Please cancel. [Your name]"}))])), reply("end_turn", json!([text("ok")]))]);
    let ev3 = chat(&guide(Some(t3), Arc::new(FakePc::default()), mc.clone()), "cancel mailco");
    assert_eq!(ev3.iter().find(|e| e["type"] == "card").unwrap()["card"]["to"], "cancel@mailco.com", "G8");
    let (t4, _) = script(vec![reply("tool_use", json!([tool("a", "offer_letter", json!({"kind": "refund_request", "merchant": "mailco", "subject": "Refund", "body": "Please refund. [Your name]"}))])), reply("end_turn", json!([text("ok")]))]);
    let ev4 = chat(&guide(Some(t4), Arc::new(FakePc::default()), mc), "refund mailco");
    assert!(ev4.iter().find(|e| e["type"] == "card").unwrap()["card"]["to"].is_null(), "G9");
}

// ---------------------------------------------------------------- Phase 5 additions

#[test]
fn every_first_message_says_it_is_an_ai_and_can_be_wrong() {
    let (t, _) = script(vec![reply("end_turn", json!([text("a")])), reply("end_turn", json!([text("b")])), reply("end_turn", json!([text("c")]))]);
    let g = guide(Some(t), Arc::new(FakePc::default()), money());
    assert!(texts(&chat(&g, "hi")).starts_with(AI_NOTICE));
    assert!(!texts(&chat(&g, "and?")).contains("I'm an AI guide"), "not repeated mid-conversation");
    g.reset();
    assert!(texts(&chat(&g, "new")).starts_with(AI_NOTICE), "a new conversation says it again");
    assert!(AI_NOTICE.contains("AI") && AI_NOTICE.contains("can be wrong"));
}

#[test]
fn recovery_offers_get_the_second_scam_warning() {
    let (t, _) = script(vec![reply("end_turn", json!([text("ok")]))]);
    let g = guide(Some(t), Arc::new(FakePc::default()), money());
    assert!(texts(&chat(&g, "A company says they can recover my money for a fee")).contains(SECOND_SCAM));
    assert!(texts(&chat(&guide(None, Arc::new(FakePc::default()), money()), "someone offered to get my money back")).contains(SECOND_SCAM), "offline too");
}

#[test]
fn no_network_falls_back_to_the_offline_guide() {
    let m = money();
    m.lock().unwrap().import_statement("chase.csv", &fixture("chase.csv"));
    let (t, _) = script(vec![Err(TurnError::Network("the guide's address could not be found (no internet?)".into()))]);
    let g = guide(Some(t), Arc::new(FakePc::default()), m);
    let ev = chat(&g, "check my bank charges");
    let tx = texts(&ev);
    assert!(tx.contains("can't reach the AI guide") && tx.contains("Repeating charges"), "{tx}");
    assert_eq!(ev.last().unwrap()["type"], "done");
    assert_eq!(g.turns(), 0, "the failed turn is not kept");
}

#[test]
fn offline_letters_come_from_the_statement() {
    let m = money();
    {
        let mut mm = m.lock().unwrap();
        mm.import_statement("chase.csv", &fixture("chase.csv"));
        mm.mark_canceled("netflix", "2026-08-05");
    }
    let g = guide(None, Arc::new(FakePc::default()), m);
    let ev = chat(&g, "Write a letter to my bank disputing the charges from Netflix after I cancelled (netflix).");
    let card = &ev.iter().find(|e| e["type"] == "card").expect("a letter card")["card"];
    let body = card["body"].as_str().unwrap();
    assert!(body.contains("cancelled on 2026-08-05") && body.contains("$15.49 on 2026-09-01") && body.contains("[Your name]"), "{body}");
    assert!(card["to"].is_null());
}

#[test]
fn the_max_round_stop_leaves_no_unanswered_tool_call() {
    let mut steps: Vec<Result<Value, TurnError>> = (0..=6).map(|i| reply("tool_use", json!([tool(&format!("t{i}"), "get_case_file", json!({}))]))).collect();
    steps.push(reply("end_turn", json!([text("next")])));
    let (t, calls) = script(steps);
    let g = guide(Some(t), Arc::new(FakePc::default()), money());
    let ev = chat(&g, "loop");
    assert!(texts(&ev).contains("let me stop here"));
    chat(&g, "continue");
    let last = calls.lock().unwrap().last().unwrap().clone();
    let a = last.as_array().unwrap();
    // The tool call at the stop has its result, then the person's next words follow.
    assert_eq!(a[a.len() - 2]["content"][0]["type"], "tool_result");
    assert_eq!(a[a.len() - 2]["content"][0]["tool_use_id"], "t6");
}

#[test]
fn a_model_reply_carrying_personal_data_is_never_sent_back() {
    let (t, calls) = script(vec![reply("end_turn", json!([text("Your account 000123456789 is safe.")])), reply("end_turn", json!([text("x")]))]);
    let g = guide(Some(t), Arc::new(FakePc::default()), money());
    chat(&g, "hi");
    let ev = chat(&g, "and?");
    assert_eq!(calls.lock().unwrap().len(), 1, "the second request never left");
    assert!(ev.last().unwrap()["message"].as_str().unwrap().contains("fresh conversation"));
    assert_eq!(g.turns(), 0);
}

// ---------------------------------------------------------------- through a fake gateway

/// A fake of gateway/server.mjs on the other side of the door: issues install tokens,
/// checks the conversation as validateMessages does, and records the exact bytes.
struct FakeGateway {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    turns: Mutex<Vec<Vec<Value>>>,
    tokens: AtomicUsize,
    reject_first_token: AtomicBool,
}

impl Wire for FakeGateway {
    fn host(&self) -> String {
        "guide.example.test".into()
    }
    fn post(&self, path: &str, headers: &[(&str, &str)], body: &[u8], sink: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), WireFail> {
        self.sent.lock().unwrap().push(body.to_vec());
        if path == "/v1/install" {
            let n = self.tokens.fetch_add(1, Ordering::SeqCst);
            sink(json!({"token": format!("{:032x}.mac{n}", n)}).to_string().as_bytes());
            return Ok(());
        }
        assert_eq!(path, "/v1/guide/turn");
        let auth = headers.iter().find(|(k, _)| *k == "authorization").map(|x| x.1).unwrap_or("");
        if self.reject_first_token.swap(false, Ordering::SeqCst) && auth.ends_with("mac0") {
            return Err(WireFail::Status(401, "{\"error\":\"unknown install\"}".into()));
        }
        let v: Value = serde_json::from_slice(body).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["messages"], "a client sends ONLY the conversation");
        let msgs = v["messages"].as_array().unwrap();
        assert!(msgs.first().unwrap()["role"] == "user" && msgs.last().unwrap()["role"] == "user", "validateMessages: starts and ends with the person");
        let events = self.turns.lock().unwrap().remove(0);
        for e in events {
            // One NDJSON line at a time, split mid-line to test reassembly.
            let line = format!("{e}\n");
            let (a, b) = line.split_at(line.len() / 2);
            sink(a.as_bytes());
            sink(b.as_bytes());
        }
        Ok(())
    }
}

#[derive(Default)]
struct MemStore(Mutex<Option<String>>);
impl TokenStore for MemStore {
    fn load(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
    fn save(&self, t: &str) {
        *self.0.lock().unwrap() = Some(t.into());
    }
    fn clear(&self) {
        *self.0.lock().unwrap() = None;
    }
}

/// Measured against the live gateway 2026-10-24: its own Claude key was refused (a 401
/// inside the stream). A new install pass cannot fix that, so none is asked for.
#[test]
fn a_401_from_behind_the_gateway_does_not_burn_another_install() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let gw = FakeGateway {
        sent: sent.clone(),
        turns: Mutex::new(vec![vec![json!({"type": "error", "status": 401, "message": "the guide couldn't answer"})]]),
        tokens: AtomicUsize::new(0),
        reject_first_token: AtomicBool::new(false),
    };
    let t: Box<dyn Transport> = Box::new(Gateway::new(Box::new(gw), Box::new(MemStore::default())));
    let g = guide(Some(t), Arc::new(FakePc::default()), money());
    let ev = chat(&g, "hi");
    assert_eq!(ev.last().unwrap()["message"], "The guide couldn't sign in.");
    assert_eq!(sent.lock().unwrap().len(), 2, "one install, one turn - no second install");
}

#[test]
fn e1_app_to_gateway_with_money_tools_and_only_redacted_bytes_leave() {
    let m = money();
    m.lock().unwrap().import_statement("amex.csv", &fixture("amex.csv"));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let gw = FakeGateway {
        sent: sent.clone(),
        turns: Mutex::new(vec![
            vec![json!({"type": "final", "message": {"stop_reason": "tool_use", "content": [tool("x1", "get_money_summary", json!({}))], "model": "claude-opus-5", "usage": {}}})],
            vec![json!({"type": "final", "message": {"stop_reason": "tool_use", "content": [tool("x2", "offer_letter", json!({"kind": "refund_request", "merchant": "adobe", "subject": "Refund", "body": "Please refund. [Your name]"}))], "model": "claude-opus-5", "usage": {}}})],
            vec![json!({"type": "text", "delta": "Done."}), json!({"type": "final", "message": {"stop_reason": "end_turn", "content": [text("Done.")], "model": "claude-opus-5", "usage": {}}})],
        ]),
        tokens: AtomicUsize::new(0),
        reject_first_token: AtomicBool::new(true),
    };
    let t: Box<dyn Transport> = Box::new(Gateway::new(Box::new(gw), Box::new(MemStore::default())));
    let g = guide(Some(t), Arc::new(FakePc::default()), m);
    let ev = chat(&g, r"refund adobe - I'm jdoe on HOME-PC, card 4111 1111 1111 1111, files in C:\Users\jdoe\Downloads");
    assert!(ev.iter().any(|e| e["type"] == "card" && e["card"]["type"] == "letter" && e["card"]["name"] == "Adobe"), "E1");
    assert_eq!(ev.last().unwrap()["type"], "done");
    assert!(texts(&ev).ends_with("Done."));
    // What actually left: two install requests (the first pass was refused once), three turns.
    let sent = sent.lock().unwrap();
    assert_eq!(sent.len(), 6, "install, refused turn, install, then three turns");
    let all = String::from_utf8_lossy(&sent.concat()).to_lowercase();
    for secret in ["jdoe", "home-pc", "4111", r"users\\jdoe"] {
        assert!(!all.contains(secret), "{secret} left the PC");
    }
    assert!(all.contains("<you>") && all.contains("<this-pc>") && all.contains("[removed: card number]"));
}
