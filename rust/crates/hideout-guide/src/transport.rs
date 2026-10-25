//! How the guide reaches Claude (a port of guide.mjs's two transports):
//!   gateway - Hideout's cloud gateway, which holds the Claude key, enforces the spec and
//!             caps usage; this PC holds only a per-install token (the normal way)
//!   direct  - a key from the environment, held in memory only (a developer's own PC)
//!
//! Both send only an [`Outbound`] (the sealed, redacted conversation) over a [`Wire`]:
//! one HTTPS door to one host, handed in by the app (hideout-win's WinHTTP door). This
//! crate has no network code of its own.

use crate::spec;
use crate::wire::Outbound;
use serde_json::{json, Value};
use std::sync::Mutex;

/// Why a request through the door did not come back with an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireFail {
    Refused(String),
    Network(String),
    Timeout,
    Status(u16, String),
    TooLarge,
}

/// One HTTPS door to one host (see hideout_win::https::Door).
pub trait Wire: Send + Sync {
    fn host(&self) -> String;
    fn post(&self, path: &str, headers: &[(&str, &str)], body: &[u8], sink: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), WireFail>;
}

/// A finished model turn.
#[derive(Debug, Clone)]
pub struct Final {
    pub stop_reason: String,
    pub content: Vec<Value>,
    pub model: String,
    pub usage: Value,
}

impl Final {
    pub fn from_json(m: &Value) -> Result<Final, TurnError> {
        let content = m["content"].as_array().cloned().ok_or_else(|| TurnError::Protocol("answer without content".into()))?;
        Ok(Final { stop_reason: m["stop_reason"].as_str().unwrap_or("").to_string(), content, model: m["model"].as_str().unwrap_or("").to_string(), usage: m["usage"].clone() })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnError {
    /// The service answered with a status (429 busy, 401 sign-in, ...).
    Status(u16, String),
    /// Could not reach it.
    Network(String),
    /// It answered, but not in a shape we could read (retried, like guide.mjs).
    Protocol(String),
    /// Refused before anything was sent.
    Refused(String),
}

impl From<WireFail> for TurnError {
    fn from(f: WireFail) -> TurnError {
        match f {
            WireFail::Refused(w) => TurnError::Refused(w),
            WireFail::Network(w) => TurnError::Network(w),
            WireFail::Timeout => TurnError::Network("timed out".into()),
            WireFail::Status(s, b) => TurnError::Status(s, b),
            WireFail::TooLarge => TurnError::Protocol("answer too large".into()),
        }
    }
}

pub trait Transport: Send + Sync {
    fn kind(&self) -> &'static str;
    fn turn(&self, out: &Outbound, on_text: &mut dyn FnMut(&str)) -> Result<Final, TurnError>;
}

/// Splits a byte stream into lines (NDJSON or SSE), across chunk boundaries.
#[derive(Default)]
pub struct Lines {
    buf: Vec<u8>,
}

impl Lines {
    pub fn push(&mut self, chunk: &[u8], mut each: impl FnMut(&str)) {
        self.buf.extend_from_slice(chunk);
        while let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=i).collect();
            let s = String::from_utf8_lossy(&line[..line.len() - 1]);
            each(s.trim_end_matches('\r'));
        }
    }
    pub fn finish(&mut self, mut each: impl FnMut(&str)) {
        if !self.buf.is_empty() {
            let s = String::from_utf8_lossy(&self.buf).to_string();
            self.buf.clear();
            each(s.trim_end_matches('\r'));
        }
    }
}

/// Where the gateway's per-install token lives (%LOCALAPPDATA%\Hideout\install.json).
pub trait TokenStore: Send + Sync {
    fn load(&self) -> Option<String>;
    fn save(&self, token: &str);
    fn clear(&self);
}

pub struct Gateway {
    wire: Box<dyn Wire>,
    store: Box<dyn TokenStore>,
    token: Mutex<Option<String>>,
}

impl Gateway {
    pub fn new(wire: Box<dyn Wire>, store: Box<dyn TokenStore>) -> Gateway {
        Gateway { wire, store, token: Mutex::new(None) }
    }

    fn token(&self) -> Result<String, TurnError> {
        let mut t = self.token.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(x) = t.as_ref() {
            return Ok(x.clone());
        }
        if let Some(x) = self.store.load() {
            *t = Some(x.clone());
            return Ok(x);
        }
        let mut body = Vec::new();
        self.wire.post("/v1/install", &[("content-type", "application/json")], b"{}", &mut |b| {
            body.extend_from_slice(b);
            body.len() < 64 * 1024
        })?;
        let v: Value = serde_json::from_slice(&body).map_err(|_| TurnError::Protocol("install answer was not JSON".into()))?;
        let tok = v["token"].as_str().filter(|s| !s.is_empty() && s.len() < 512).ok_or_else(|| TurnError::Protocol("install answer had no token".into()))?.to_string();
        self.store.save(&tok);
        *t = Some(tok.clone());
        Ok(tok)
    }

    fn forget_token(&self) {
        *self.token.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.store.clear();
    }

    fn turn_once(&self, out: &Outbound, on_text: &mut dyn FnMut(&str)) -> Result<Final, TurnError> {
        let tok = self.token()?;
        let auth = format!("Bearer {tok}");
        let mut lines = Lines::default();
        let mut fin: Option<Value> = None;
        let mut err: Option<TurnError> = None;
        let mut handle = |line: &str, fin: &mut Option<Value>, err: &mut Option<TurnError>| {
            let line = line.trim();
            if line.is_empty() || err.is_some() {
                return;
            }
            match serde_json::from_str::<Value>(line) {
                Err(_) => *err = Some(TurnError::Protocol("the gateway sent a line that was not JSON".into())),
                Ok(ev) => match ev["type"].as_str() {
                    Some("text") => on_text(ev["delta"].as_str().unwrap_or("")),
                    Some("final") => *fin = Some(ev["message"].clone()),
                    Some("error") => *err = Some(TurnError::Status(ev["status"].as_u64().map(|s| s as u16).unwrap_or(502), ev["message"].as_str().unwrap_or("gateway error").chars().take(200).collect())),
                    _ => {}
                },
            }
        };
        self.wire.post("/v1/guide/turn", &[("content-type", "application/json"), ("authorization", &auth)], &out.gateway_body(), &mut |b| {
            lines.push(b, |l| handle(l, &mut fin, &mut err));
            err.is_none()
        })?;
        lines.finish(|l| handle(l, &mut fin, &mut err));
        if let Some(e) = err {
            return Err(e);
        }
        Final::from_json(&fin.ok_or_else(|| TurnError::Protocol("gateway ended without an answer".into()))?)
    }
}

impl Transport for Gateway {
    fn kind(&self) -> &'static str {
        "gateway"
    }

    fn turn(&self, out: &Outbound, on_text: &mut dyn FnMut(&str)) -> Result<Final, TurnError> {
        match self.turn_once(out, on_text) {
            // The gateway no longer knows this install (its secret was rotated): get a new
            // pass once, then give up. Only its own "unknown install" answer counts - a 401
            // from Claude behind the gateway (its key) is not fixed by a new pass.
            Err(TurnError::Status(401, body)) if body.contains("unknown install") => {
                self.forget_token();
                self.turn_once(out, on_text)
            }
            r => r,
        }
    }
}

pub const API_VERSION: &str = "2023-06-01";

pub struct Direct {
    wire: Box<dyn Wire>,
    key: String,
}

impl Direct {
    /// `key` stays in this process's memory; it is only ever written into the request
    /// header, never logged, saved or sent to the window.
    pub fn new(wire: Box<dyn Wire>, key: String) -> Direct {
        Direct { wire, key }
    }
}

/// Accumulates a streamed Messages API answer (server-sent events) into the final message.
#[derive(Default)]
pub struct SseMessage {
    event: String,
    message: Value,
    partial_json: Vec<String>,
    pub error: Option<TurnError>,
    pub done: bool,
}

impl SseMessage {
    pub fn line(&mut self, line: &str, on_text: &mut dyn FnMut(&str)) {
        if let Some(e) = line.strip_prefix("event:") {
            self.event = e.trim().to_string();
            return;
        }
        let Some(data) = line.strip_prefix("data:") else { return };
        let Ok(d) = serde_json::from_str::<Value>(data.trim()) else {
            self.error = Some(TurnError::Protocol("unreadable event".into()));
            return;
        };
        let kind = d["type"].as_str().unwrap_or(&self.event).to_string();
        match kind.as_str() {
            "message_start" => self.message = d["message"].clone(),
            "content_block_start" => {
                let i = d["index"].as_u64().unwrap_or(0) as usize;
                if let Some(c) = self.message["content"].as_array_mut() {
                    while c.len() <= i {
                        c.push(Value::Null);
                    }
                    c[i] = d["content_block"].clone();
                }
                while self.partial_json.len() <= i {
                    self.partial_json.push(String::new());
                }
            }
            "content_block_delta" => {
                let i = d["index"].as_u64().unwrap_or(0) as usize;
                let delta = &d["delta"];
                let Some(block) = self.message["content"].get_mut(i) else { return };
                match delta["type"].as_str().unwrap_or("") {
                    "text_delta" => {
                        let t = delta["text"].as_str().unwrap_or("");
                        let prev = block["text"].as_str().unwrap_or("").to_string();
                        block["text"] = json!(prev + t);
                        on_text(t);
                    }
                    "input_json_delta" => {
                        if let Some(p) = self.partial_json.get_mut(i) {
                            p.push_str(delta["partial_json"].as_str().unwrap_or(""));
                        }
                    }
                    "thinking_delta" => {
                        let prev = block["thinking"].as_str().unwrap_or("").to_string();
                        block["thinking"] = json!(prev + delta["thinking"].as_str().unwrap_or(""));
                    }
                    "signature_delta" => block["signature"] = delta["signature"].clone(),
                    "citations_delta" => {
                        if !block["citations"].is_array() {
                            block["citations"] = json!([]);
                        }
                        if let Some(a) = block["citations"].as_array_mut() {
                            a.push(delta["citation"].clone());
                        }
                    }
                    _ => {}
                }
            }
            "content_block_stop" => {
                let i = d["index"].as_u64().unwrap_or(0) as usize;
                let p = self.partial_json.get(i).cloned().unwrap_or_default();
                if let Some(block) = self.message["content"].get_mut(i) {
                    if block["type"] == "tool_use" || block["type"] == "server_tool_use" {
                        match if p.trim().is_empty() { Ok(json!({})) } else { serde_json::from_str::<Value>(&p) } {
                            Ok(input) => block["input"] = input,
                            Err(_) => self.error = Some(TurnError::Protocol("a tool input could not be read".into())),
                        }
                    }
                }
            }
            "message_delta" => {
                for k in ["stop_reason", "stop_sequence", "stop_details"] {
                    if let Some(v) = d["delta"].get(k) {
                        self.message[k] = v.clone();
                    }
                }
                if let (Some(u), Some(m)) = (d["usage"].as_object(), self.message["usage"].as_object_mut()) {
                    for (k, v) in u {
                        m.insert(k.clone(), v.clone());
                    }
                }
            }
            "message_stop" => self.done = true,
            "error" => {
                let t = d["error"]["type"].as_str().unwrap_or("");
                let status = match t {
                    "overloaded_error" => 529,
                    "rate_limit_error" => 429,
                    "authentication_error" => 401,
                    "permission_error" => 403,
                    "api_error" => 500,
                    _ => 0,
                };
                self.error = Some(if status > 0 { TurnError::Status(status, t.into()) } else { TurnError::Protocol(format!("stream error {t}")) });
            }
            _ => {}
        }
    }

    pub fn finish(self) -> Result<Final, TurnError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        if !self.done {
            return Err(TurnError::Protocol("the answer ended early".into()));
        }
        Final::from_json(&self.message)
    }
}

impl Transport for Direct {
    fn kind(&self) -> &'static str {
        "direct"
    }

    fn turn(&self, out: &Outbound, on_text: &mut dyn FnMut(&str)) -> Result<Final, TurnError> {
        let mut lines = Lines::default();
        let mut sse = SseMessage::default();
        let headers = [("content-type", "application/json"), ("x-api-key", self.key.as_str()), ("anthropic-version", API_VERSION), ("anthropic-beta", spec::FALLBACK_BETA)];
        self.wire.post("/v1/messages", &headers, &out.direct_body(), &mut |b| {
            lines.push(b, |l| sse.line(l, on_text));
            sse.error.is_none()
        })?;
        lines.finish(|l| sse.line(l, on_text));
        sse.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_survive_chunk_boundaries() {
        let mut l = Lines::default();
        let mut got = Vec::new();
        for c in [&b"{\"a\":1}\n{\"b\""[..], b":2}\r\n", b"{\"c\":3}"] {
            l.push(c, |s| got.push(s.to_string()));
        }
        l.finish(|s| got.push(s.to_string()));
        assert_eq!(got, vec!["{\"a\":1}", "{\"b\":2}", "{\"c\":3}"]);
    }

    #[test]
    fn a_streamed_answer_becomes_the_final_message() {
        let events = r#"event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5","content":[],"stop_reason":null,"usage":{"input_tokens":10,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"EqQBsig"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Let me "}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"look."}}

event: content_block_stop
data: {"type":"content_block_stop","index":1}

event: content_block_start
data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_1","name":"start_deep_check","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"with_ad"}}

event: content_block_delta
data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"min\": false}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":2}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":42}}

event: message_stop
data: {"type":"message_stop"}
"#;
        let mut sse = SseMessage::default();
        let mut text = String::new();
        let mut l = Lines::default();
        l.push(events.as_bytes(), |s| sse.line(s, &mut |t| text.push_str(t)));
        let f = sse.finish().unwrap();
        assert_eq!(text, "Let me look.");
        assert_eq!(f.stop_reason, "tool_use");
        assert_eq!(f.content[0], json!({"type": "thinking", "thinking": "", "signature": "EqQBsig"}));
        assert_eq!(f.content[2]["input"], json!({"with_admin": false}));
        assert_eq!(f.usage["output_tokens"], 42);
        assert_eq!(f.usage["input_tokens"], 10);
    }

    #[test]
    fn a_stream_cut_short_or_overloaded_is_an_error() {
        let mut sse = SseMessage::default();
        sse.line(r#"data: {"type":"message_start","message":{"content":[],"usage":{}}}"#, &mut |_| {});
        assert!(matches!(sse.finish(), Err(TurnError::Protocol(_))));
        let mut sse = SseMessage::default();
        sse.line(r#"data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#, &mut |_| {});
        assert_eq!(sse.finish().err(), Some(TurnError::Status(529, "overloaded_error".into())));
    }
}
