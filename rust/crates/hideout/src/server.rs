//! The local app server. It is only ever reachable from THIS PC, and only by the window
//! Hideout itself opened:
//!   - binds 127.0.0.1 on a random free port (never 0.0.0.0, never a fixed port)
//!   - a fresh 256-bit session key per launch; the window gets it once via /launch and
//!     holds it as an HttpOnly SameSite=Strict cookie; every other request needs it
//!   - the Host header must be exactly 127.0.0.1:<port> (blocks DNS-rebinding pages)
//!   - every POST must carry Origin = this server (blocks other sites and tabs)
//!   - request bodies are capped; the page gets a strict Content-Security-Policy
//!   - it shuts itself down when the window has been closed for a while
//!
//! The rules and their order are the same as app/src/server.mjs.

use crate::http::{self, ReadError, Request};
use crate::worker::{Event, Worker};
use serde_json::{json, Value};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_BODY: usize = 64 * 1024;
const MAX_IMPORT: usize = 3 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 64;
const CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub struct Config {
    pub ui_html: &'static str,
    pub version: String,
    pub idle_exit: Duration,
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
}

pub struct Running {
    pub port: u16,
    pub launch_url: String,
    /// Fires once the window has been closed (no event stream) for `idle_exit` while
    /// nothing is running.
    pub idle: Receiver<()>,
}

struct Shared {
    token: String,
    port: u16,
    origin: String,
    worker: Worker,
    cfg: Config,
    clients: Mutex<Vec<Sender<String>>>,
    ever_connected: AtomicBool,
    last_client: Mutex<Instant>,
    open_connections: AtomicUsize,
}

/// Equal-time comparison, so the session key cannot be guessed a byte at a time.
fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn memory_state() -> Value {
    json!({"available": false, "why": "memory arrives in a later Rust build", "caseFile": null})
}

impl Shared {
    fn full_state(&self) -> Value {
        json!({"worker": self.worker.state(), "memory": memory_state(), "money": null})
    }

    fn broadcast(&self, event: &str, data: &Value) {
        let line = format!("event: {event}\ndata: {data}\n\n");
        self.clients.lock().unwrap_or_else(|p| p.into_inner()).retain(|c| c.send(line.clone()).is_ok());
    }
}

/// Start the server on a random loopback port. `events` is the worker's event feed.
pub fn start(worker: Worker, events: Receiver<Event>, cfg: Config) -> std::io::Result<Running> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let token = hideout_win::crypto::random_hex(32);
    let shared = Arc::new(Shared {
        origin: format!("http://127.0.0.1:{port}"),
        token: token.clone(),
        port,
        worker,
        cfg,
        clients: Mutex::new(Vec::new()),
        ever_connected: AtomicBool::new(false),
        last_client: Mutex::new(Instant::now()),
        open_connections: AtomicUsize::new(0),
    });

    // Worker events -> every open window.
    let s = shared.clone();
    std::thread::Builder::new().name("hideout-events".into()).spawn(move || {
        while let Ok(ev) = events.recv() {
            match ev {
                Event::Job(j) => s.broadcast("job", &j),
                Event::State => s.broadcast("state", &s.full_state()),
            }
        }
    })?;

    // Connections.
    let s = shared.clone();
    std::thread::Builder::new().name("hideout-accept".into()).spawn(move || {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            if s.open_connections.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                drop(stream);
                continue;
            }
            s.open_connections.fetch_add(1, Ordering::SeqCst);
            let s2 = s.clone();
            let spawned = std::thread::Builder::new().name("hideout-conn".into()).spawn(move || {
                let s3 = s2.clone();
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle(&s3, stream)));
                if r.is_err() {
                    (s2.cfg.log)("request handler panicked");
                }
                s2.open_connections.fetch_sub(1, Ordering::SeqCst);
            });
            if spawned.is_err() {
                s.open_connections.fetch_sub(1, Ordering::SeqCst);
            }
        }
    })?;

    // Idle exit: the window was closed a while ago and nothing is running.
    let (idle_tx, idle_rx) = channel();
    let s = shared.clone();
    std::thread::Builder::new().name("hideout-idle".into()).spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1).min(s.cfg.idle_exit / 4).max(Duration::from_millis(50)));
        let no_clients = s.clients.lock().map(|c| c.is_empty()).unwrap_or(false);
        if !s.ever_connected.load(Ordering::SeqCst) || !no_clients || s.worker.busy() {
            continue;
        }
        let since = s.last_client.lock().map(|t| t.elapsed()).unwrap_or_default();
        if since > s.cfg.idle_exit {
            let _ = idle_tx.send(());
            return;
        }
    })?;

    Ok(Running { port, launch_url: format!("http://127.0.0.1:{port}/launch?k={token}"), idle: idle_rx })
}

fn text(stream: &mut TcpStream, status: u16, body: &str) {
    http::respond(stream, status, &[("content-type", "text/plain; charset=utf-8")], body.as_bytes());
}

fn json_reply(stream: &mut TcpStream, status: u16, v: &Value) {
    http::respond(stream, status, &[("content-type", "application/json; charset=utf-8")], v.to_string().as_bytes());
}

fn handle(s: &Shared, mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let req = match http::read_request(&stream, |m, p| if m == "POST" && p == "/api/money/import" { MAX_IMPORT } else { MAX_BODY }) {
        Ok(r) => r,
        Err(ReadError::TooLarge) => return text(&mut stream, 413, "too large"),
        Err(ReadError::LengthRequired) => return text(&mut stream, 411, "length required"),
        Err(ReadError::Bad(_)) => return text(&mut stream, 400, "bad request"),
        Err(ReadError::Closed) => return,
    };
    route(s, &mut stream, req);
}

fn route(s: &Shared, stream: &mut TcpStream, req: Request) {
    if req.header("host") != Some(&format!("127.0.0.1:{}", s.port)) {
        return text(stream, 421, "wrong host");
    }
    let p = req.path().to_string();

    if p == "/launch" && req.method == "GET" {
        if !same(&req.query("k").unwrap_or_default(), &s.token) {
            return text(stream, 403, "This link has expired - open Hideout again.");
        }
        let cookie = format!("hideout={}; HttpOnly; SameSite=Strict; Path=/", s.token);
        return http::respond(stream, 302, &[("location", "/"), ("set-cookie", &cookie)], b"");
    }
    if !same(&req.cookie("hideout").unwrap_or_default(), &s.token) {
        return text(stream, 403, "Open Hideout from its shortcut.");
    }
    if req.method == "POST" {
        if req.header("origin") != Some(s.origin.as_str()) {
            return text(stream, 403, "cross-site request refused");
        }
        let ct = req.header("content-type").unwrap_or("");
        let is_json = ct.len() >= 16 && ct[..16].eq_ignore_ascii_case("application/json") && ct[16..].chars().next().map(|c| !c.is_ascii_alphanumeric() && c != '_').unwrap_or(true);
        if !is_json {
            return text(stream, 415, "json only");
        }
    }

    match (req.method.as_str(), p.as_str()) {
        ("GET", "/") => http::respond(
            stream,
            200,
            &[("content-type", "text/html; charset=utf-8"), ("content-security-policy", CSP), ("x-frame-options", "DENY")],
            s.cfg.ui_html.as_bytes(),
        ),
        ("GET", "/api/state") => {
            let mut v = json!({"version": s.cfg.version, "ai": false, "aiMode": "off", "model": null});
            if let (Value::Object(a), Value::Object(b)) = (&mut v, s.full_state()) {
                a.extend(b);
            }
            json_reply(stream, 200, &v)
        }
        ("GET", "/api/events") => event_stream(s, stream),
        ("POST", _) => {
            let body: Value = match serde_json::from_slice(if req.body.is_empty() { b"{}" } else { &req.body }) {
                Ok(v) => v,
                Err(_) => return text(stream, 400, "bad json"),
            };
            post(s, stream, &p, &body)
        }
        _ => text(stream, 404, "not found"),
    }
}

fn post(s: &Shared, stream: &mut TcpStream, p: &str, body: &Value) {
    if p.starts_with("/api/money/") {
        // The Money tab is ported in Phase 4; until then it answers like a build without it.
        return json_reply(stream, 404, &json!({"error": "money section unavailable"}));
    }
    match p {
        "/api/scan" => {
            let kind = body.get("kind").and_then(|k| k.as_str()).unwrap_or("");
            match s.worker.enqueue(kind) {
                Ok((id, state)) => json_reply(stream, 202, &json!({"id": id, "state": state})),
                Err(_) => json_reply(stream, 400, &json!({"error": "unknown kind"})),
            }
        }
        "/api/chat/reset" => json_reply(stream, 200, &json!({"ok": true})),
        "/api/chat" => {
            let msg = body.get("message").and_then(|m| m.as_str()).unwrap_or("").trim().to_string();
            if msg.is_empty() {
                return json_reply(stream, 400, &json!({"error": "empty message"}));
            }
            // The guide is ported in Phase 5. Same answer as a build with no guide.
            if http::start_stream(stream, "application/x-ndjson; charset=utf-8").is_ok() {
                let _ = stream.write_all(format!("{}\n", json!({"type": "error", "message": "The AI guide isn't connected on this PC."})).as_bytes());
            }
        }
        _ => text(stream, 404, "not found"),
    }
}

/// The window closed its end: a peek reads end-of-stream (or an error) instead of
/// "nothing yet". The window never sends anything on this connection after the request.
fn window_gone(stream: &TcpStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return true;
    }
    let mut b = [0u8; 1];
    let gone = match stream.peek(&mut b) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
    };
    let _ = stream.set_nonblocking(false);
    gone
}

fn event_stream(s: &Shared, stream: &mut TcpStream) {
    if http::start_stream(stream, "text/event-stream").is_err() {
        return;
    }
    let first = format!("event: state\ndata: {}\n\n", s.full_state());
    if stream.write_all(first.as_bytes()).is_err() {
        return;
    }
    let (tx, rx) = channel::<String>();
    s.clients.lock().unwrap_or_else(|p| p.into_inner()).push(tx);
    s.ever_connected.store(true, Ordering::SeqCst);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let mut last_ping = Instant::now();
    loop {
        let out = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(line) if line.is_empty() => continue,
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => {
                if window_gone(stream) {
                    break;
                }
                if last_ping.elapsed() < Duration::from_secs(15) {
                    continue;
                }
                last_ping = Instant::now();
                ": ping\n\n".to_string()
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if stream.write_all(out.as_bytes()).and_then(|_| stream.flush()).is_err() {
            break;
        }
    }
    // The window went away: our sender is dropped from the list on the next broadcast.
    drop(rx);
    s.clients.lock().unwrap_or_else(|p| p.into_inner()).retain(|c| c.send(String::new()).is_ok());
    *s.last_client.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::sync::Arc;

    fn start_test(idle: Duration) -> (Running, Worker) {
        let (etx, erx) = channel();
        let scan: crate::worker::ScanFn = Arc::new(|| Ok(json!({"app": "Hideout", "findings": []})));
        let hunt: crate::worker::HuntFn = Arc::new(|_, _| Err("no deep check in server tests".into()));
        let w = Worker::start(scan, hunt, etx);
        let cfg = Config { ui_html: "<html>ui</html>", version: "test".into(), idle_exit: idle, log: Arc::new(|_| {}) };
        (start(w.clone(), erx, cfg).unwrap(), w)
    }

    fn raw(port: u16, req: &str) -> (u16, String, String) {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = c.read_to_string(&mut out);
        let status = out.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let (head, body) = out.split_once("\r\n\r\n").map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((out.clone(), String::new()));
        (status, head, body)
    }

    fn token_of(r: &Running) -> String {
        r.launch_url.split("k=").nth(1).unwrap().to_string()
    }

    fn get(port: u16, path: &str, cookie: &str) -> (u16, String, String) {
        raw(port, &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: hideout={cookie}\r\n\r\n"))
    }

    fn post(port: u16, path: &str, cookie: &str, origin: &str, ct: &str, body: &str) -> (u16, String, String) {
        raw(port, &format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: hideout={cookie}\r\nOrigin: {origin}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n{body}", body.len()))
    }

    #[test]
    fn launch_sets_the_cookie_and_wrong_keys_fail() {
        let (r, _) = start_test(Duration::from_secs(60));
        let k = token_of(&r);
        assert_eq!(k.len(), 64);
        let (st, head, _) = get(r.port, &format!("/launch?k={k}"), "");
        assert_eq!(st, 302);
        assert!(head.contains(&format!("set-cookie: hideout={k}; HttpOnly; SameSite=Strict; Path=/")));
        assert_eq!(get(r.port, "/launch?k=nope", "").0, 403);
        assert_eq!(get(r.port, &format!("/launch?k={}", &k[..63]), "").0, 403);
    }

    #[test]
    fn everything_else_needs_the_cookie() {
        let (r, _) = start_test(Duration::from_secs(60));
        assert_eq!(get(r.port, "/", "").0, 403);
        assert_eq!(get(r.port, "/api/state", "wrong").0, 403);
        let (st, head, body) = get(r.port, "/", &token_of(&r));
        assert_eq!(st, 200);
        assert!(head.contains("content-security-policy: default-src 'none'"));
        assert!(head.contains("x-frame-options: DENY"));
        assert!(head.contains("x-content-type-options: nosniff"));
        assert_eq!(body, "<html>ui</html>");
    }

    #[test]
    fn wrong_host_is_refused_even_with_the_cookie() {
        let (r, _) = start_test(Duration::from_secs(60));
        let k = token_of(&r);
        let (st, _, _) = raw(r.port, &format!("GET /api/state HTTP/1.1\r\nHost: evil.example:{}\r\nCookie: hideout={k}\r\n\r\n", r.port));
        assert_eq!(st, 421);
        let (st, _, _) = raw(r.port, &format!("GET /api/state HTTP/1.1\r\nHost: localhost:{}\r\nCookie: hideout={k}\r\n\r\n", r.port));
        assert_eq!(st, 421);
        let (st, _, _) = raw(r.port, &format!("GET /api/state HTTP/1.1\r\nCookie: hideout={k}\r\n\r\n"));
        assert_eq!(st, 421);
    }

    #[test]
    fn posts_need_same_origin_and_json() {
        let (r, _) = start_test(Duration::from_secs(60));
        let k = token_of(&r);
        let me = format!("http://127.0.0.1:{}", r.port);
        assert_eq!(post(r.port, "/api/scan", &k, "http://evil.example", "application/json", "{\"kind\":\"scan\"}").0, 403);
        assert_eq!(post(r.port, "/api/scan", &k, "null", "application/json", "{\"kind\":\"scan\"}").0, 403);
        assert_eq!(post(r.port, "/api/scan", &k, &me, "text/plain", "{\"kind\":\"scan\"}").0, 415);
        assert_eq!(post(r.port, "/api/scan", &k, &me, "application/jsonx", "{}").0, 415);
        assert_eq!(post(r.port, "/api/scan", &k, &me, "application/json", "{not json").0, 400);
        assert_eq!(post(r.port, "/api/scan", &k, &me, "application/json", "{\"kind\":\"rm\"}").0, 400);
        let (st, _, body) = post(r.port, "/api/scan", &k, &me, "application/json; charset=utf-8", "{\"kind\":\"scan\"}");
        assert_eq!(st, 202, "{body}");
        assert!(body.contains("\"state\":\"queued\""));
    }

    #[test]
    fn bodies_are_capped() {
        let (r, _) = start_test(Duration::from_secs(60));
        let k = token_of(&r);
        let me = format!("http://127.0.0.1:{}", r.port);
        let big = format!("{{\"message\":\"{}\"}}", "a".repeat(MAX_BODY));
        assert_eq!(post(r.port, "/api/chat", &k, &me, "application/json", &big).0, 413);
    }

    #[test]
    fn state_matches_what_the_window_reads() {
        let (r, _) = start_test(Duration::from_secs(60));
        let (st, _, body) = get(r.port, "/api/state", &token_of(&r));
        assert_eq!(st, 200);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["version"], "test");
        assert_eq!(v["ai"], false);
        assert_eq!(v["memory"]["available"], false);
        assert!(v["money"].is_null());
        assert_eq!(v["worker"]["busy"], false);
    }

    #[test]
    fn unported_sections_answer_like_a_build_without_them() {
        let (r, _) = start_test(Duration::from_secs(60));
        let k = token_of(&r);
        let me = format!("http://127.0.0.1:{}", r.port);
        assert_eq!(post(r.port, "/api/money/import", &k, &me, "application/json", "{\"text\":\"a\"}").0, 404);
        let (st, _, body) = post(r.port, "/api/chat", &k, &me, "application/json", "{\"message\":\"hi\"}");
        assert_eq!(st, 200);
        assert!(body.contains("isn't connected"));
    }

    #[test]
    fn event_stream_sends_state_then_job_events() {
        let (r, w) = start_test(Duration::from_secs(60));
        let k = token_of(&r);
        let mut c = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(format!("GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: hideout={k}\r\n\r\n", r.port).as_bytes()).unwrap();
        let mut rd = BufReader::new(c);
        let mut seen = Vec::new();
        let mut line = String::new();
        let mut asked = false;
        while rd.read_line(&mut line).unwrap_or(0) > 0 {
            if line.starts_with("event:") {
                seen.push(line.trim().to_string());
                if !asked {
                    asked = true;
                    w.enqueue("scan").unwrap();
                }
            }
            if seen.iter().any(|e| e == "event: state") && seen.iter().filter(|e| *e == "event: job").count() >= 2 {
                break;
            }
            line.clear();
        }
        assert_eq!(seen.first().map(String::as_str), Some("event: state"));
        assert!(seen.iter().any(|e| e == "event: job"));
    }

    #[test]
    fn exits_after_the_window_closes() {
        let (r, _) = start_test(Duration::from_millis(300));
        let k = token_of(&r);
        {
            let mut c = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
            c.write_all(format!("GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: hideout={k}\r\n\r\n", r.port).as_bytes()).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        }
        // No window ever connected -> never idles out; one did and left -> it does.
        r.idle.recv_timeout(Duration::from_secs(5)).expect("idle exit after the window closed");
    }
}
