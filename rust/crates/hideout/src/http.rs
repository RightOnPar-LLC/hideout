//! A deliberately small HTTP/1.1 reader/writer for the loopback app server.
//!
//! Only what the app's own page sends is understood: a request line, headers, and a
//! body with Content-Length. Everything is capped - header bytes, header count, body
//! size - and anything malformed is refused, never guessed at. One request per
//! connection (the response says Connection: close), except the event stream.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 64;
/// The most of an oversized upload that is read (and thrown away) before answering 413.
pub const MAX_DRAIN: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    /// Path and query exactly as sent ("/launch?k=...").
    pub target: String,
    /// Lower-case header names, in order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// Connection closed or timed out before a full request arrived.
    Closed,
    /// Not HTTP we accept (malformed line, too many/too long headers, bad length).
    Bad(&'static str),
    /// Body bigger than the limit for this request. The caller answers 413.
    TooLarge,
    /// A body without Content-Length (e.g. chunked). The caller answers 411.
    LengthRequired,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }
    /// One query parameter, percent-decoded. Repeated keys: the first one wins.
    pub fn query(&self, key: &str) -> Option<String> {
        let q = self.target.split_once('?')?.1;
        q.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k == key).then(|| percent_decode(v))
        })
    }
    pub fn cookie(&self, name: &str) -> Option<String> {
        let all = self.header("cookie")?;
        all.split(';').find_map(|part| {
            let (k, v) = part.split_once('=')?;
            (k.trim() == name).then(|| v.trim().to_string())
        })
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(x) => {
                        out.push(x);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read one request. `body_limit` decides the cap from the method and path, so a
/// statement import can be bigger than a chat message.
pub fn read_request(stream: &TcpStream, body_limit: impl Fn(&str, &str) -> usize) -> Result<Request, ReadError> {
    let mut r = BufReader::new(stream);
    let mut head = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = r.by_ref().take((MAX_HEADER_BYTES - head.len() + 1) as u64).read_until(b'\n', &mut line).map_err(|_| ReadError::Closed)?;
        if n == 0 {
            return Err(if lines.is_empty() { ReadError::Closed } else { ReadError::Bad("truncated headers") });
        }
        head.extend_from_slice(&line);
        if head.len() > MAX_HEADER_BYTES {
            return Err(ReadError::Bad("headers too large"));
        }
        if !line.ends_with(b"\n") {
            return Err(ReadError::Bad("headers too large"));
        }
        let text = String::from_utf8(line).map_err(|_| ReadError::Bad("non-UTF-8 header"))?;
        let text = text.trim_end_matches(['\r', '\n']).to_string();
        if text.is_empty() {
            if lines.is_empty() {
                continue; // tolerate a stray CRLF before the request line
            }
            break;
        }
        lines.push(text);
        if lines.len() > MAX_HEADERS + 1 {
            return Err(ReadError::Bad("too many headers"));
        }
    }
    let mut parts = lines[0].split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(ReadError::Bad("bad request line"));
    };
    if !version.starts_with("HTTP/1.") || !target.starts_with('/') || method.is_empty() || !method.bytes().all(|c| c.is_ascii_uppercase()) {
        return Err(ReadError::Bad("bad request line"));
    }
    let mut headers = Vec::new();
    for l in &lines[1..] {
        let (k, v) = l.split_once(':').ok_or(ReadError::Bad("bad header"))?;
        if k.is_empty() || k.contains(' ') {
            return Err(ReadError::Bad("bad header"));
        }
        headers.push((k.to_ascii_lowercase(), v.trim().to_string()));
    }
    let mut req = Request { method: method.to_string(), target: target.to_string(), headers, body: Vec::new() };
    if req.header("transfer-encoding").is_some() {
        return Err(ReadError::LengthRequired);
    }
    let lens: Vec<&str> = req.headers.iter().filter(|(k, _)| k == "content-length").map(|(_, v)| v.as_str()).collect();
    if lens.len() > 1 {
        return Err(ReadError::Bad("repeated content-length"));
    }
    if let Some(l) = lens.first() {
        let n: usize = l.parse().map_err(|_| ReadError::Bad("bad content-length"))?;
        if n > body_limit(&req.method, req.path()) {
            // Read the upload to its end (discarding it, capped) so the sender gets a
            // real 413 rather than a connection torn mid-upload.
            let _ = std::io::copy(&mut r.by_ref().take(n.min(MAX_DRAIN) as u64), &mut std::io::sink());
            return Err(ReadError::TooLarge);
        }
        let mut body = vec![0u8; n];
        r.read_exact(&mut body).map_err(|_| ReadError::Closed)?;
        req.body = body;
    } else if req.method == "POST" {
        return Err(ReadError::LengthRequired);
    }
    Ok(req)
}

pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cache-control", "no-store"),
];

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        302 => "Found",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

/// Write a complete response and close.
pub fn respond(stream: &mut TcpStream, status: u16, headers: &[(&str, &str)], body: &[u8]) {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (k, v) in SECURITY_HEADERS.iter().chain(headers.iter()) {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", body.len()));
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// Start a streamed response (event stream or ndjson). The caller writes chunks of the
/// body directly and closes the connection to end it.
pub fn start_stream(stream: &mut TcpStream, content_type: &str) -> std::io::Result<()> {
    let mut out = String::from("HTTP/1.1 200 OK\r\n");
    for (k, v) in SECURITY_HEADERS {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("content-type: {content_type}\r\nconnection: close\r\n\r\n"));
    stream.write_all(out.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn roundtrip(raw: &[u8], limit: usize) -> Result<Request, ReadError> {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let raw = raw.to_vec();
        let t = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            let _ = c.write_all(&raw);
            let _ = c.shutdown(std::net::Shutdown::Write);
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
        let (s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let r = read_request(&s, |_, _| limit);
        t.join().unwrap();
        r
    }

    #[test]
    fn parses_a_normal_post() {
        let r = roundtrip(b"POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1:5\r\nContent-Type: application/json\r\nContent-Length: 15\r\nCookie: a=1; hideout=abc\r\n\r\n{\"kind\":\"scan\"}", 64).unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.path(), "/api/scan");
        assert_eq!(r.header("host"), Some("127.0.0.1:5"));
        assert_eq!(r.cookie("hideout").as_deref(), Some("abc"));
        assert_eq!(r.body, b"{\"kind\":\"scan\"}");
    }

    #[test]
    fn query_is_decoded() {
        let r = roundtrip(b"GET /launch?k=ab%20c&k=zz HTTP/1.1\r\n\r\n", 0).unwrap();
        assert_eq!(r.query("k").as_deref(), Some("ab c"));
        assert_eq!(r.query("missing"), None);
    }

    #[test]
    fn refuses_bad_input() {
        assert_eq!(roundtrip(b"GARBAGE\r\n\r\n", 64).unwrap_err(), ReadError::Bad("bad request line"));
        assert_eq!(roundtrip(b"GET http://evil/ HTTP/1.1\r\n\r\n", 64).unwrap_err(), ReadError::Bad("bad request line"));
        assert_eq!(roundtrip(b"GET / HTTP/1.1\r\nNoColon\r\n\r\n", 64).unwrap_err(), ReadError::Bad("bad header"));
        assert_eq!(roundtrip(b"POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\n", 10).unwrap_err(), ReadError::TooLarge);
        assert_eq!(roundtrip(b"POST / HTTP/1.1\r\nContent-Length: x\r\n\r\n", 10).unwrap_err(), ReadError::Bad("bad content-length"));
        assert_eq!(roundtrip(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", 10).unwrap_err(), ReadError::LengthRequired);
        assert_eq!(roundtrip(b"POST / HTTP/1.1\r\n\r\n", 10).unwrap_err(), ReadError::LengthRequired);
        assert_eq!(roundtrip(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx", 10).unwrap_err(), ReadError::Bad("repeated content-length"));
    }

    #[test]
    fn caps_header_size_and_count() {
        let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES + 10));
        big.extend_from_slice(b"\r\n\r\n");
        assert_eq!(roundtrip(&big, 0).unwrap_err(), ReadError::Bad("headers too large"));
        let mut many = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..(MAX_HEADERS + 5) {
            many.extend_from_slice(format!("H{i}: v\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(roundtrip(&many, 0).unwrap_err(), ReadError::Bad("too many headers"));
    }

    #[test]
    fn early_close_is_closed() {
        assert_eq!(roundtrip(b"", 0).unwrap_err(), ReadError::Closed);
        assert_eq!(roundtrip(b"POST / HTTP/1.1\r\nContent-Length: 50\r\n\r\nshort", 64).unwrap_err(), ReadError::Closed);
    }
}
