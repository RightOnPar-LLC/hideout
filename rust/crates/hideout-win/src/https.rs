//! The one door out: an HTTPS client (WinHTTP, Windows' own TLS) that can reach exactly
//! ONE host, fixed when the door is opened. It is how the guide's redacted request
//! reaches the guide's service, and nothing else in Hideout opens a network connection.
//!
//!   - https only, to the host given to [`Door::open`]; a request names only a path, so
//!     there is no way to point a request at any other host
//!   - redirects are refused (a redirect could lead somewhere else)
//!   - TLS 1.2 or 1.3, with Windows checking the certificate and the host name
//!   - time limits on name lookup, connect, send and every read
//!   - a connection that fails before any byte of the answer arrived is retried at most
//!     twice; nothing is retried once an answer has started
//!   - answers are capped in size
//!
//! Headers and bodies are never logged here.

use crate::wide::Wide;
use windows::core::PCWSTR;
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WinHttpSetTimeouts, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_NEVER, WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
};

const MAX_ANSWER: usize = 8 * 1024 * 1024;
const RETRIES: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fail {
    /// Refused before anything left the PC (not https, another host, a bad path or header).
    Refused(String),
    /// Could not reach the host (no network, name not found, connection failed).
    Network(String),
    Timeout,
    /// The host answered with this status (and the start of its body).
    Status(u16, String),
    TooLarge,
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fail::Refused(w) => write!(f, "refused: {w}"),
            Fail::Network(w) => write!(f, "network: {w}"),
            Fail::Timeout => write!(f, "timed out"),
            Fail::Status(s, _) => write!(f, "status {s}"),
            Fail::TooLarge => write!(f, "answer too large"),
        }
    }
}

/// A WinHTTP handle, closed on drop.
struct Handle(*mut core::ffi::c_void);

// SAFETY: WinHTTP session and connection handles may be used from any thread (requests
// on one handle are made one at a time here, behind &self methods that open their own
// request handle).
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a handle WinHTTP gave us, closed once.
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

/// Where a door leads: scheme must be https, a host, an optional port, nothing else.
pub fn parse_origin(url: &str) -> Result<(String, u16), Fail> {
    let rest = url.strip_prefix("https://").ok_or_else(|| Fail::Refused("only https is allowed".into()))?;
    let hostport = rest.strip_suffix('/').unwrap_or(rest);
    if hostport.is_empty() || hostport.contains(['/', '?', '#', '@', '\\', ' ', '\r', '\n']) {
        return Err(Fail::Refused("give only https://host (no path, no user name)".into()));
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| Fail::Refused("bad port".into()))?),
        None => (hostport, 443),
    };
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return Err(Fail::Refused("bad host name".into()));
    }
    Ok((host.to_ascii_lowercase(), port))
}

fn set_u32(h: *mut core::ffi::c_void, option: u32, v: u32) -> bool {
    // SAFETY: `h` is a live WinHTTP handle; the option takes a DWORD.
    unsafe { WinHttpSetOption(Some(h as *const _), option, Some(&v.to_le_bytes())).is_ok() }
}

fn last_fail(e: &windows::core::Error) -> Fail {
    let code = (e.code().0 as u32) & 0xFFFF;
    match code {
        12002 => Fail::Timeout,
        12007 => Fail::Network("the guide's address could not be found (no internet?)".into()),
        12029..=12031 => Fail::Network("could not connect".into()),
        12175 | 12045 | 12038 | 12037 | 12057 => Fail::Network(format!("the secure connection failed (error {code})")),
        _ => Fail::Network(format!("error {code}")),
    }
}

pub struct Door {
    host: String,
    port: u16,
    session: Handle,
    connect: Handle,
}

impl Door {
    /// Open the door to one host. `origin` is "https://host" or "https://host:port".
    pub fn open(origin: &str, agent: &str) -> Result<Door, Fail> {
        let (host, port) = parse_origin(origin)?;
        let agent_w = Wide::new(agent);
        // SAFETY: valid wide strings that outlive the call; null proxy strings mean "none".
        let session = Handle(unsafe { WinHttpOpen(agent_w.pcwstr(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, PCWSTR::null(), PCWSTR::null(), 0) });
        if session.0.is_null() {
            return Err(Fail::Network("could not start the secure connection".into()));
        }
        if !set_u32(session.0, WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3) {
            // Older Windows without TLS 1.3 support: TLS 1.2 only.
            if !set_u32(session.0, WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2) {
                return Err(Fail::Network("TLS 1.2 is not available".into()));
            }
        }
        // Name lookup 10 s, connect 10 s, send 30 s, each read 180 s (the guide may think
        // for a while before its first word).
        // SAFETY: live session handle.
        unsafe { WinHttpSetTimeouts(session.0, 10_000, 10_000, 30_000, 180_000) }.map_err(|e| last_fail(&e))?;
        let host_w = Wide::new(&host);
        // SAFETY: live session handle, valid host string.
        let connect = Handle(unsafe { WinHttpConnect(session.0, host_w.pcwstr(), port, 0) });
        if connect.0.is_null() {
            return Err(Fail::Network("could not prepare the connection".into()));
        }
        Ok(Door { host, port, session, connect })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// POST `body` to `path` on this door's host. `sink` receives the answer as it
    /// arrives (only for a 200); it returns false to stop reading.
    pub fn post(&self, path: &str, headers: &[(&str, &str)], body: &[u8], sink: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Fail> {
        check_request(path, headers)?;
        let mut attempt = 0;
        loop {
            let mut delivered = false;
            match self.post_once(path, headers, body, &mut |b| {
                delivered = true;
                sink(b)
            }) {
                Err(Fail::Network(_)) | Err(Fail::Timeout) if !delivered && attempt < RETRIES => {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(500 * 3u64.pow(attempt - 1)));
                }
                other => return other,
            }
        }
    }

    fn post_once(&self, path: &str, headers: &[(&str, &str)], body: &[u8], sink: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Fail> {
        let _ = &self.session;
        let (verb, path_w) = (Wide::new("POST"), Wide::new(path));
        // SAFETY: live connect handle; valid strings; null accept-types pointer.
        let req = Handle(unsafe { WinHttpOpenRequest(self.connect.0, verb.pcwstr(), path_w.pcwstr(), PCWSTR::null(), PCWSTR::null(), std::ptr::null(), WINHTTP_FLAG_SECURE) });
        if req.0.is_null() {
            return Err(Fail::Network("could not open the request".into()));
        }
        if !set_u32(req.0, WINHTTP_OPTION_REDIRECT_POLICY, WINHTTP_OPTION_REDIRECT_POLICY_NEVER) {
            return Err(Fail::Refused("could not turn redirects off, so nothing was sent".into()));
        }
        let head: String = headers.iter().map(|(k, v)| format!("{k}: {v}\r\n")).collect();
        let head_w: Vec<u16> = head.encode_utf16().collect();
        let len = u32::try_from(body.len()).map_err(|_| Fail::Refused("request too large".into()))?;
        // SAFETY: live request handle; header and body buffers outlive the call.
        unsafe { WinHttpSendRequest(req.0, Some(&head_w), Some(body.as_ptr() as *const _), len, len, 0) }.map_err(|e| last_fail(&e))?;
        // SAFETY: live request handle, reserved must be null.
        unsafe { WinHttpReceiveResponse(req.0, std::ptr::null_mut()) }.map_err(|e| last_fail(&e))?;
        let mut status = 0u32;
        let mut size = 4u32;
        // SAFETY: a DWORD-sized buffer for a numeric query.
        unsafe { WinHttpQueryHeaders(req.0, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, PCWSTR::null(), Some(&mut status as *mut u32 as *mut _), &mut size, std::ptr::null_mut()) }.map_err(|e| last_fail(&e))?;
        let mut buf = vec![0u8; 16 * 1024];
        let mut total = 0usize;
        let mut err_body = Vec::new();
        loop {
            let mut got = 0u32;
            // SAFETY: `buf` is a writable buffer of the stated length.
            unsafe { WinHttpReadData(req.0, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut got) }.map_err(|e| last_fail(&e))?;
            if got == 0 {
                break;
            }
            let chunk = &buf[..got as usize];
            total += chunk.len();
            if total > MAX_ANSWER {
                return Err(Fail::TooLarge);
            }
            if status == 200 {
                if !sink(chunk) {
                    break;
                }
            } else if err_body.len() < 4096 {
                err_body.extend_from_slice(chunk);
            }
        }
        if status != 200 {
            return Err(Fail::Status(status as u16, String::from_utf8_lossy(&err_body).chars().take(500).collect()));
        }
        Ok(())
    }
}

/// A request names a path on the door's host and nothing else.
pub fn check_request(path: &str, headers: &[(&str, &str)]) -> Result<(), Fail> {
    if !path.starts_with('/') || path.starts_with("//") || path.contains(['\r', '\n', ' ', '@', '\\', '#']) || path.contains("://") {
        return Err(Fail::Refused(format!("not a plain path: {path:?}")));
    }
    for (k, v) in headers {
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') || v.contains(['\r', '\n']) {
            return Err(Fail::Refused("bad header".into()));
        }
        if k.eq_ignore_ascii_case("host") {
            return Err(Fail::Refused("the host header is fixed by the door".into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_to_one_plain_host() {
        assert_eq!(parse_origin("https://guide.example.com").unwrap(), ("guide.example.com".into(), 443));
        assert_eq!(parse_origin("https://Guide.Example.com/").unwrap(), ("guide.example.com".into(), 443));
        assert_eq!(parse_origin("https://guide.example.com:8443").unwrap().1, 8443);
        for bad in ["http://guide.example.com", "https://user:pw@guide.example.com", "https://guide.example.com/v1", "https://", "ftp://x", "https://a b", "https://x.example?y", "guide.example.com", "https://évil.example"] {
            assert!(matches!(parse_origin(bad), Err(Fail::Refused(_))), "{bad}");
        }
    }

    #[test]
    fn a_request_can_only_name_a_path() {
        assert!(check_request("/v1/guide/turn", &[("content-type", "application/json")]).is_ok());
        for bad in ["https://evil.example/x", "//evil.example/x", "v1", "/x\r\nHost: evil", "/x@evil", "/x y"] {
            assert!(check_request(bad, &[]).is_err(), "{bad}");
        }
        assert!(check_request("/x", &[("Host", "evil.example")]).is_err());
        assert!(check_request("/x", &[("x-a", "b\r\nHost: evil")]).is_err());
    }

    /// No network: an address that can never exist fails as a network failure, quickly,
    /// after the capped retries - and nothing is delivered.
    #[test]
    fn no_network_is_a_clean_failure() {
        let d = Door::open("https://hideout-offline-check.invalid", "Hideout-test").unwrap();
        let t = std::time::Instant::now();
        let mut got = 0;
        let r = d.post("/v1/guide/turn", &[("content-type", "application/json")], b"{}", &mut |b| {
            got += b.len();
            true
        });
        assert!(matches!(r, Err(Fail::Network(_)) | Err(Fail::Timeout)), "{r:?}");
        assert_eq!(got, 0);
        assert!(t.elapsed().as_secs() < 60, "retries are capped");
    }
}
