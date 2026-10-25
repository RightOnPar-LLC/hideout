//! TCP connections and listening ports, with the process that owns each one
//! (GetExtendedTcpTable). Read-only; nothing is opened, closed or sent.

use std::net::{Ipv4Addr, Ipv6Addr};
use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    /// Listen, Established, TimeWait, ...
    pub state: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub pid: u32,
}

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

/// The names Get-NetTCPConnection uses for MIB_TCP_STATE values.
fn state_word(s: u32) -> &'static str {
    match s {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTCB",
        _ => "Unknown",
    }
}

/// Ports are stored in network byte order in the low 16 bits.
fn port(p: u32) -> u16 {
    u16::from_be(p as u16)
}

fn table(af: u32) -> Result<Vec<u8>, String> {
    let mut size = 0u32;
    // SAFETY: size query with no buffer, then the call with a buffer of that size (plus
    // headroom for connections opened in between); retried if it grew again.
    unsafe {
        let _ = GetExtendedTcpTable(None, &mut size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
        for _ in 0..5 {
            let mut buf = vec![0u8; size as usize + 4096];
            let mut len = buf.len() as u32;
            let rc = GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut _), &mut len, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
            if rc == 0 {
                return Ok(buf);
            }
            if rc != 122 {
                return Err(format!("could not read the connection table (error {rc})"));
            }
            size = len;
        }
    }
    Err("the connection table kept growing while it was read".into())
}

/// Every IPv4 and IPv6 TCP connection and listener.
pub fn tcp() -> Result<Vec<Conn>, String> {
    let mut out = Vec::new();
    let b4 = table(AF_INET)?;
    let n = u32::from_le_bytes([b4[0], b4[1], b4[2], b4[3]]) as usize;
    let row = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    for i in 0..n {
        let off = 4 + i * row;
        if off + row > b4.len() {
            break;
        }
        // SAFETY: bounds checked above; read_unaligned copies the row out.
        let r: MIB_TCPROW_OWNER_PID = unsafe { std::ptr::read_unaligned(b4.as_ptr().add(off) as *const _) };
        out.push(Conn {
            state: state_word(r.dwState).into(),
            local_addr: Ipv4Addr::from(u32::from_be(r.dwLocalAddr)).to_string(),
            local_port: port(r.dwLocalPort),
            remote_addr: Ipv4Addr::from(u32::from_be(r.dwRemoteAddr)).to_string(),
            remote_port: port(r.dwRemotePort),
            pid: r.dwOwningPid,
        });
    }
    let b6 = table(AF_INET6)?;
    let n = u32::from_le_bytes([b6[0], b6[1], b6[2], b6[3]]) as usize;
    let row = std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
    for i in 0..n {
        let off = 4 + i * row;
        if off + row > b6.len() {
            break;
        }
        // SAFETY: as above.
        let r: MIB_TCP6ROW_OWNER_PID = unsafe { std::ptr::read_unaligned(b6.as_ptr().add(off) as *const _) };
        out.push(Conn {
            state: state_word(r.dwState).into(),
            local_addr: Ipv6Addr::from(r.ucLocalAddr).to_string(),
            local_port: port(r.dwLocalPort),
            remote_addr: Ipv6Addr::from(r.ucRemoteAddr).to_string(),
            remote_port: port(r.dwRemotePort),
            pid: r.dwOwningPid,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn something_is_listening() {
        let v = super::tcp().expect("tcp table");
        assert!(v.iter().any(|c| c.state == "Listen"), "Windows always listens on something (RPC 135)");
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        let v = super::tcp().unwrap();
        assert!(v.iter().any(|c| c.state == "Listen" && c.local_port == p && c.pid == std::process::id()), "our own listener, with our pid");
    }
}
