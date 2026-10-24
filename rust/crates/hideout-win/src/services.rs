//! Services and drivers, read from the Service Control Manager with enumerate/query
//! rights only (no start, stop, change or delete rights are ever requested).

use crate::wide::{from_pwstr, Wide};
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
    ENUM_SERVICE_STATUS_PROCESSW, ENUM_SERVICE_TYPE, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO,
    SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_DRIVER,
    SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Service {
    pub name: String,
    pub display: String,
    /// Win32_Service.State wording: Running, Stopped, Start Pending, ...
    pub state: String,
    /// Win32_Service.StartMode wording: Auto, Manual, Disabled, Boot, System.
    pub start: String,
    /// The account it runs as (Win32_Service.StartName).
    pub account: String,
    /// ImagePath exactly as the SCM holds it (may be "\SystemRoot\...", quoted, with args).
    pub path: String,
    pub pid: u32,
    pub service_type: u32,
    /// False when the configuration could not be read (access denied, gone mid-scan).
    pub config_read: bool,
}

struct Sc(SC_HANDLE);
impl Drop for Sc {
    fn drop(&mut self) {
        // SAFETY: we own the handle and close it once.
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Win32 services (what Win32_Service lists).
    Win32,
    /// Kernel and file-system drivers (what Win32_SystemDriver lists).
    Driver,
}

fn state_word(s: u32) -> &'static str {
    match s {
        1 => "Stopped",
        2 => "Start Pending",
        3 => "Stop Pending",
        4 => "Running",
        5 => "Continue Pending",
        6 => "Pause Pending",
        7 => "Paused",
        _ => "Unknown",
    }
}

fn start_word(s: u32) -> &'static str {
    match s {
        0 => "Boot",
        1 => "System",
        2 => "Auto",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    }
}

/// Every service (or driver) the SCM will list to this user. Err only if the SCM itself
/// cannot be opened - then the caller must report "could not check", never "clean".
pub fn list(kind: Kind) -> Result<Vec<Service>, String> {
    // SAFETY: local machine, default database, read-only access mask.
    let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE) }
        .map_err(|e| format!("could not open the service list: {e}"))?;
    let scm = Sc(scm);
    let ty: ENUM_SERVICE_TYPE = match kind {
        Kind::Win32 => SERVICE_WIN32,
        Kind::Driver => SERVICE_DRIVER,
    };
    let mut needed = 0u32;
    let mut count = 0u32;
    let mut resume = 0u32;
    let mut buf: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    loop {
        // SAFETY: buffer slice and out-pointers to locals; handle owned above.
        let r = unsafe {
            EnumServicesStatusExW(scm.0, SC_ENUM_PROCESS_INFO, ty, SERVICE_STATE_ALL, Some(&mut buf), &mut needed, &mut count, Some(&mut resume), PCWSTR::null())
        };
        let more = match &r {
            Ok(()) => false,
            Err(e) if e.code().0 as u32 == 0x8007_00EA => true, // ERROR_MORE_DATA
            Err(e) => return Err(format!("could not list services: {e}")),
        };
        let entry = std::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>();
        for i in 0..count as usize {
            // SAFETY: Windows wrote `count` structs at the start of `buf`; the strings
            // they point to live later in the same buffer. Read unaligned to be safe.
            let e: ENUM_SERVICE_STATUS_PROCESSW = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(i * entry) as *const ENUM_SERVICE_STATUS_PROCESSW) };
            let name = unsafe { from_pwstr(e.lpServiceName.0) };
            let display = unsafe { from_pwstr(e.lpDisplayName.0) };
            let st = e.ServiceStatusProcess;
            let mut s = Service {
                name,
                display,
                state: state_word(st.dwCurrentState.0).to_string(),
                pid: st.dwProcessId,
                service_type: st.dwServiceType.0,
                ..Default::default()
            };
            read_config(&scm, &mut s);
            if !s.config_read {
                // WMI's word for a start type it cannot read.
                s.start = "Unknown".into();
            }
            out.push(s);
        }
        if !more {
            break;
        }
        if needed as usize > 64 * 1024 * 1024 {
            return Err("service list too large".into());
        }
        buf = vec![0u8; needed as usize + 4096];
        count = 0;
    }
    Ok(out)
}

fn read_config(scm: &Sc, s: &mut Service) {
    let w = Wide::new(&s.name);
    // SAFETY: query-config right only.
    let Ok(h) = (unsafe { OpenServiceW(scm.0, w.pcwstr(), SERVICE_QUERY_CONFIG) }) else { return };
    let h = Sc(h);
    let mut needed = 0u32;
    // SAFETY: size query, then a buffer of that size, aligned for the struct.
    unsafe {
        let _ = QueryServiceConfigW(h.0, None, 0, &mut needed);
    }
    if needed == 0 || needed > 1 << 20 {
        return;
    }
    let words = (needed as usize).div_ceil(8);
    let mut buf = vec![0u64; words];
    let p = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
    if unsafe { QueryServiceConfigW(h.0, Some(p), (words * 8) as u32, &mut needed) }.is_err() {
        return;
    }
    // SAFETY: Windows filled the struct; its strings point inside `buf`, still alive.
    unsafe {
        let c = &*p;
        s.start = start_word(c.dwStartType.0).to_string();
        s.path = from_pwstr(c.lpBinaryPathName.0);
        s.account = from_pwstr(c.lpServiceStartName.0);
    }
    s.config_read = true;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_services_with_paths() {
        let v = list(Kind::Win32).expect("scm");
        assert!(v.len() > 50, "only {} services", v.len());
        let ev = v.iter().find(|s| s.name.eq_ignore_ascii_case("EventLog")).expect("EventLog service");
        assert!(ev.path.to_ascii_lowercase().contains("svchost"), "{ev:?}");
        assert!(ev.config_read);
    }

    #[test]
    fn lists_drivers() {
        let v = list(Kind::Driver).expect("scm");
        assert!(v.len() > 50, "only {} drivers", v.len());
    }
}
