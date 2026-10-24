//! Certificates in a system store (Root, AuthRoot ...), opened read-only. A root
//! certificate someone added lets them read "secure" connections; Hideout lists them.

use crate::authenticode::cert_name;
use crate::wide::Wide;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertGetCertificateContextProperty, CertOpenStore, CERT_CONTEXT,
    CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_SHA1_HASH_PROP_ID, CERT_STORE_OPEN_EXISTING_FLAG,
    CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    pub subject: String,
    pub issuer: String,
    /// UTC FILETIME ticks.
    pub not_before: u64,
    pub not_after: u64,
    /// SHA-1 of the certificate, upper-case hex (what Windows calls the thumbprint).
    pub thumbprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    LocalMachine,
    CurrentUser,
}

fn ticks(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

/// Every certificate in `location\name` ("Root", "AuthRoot", ...). Err if the store
/// cannot be opened; an absent store is an empty list.
pub fn list(location: Location, name: &str) -> Result<Vec<Cert>, String> {
    let loc = match location {
        Location::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
        Location::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
    };
    let w = Wide::new(name);
    let flags = CERT_OPEN_STORE_FLAGS(loc | CERT_STORE_READONLY_FLAG.0 | CERT_STORE_OPEN_EXISTING_FLAG.0);
    // SAFETY: system-store provider with a NUL-terminated store name; read-only open.
    let store = match unsafe { CertOpenStore(CERT_STORE_PROV_SYSTEM_W, CERT_QUERY_ENCODING_TYPE(0), None, flags, Some(w.pcwstr().0 as *const _)) } {
        Ok(s) => s,
        Err(e) if e.code().0 as u32 == 0x8007_0002 => return Ok(Vec::new()),
        Err(e) => return Err(format!("could not open {name}: {e}")),
    };
    let mut out = Vec::new();
    let mut prev: Option<*const CERT_CONTEXT> = None;
    loop {
        // SAFETY: enumeration hands back the next context and frees the previous one.
        let c = unsafe { CertEnumCertificatesInStore(store, prev) };
        if c.is_null() {
            break;
        }
        // SAFETY: `c` is a live context until the next enumeration call.
        unsafe {
            let info = &*(*c).pCertInfo;
            let mut hash = [0u8; 20];
            let mut len = hash.len() as u32;
            let thumb = if CertGetCertificateContextProperty(c, CERT_SHA1_HASH_PROP_ID, Some(hash.as_mut_ptr() as *mut _), &mut len).is_ok() {
                crate::crypto::hex(&hash[..len as usize]).to_ascii_uppercase()
            } else {
                String::new()
            };
            out.push(Cert {
                subject: cert_name(c, true),
                issuer: cert_name(c, false),
                not_before: ticks(info.NotBefore),
                not_after: ticks(info.NotAfter),
                thumbprint: thumb,
            });
        }
        prev = Some(c);
    }
    // SAFETY: closing the store we opened.
    unsafe {
        let _ = CertCloseStore(Some(store), 0);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_roots_are_listed() {
        let v = list(Location::LocalMachine, "Root").expect("root store");
        assert!(v.len() > 5);
        assert!(v.iter().all(|c| c.thumbprint.len() == 40));
        assert!(v.iter().any(|c| c.subject.contains("Microsoft")));
    }
}
