//! Authenticode: is this file signed, is the signature intact, and who signed it.
//!
//! This follows what PowerShell's Get-AuthenticodeSignature does, because the scan's
//! verdicts were built and tested on its answers:
//!   1. look the file's hash up in the system catalogs (how most Windows files are
//!      signed); if a catalog vouches for it, verify through the catalog;
//!   2. if there is no catalog, or the catalog answer is not Valid, verify the signature
//!      embedded in the file itself.
//!
//! The Windows error code is then turned into the same status names PowerShell uses
//! (Valid, NotSigned, HashMismatch, NotTrusted, NotSupportedFileFormat, Incompatible,
//! UnknownError), plus two of Hideout's own for files it could not open.
//!
//! One deliberate difference: Hideout never lets Windows go online while checking.
//! Revocation checks are off (as in PowerShell) and certificate retrieval is
//! cache-only (WTD_CACHE_ONLY_URL_RETRIEVAL). Hideout has exactly one door out, and
//! signature checking is not it.

use crate::wide::{from_wide, Wide};
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows::Win32::Security::Cryptography::{
    CertNameToStrW, CERT_CONTEXT, CERT_NAME_STR_REVERSE_FLAG, CERT_STRING_TYPE,
    CERT_X500_NAME_STR, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE,
};

/// The status names PowerShell's SignatureStatus enum uses, plus Hideout's own two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigStatus {
    Valid,
    NotSigned,
    HashMismatch,
    NotTrusted,
    NotSupportedFileFormat,
    Incompatible,
    UnknownError,
    /// The path is not a file (gone, or a folder). hunt.ps1 calls this FileMissing.
    FileMissing,
    /// The file exists but could not be opened to check (locked, access denied, a Store
    /// alias). hunt.ps1 calls this Unreadable.
    Unreadable,
}

impl SigStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SigStatus::Valid => "Valid",
            SigStatus::NotSigned => "NotSigned",
            SigStatus::HashMismatch => "HashMismatch",
            SigStatus::NotTrusted => "NotTrusted",
            SigStatus::NotSupportedFileFormat => "NotSupportedFileFormat",
            SigStatus::Incompatible => "Incompatible",
            SigStatus::UnknownError => "UnknownError",
            SigStatus::FileMissing => "FileMissing",
            SigStatus::Unreadable => "Unreadable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub status: SigStatus,
    /// The raw WinVerifyTrust result, kept for the phase reports and for "why".
    pub code: u32,
    /// The signer certificate's subject, formatted the way .NET formats
    /// X509Certificate.Subject ("CN=..., O=..., C=US"). Empty when there is no signer.
    pub subject: String,
    /// True when a system catalog (not the file itself) carried the signature.
    pub from_catalog: bool,
}

// Win32 error codes PowerShell maps (System.Management.Automation, SignatureHelper).
const NO_ERROR: u32 = 0;
const NTE_BAD_ALGID: u32 = 0x8009_0008;
const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
const CRYPT_E_BAD_MSG: u32 = 0x8009_200D;
const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;

/// The same mapping PowerShell uses. Everything not listed is UnknownError: that
/// includes an untrusted root (self-signed) and a subject Windows has no SIP for.
pub fn status_from_code(code: u32) -> SigStatus {
    match code {
        NO_ERROR => SigStatus::Valid,
        NTE_BAD_ALGID => SigStatus::Incompatible,
        TRUST_E_NOSIGNATURE => SigStatus::NotSigned,
        TRUST_E_BAD_DIGEST | CRYPT_E_BAD_MSG => SigStatus::HashMismatch,
        TRUST_E_PROVIDER_UNKNOWN => SigStatus::NotSupportedFileFormat,
        TRUST_E_EXPLICIT_DISTRUST => SigStatus::NotTrusted,
        _ => SigStatus::UnknownError,
    }
}

/// Check one file. Never fails: problems become a status.
pub fn check(path: &Path) -> Signature {
    if !std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false) {
        return Signature { status: SigStatus::FileMissing, code: 0, subject: String::new(), from_catalog: false };
    }
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Signature { status: SigStatus::Unreadable, code: 0, subject: String::new(), from_catalog: false },
    };
    let wpath = Wide::new(&path.to_string_lossy());
    // Order: the signature inside the file first, the catalogs second. Both checks read
    // the whole file, so doing the likely one first halves the work for the signed
    // programs a scan meets most. A file without an embedded signature fails that check
    // at once, before any hashing. (PowerShell asks the catalog first; the answer only
    // differs for a file that is BOTH embedded-signed and catalog-listed, where the two
    // may name different signers of the same publisher. See the phase report.)
    let emb = embedded(&file, &wpath);
    if emb.status == SigStatus::Valid {
        return emb;
    }
    match from_catalog(&file, &wpath, "SHA256") {
        Some(sig) if sig.status == SigStatus::Valid => sig,
        _ => emb,
    }
}

fn verify(data: &mut WINTRUST_DATA) -> (u32, String) {
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` is fully initialised for the union member its dwUnionChoice names,
    // and every pointer inside it outlives this call (owned by our caller's frame).
    let code = unsafe { WinVerifyTrust(Default::default(), &mut action, data as *mut _ as *mut _) } as u32;
    let subject = signer_subject(data.hWVTStateData);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closing the state WinVerifyTrust handed back, same action and data.
    unsafe { WinVerifyTrust(Default::default(), &mut action, data as *mut _ as *mut _) };
    (code, subject)
}

fn base_data() -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    }
}

fn embedded(file: &File, wpath: &Wide) -> Signature {
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wpath.pcwstr(),
        hFile: HANDLE(file.as_raw_handle()),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = base_data();
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous = WINTRUST_DATA_0 { pFile: &mut info };
    let (code, subject) = verify(&mut data);
    Signature { status: status_from_code(code), code, subject, from_catalog: false }
}

/// Some(..) only when a catalog on this PC lists the file's hash.
fn from_catalog(file: &File, wpath: &Wide, alg: &str) -> Option<Signature> {
    let mut admin: isize = 0;
    let alg = Wide::new(alg);
    // SAFETY: out-pointer to a local; the algorithm name outlives the call.
    unsafe { CryptCATAdminAcquireContext2(&mut admin, None, alg.pcwstr(), None, None) }.ok()?;
    let result = (|| {
        let h = HANDLE(file.as_raw_handle());
        let mut len: u32 = 0;
        // SAFETY: size query (no output buffer), then the real call with a buffer of
        // exactly that size. The file handle is open for the whole scope.
        unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut len, None, None) }.ok()?;
        if len == 0 || len > 256 {
            return None;
        }
        let mut hash = vec![0u8; len as usize];
        unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut len, Some(hash.as_mut_ptr()), None) }.ok()?;
        // SAFETY: admin context and hash buffer are valid.
        let cat = unsafe { CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None) };
        if cat == 0 {
            return None;
        }
        let mut ci = CATALOG_INFO { cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32, wszCatalogFile: [0; 260] };
        // SAFETY: `cat` is a live catalog context from the enum call above.
        let got = unsafe { CryptCATCatalogInfoFromContext(cat, &mut ci, 0) };
        let sig = if got.is_ok() {
            let catalog_path = Wide::new(&from_wide(&ci.wszCatalogFile));
            // The member tag is the hash in upper-case hex, as the catalog stores it.
            let tag = Wide::new(&crate::crypto::hex(&hash).to_ascii_uppercase());
            let mut info = WINTRUST_CATALOG_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                dwCatalogVersion: 0,
                pcwszCatalogFilePath: catalog_path.pcwstr(),
                pcwszMemberTag: tag.pcwstr(),
                pcwszMemberFilePath: wpath.pcwstr(),
                hMemberFile: h,
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: len,
                pcCatalogContext: std::ptr::null_mut(),
                hCatAdmin: admin,
            };
            let mut data = base_data();
            data.dwUnionChoice = WTD_CHOICE_CATALOG;
            data.Anonymous = WINTRUST_DATA_0 { pCatalog: &mut info };
            let (code, subject) = verify(&mut data);
            Some(Signature { status: status_from_code(code), code, subject, from_catalog: true })
        } else {
            None
        };
        // SAFETY: releasing the context we were given, exactly once.
        let _ = unsafe { CryptCATAdminReleaseCatalogContext(admin, cat, 0) };
        sig
    })();
    // SAFETY: releasing the admin context acquired above, exactly once.
    let _ = unsafe { CryptCATAdminReleaseContext(admin, 0) };
    result
}

/// The leaf signer's subject from WinVerifyTrust's state, formatted like .NET's
/// X509Certificate.Subject (X.500, reversed: "CN=..., O=..., C=..").
fn signer_subject(state: HANDLE) -> String {
    if state.is_invalid() || state.0.is_null() {
        return String::new();
    }
    // SAFETY: `state` is the live state handle from a VERIFY call that has not been
    // closed yet; every pointer is null-checked before it is followed.
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return String::new();
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
            return String::new();
        }
        let cert: *const CERT_CONTEXT = (*(*sgnr).pasCertChain).pCert;
        cert_subject(cert)
    }
}

/// .NET-style subject string of a certificate context.
///
/// # Safety
/// `cert` must be null or a valid CERT_CONTEXT pointer for the duration of the call.
pub(crate) unsafe fn cert_subject(cert: *const CERT_CONTEXT) -> String {
    // SAFETY: forwarded to the caller's guarantee.
    unsafe { cert_name(cert, true) }
}

unsafe fn cert_name(cert: *const CERT_CONTEXT, subject: bool) -> String {
    // SAFETY: null-checked; the blob lives inside the certificate context.
    unsafe {
        if cert.is_null() || (*cert).pCertInfo.is_null() {
            return String::new();
        }
        let info = &*(*cert).pCertInfo;
        let blob = if subject { &info.Subject } else { &info.Issuer };
        let flags = CERT_STRING_TYPE(CERT_X500_NAME_STR.0 | CERT_NAME_STR_REVERSE_FLAG);
        let enc = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        let n = CertNameToStrW(enc, blob, flags, None);
        if n <= 1 {
            return String::new();
        }
        let mut buf = vec![0u16; n as usize];
        CertNameToStrW(enc, blob, flags, Some(&mut buf));
        from_wide(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sys(p: &str) -> PathBuf {
        PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join(p)
    }

    #[test]
    fn catalog_signed_windows_file_is_valid() {
        let s = check(&sys("System32\\notepad.exe"));
        assert_eq!(s.status, SigStatus::Valid, "{s:?}");
        assert!(s.subject.contains("Microsoft"), "{s:?}");
    }

    #[test]
    fn missing_file_is_file_missing_not_clean() {
        let s = check(Path::new("C:\\definitely\\not\\here\\x.exe"));
        assert_eq!(s.status, SigStatus::FileMissing);
    }

    #[test]
    fn a_folder_is_not_a_file() {
        assert_eq!(check(&sys("System32")).status, SigStatus::FileMissing);
    }

    #[test]
    fn unsigned_text_file_is_not_valid() {
        let dir = std::env::temp_dir().join(format!("hw-sig-{}", crate::crypto::random_hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("plain.txt");
        std::fs::write(&f, b"hello").unwrap();
        let s = check(&f);
        assert_ne!(s.status, SigStatus::Valid, "{s:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn code_mapping_matches_powershell() {
        assert_eq!(status_from_code(0), SigStatus::Valid);
        assert_eq!(status_from_code(0x800B_0100), SigStatus::NotSigned);
        assert_eq!(status_from_code(0x8009_6010), SigStatus::HashMismatch);
        assert_eq!(status_from_code(0x8009_200D), SigStatus::HashMismatch);
        assert_eq!(status_from_code(0x800B_0001), SigStatus::NotSupportedFileFormat);
        assert_eq!(status_from_code(0x800B_0111), SigStatus::NotTrusted);
        assert_eq!(status_from_code(0x8009_0008), SigStatus::Incompatible);
        // Untrusted root (self-signed) is UnknownError in PowerShell, not NotTrusted.
        assert_eq!(status_from_code(0x800B_0109), SigStatus::UnknownError);
    }
}
