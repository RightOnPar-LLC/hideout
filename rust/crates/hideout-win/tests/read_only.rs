//! The promise in lib.rs, checked: no Windows call in this crate's shipped code changes
//! anything, and the only network code is the one-host door in https.rs.
//!
//! Each allowed use is listed with its file and the reason. Test modules are not shipped
//! and are skipped.

const FORBIDDEN: &[&str] = &[
    // files and folders
    "DeleteFile", "MoveFile", "RemoveDirectory", "SetFileAttributes", "WriteFile", "CopyFile", "ReplaceFile", "CreateHardLink", "CreateSymbolicLink",
    "fs::write", "remove_file", "remove_dir", "fs::rename", "fs::copy", "create_dir", "OpenOptions",
    // registry
    "RegSetValue", "RegSetKeyValue", "RegDeleteKey", "RegDeleteValue", "RegCreateKey", "RegRestoreKey", "RegLoadKey", "RegSaveKey",
    // services, tasks, processes
    "StartService", "ControlService", "DeleteService", "ChangeServiceConfig", "CreateService", "RegisterTask", "DeleteTask", "TerminateProcess", "CreateProcess", "ShellExecute", "Command::new", "WinExec",
    // accounts and security
    "NetUserAdd", "NetUserDel", "NetUserSetInfo", "NetLocalGroupAdd", "NetLocalGroupDel", "SetNamedSecurityInfo", "SetSecurityInfo", "AdjustTokenPrivileges",
    // network
    "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "InternetOpen", "URLDownload", "TcpStream", "UdpSocket", "TcpListener", "WSAConnect", "WSASocket", "getaddrinfo",
    // named pipes
    "CreateNamedPipe",
];

/// (file, call, why it is allowed)
const ALLOWED: &[(&str, &str, &str)] = &[
    ("pipe.rs", "CreateNamedPipe", "the single-instance pipe: a second launch can only say \"show\""),
    ("pipe.rs", "WriteFile", "the pipe's one-byte \"k\" acknowledgement, never a file"),
    ("pipe.rs", "OpenOptions", "a second launch opens the running copy's pipe (never a file) to say \"show\""),
    ("elevate.rs", "ShellExecute", "Deep check (admin): runs this same read-only program with admin rights, after the person clicks Yes"),
    ("https.rs", "WinHttpOpen", "the one door out, to the guide's host only"),
    ("https.rs", "WinHttpConnect", "the one door out, to the guide's host only"),
    ("https.rs", "WinHttpSendRequest", "sends the guide's redacted request on that door"),
];

/// Shipped code only: comments and everything from the test module on are dropped.
fn shipped(src: &str) -> String {
    let code = src.split("#[cfg(test)]").next().unwrap_or("");
    code.lines().map(|l| l.split("//").next().unwrap_or("")).collect::<Vec<_>>().join("\n")
}

fn violations(file: &str, src: &str) -> Vec<String> {
    let code = shipped(src);
    FORBIDDEN
        .iter()
        .filter(|call| code.contains(*call))
        .filter(|call| !ALLOWED.iter().any(|(f, c, _)| *f == file && c == *call))
        .map(|call| format!("{file}: {call}"))
        .collect()
}

#[test]
fn nothing_shipped_changes_the_pc_and_only_one_door_opens() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    let mut files = 0;
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.ends_with(".rs") {
            files += 1;
            found.extend(violations(&name, &std::fs::read_to_string(e.path()).unwrap()));
        }
    }
    assert!(files >= 20, "scanned {files} files");
    assert!(found.is_empty(), "calls that change the PC or open a connection:\n{}", found.join("\n"));
    // Every allowance is still needed (a stale allowance would hide a future use).
    for (f, c, why) in ALLOWED {
        let src = std::fs::read_to_string(dir.join(f)).unwrap();
        assert!(shipped(&src).contains(c), "{f} no longer uses {c} ({why}) - drop the allowance");
    }
}

/// Negative control: the scanner does catch a planted call, in any file but its allowed one.
#[test]
fn the_scanner_catches_a_planted_call() {
    assert_eq!(violations("registry.rs", "fn f() { RegSetValueExW(k, x) }"), vec!["registry.rs: RegSetValue"]);
    assert_eq!(violations("tasks.rs", "let s = std::net::TcpStream::connect(a);"), vec!["tasks.rs: TcpStream"]);
    assert_eq!(violations("crypto.rs", "unsafe { WinHttpConnect(s, h, 443, 0) }"), vec!["crypto.rs: WinHttpConnect"]);
    assert!(violations("https.rs", "unsafe { WinHttpConnect(s, h, 443, 0) }").is_empty());
    assert!(violations("crypto.rs", "// std::fs::write is fine in a comment\n#[cfg(test)]\nmod t { fn x() { std::fs::write(p, b) } }").is_empty());
}
