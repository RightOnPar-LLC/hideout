//! One Hideout per data folder. The first copy owns a named pipe; a second launch
//! connects, writes "show", and exits. The pipe refuses remote clients, and only ever
//! carries that one word.

use crate::wide::Wide;
use std::io::{Read, Write};
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};

/// Ask a running copy to show its window. True if it acknowledged within two seconds.
/// The caller stays connected until the acknowledgement, so the message cannot be lost
/// to a disconnect that races the running copy's read.
pub fn signal_existing(name: &str) -> bool {
    let Ok(mut f) = std::fs::OpenOptions::new().read(true).write(true).open(name) else { return false };
    if f.write_all(b"show\n").is_err() {
        return false;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut ack = [0u8; 1];
        let _ = tx.send(f.read_exact(&mut ack).is_ok() && ack[0] == b'k');
    });
    rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap_or(false)
}

pub struct Listener(HANDLE);
unsafe impl Send for Listener {}

impl Drop for Listener {
    fn drop(&mut self) {
        // SAFETY: we own the pipe handle.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Claim the pipe. None if another copy already owns it.
pub fn claim(name: &str) -> Option<Listener> {
    let w = Wide::new(name);
    // SAFETY: valid name; FIRST_PIPE_INSTANCE makes this fail if the pipe exists.
    let h = unsafe {
        CreateNamedPipeW(
            w.pcwstr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            16,
            64,
            0,
            None,
        )
    };
    if h == INVALID_HANDLE_VALUE || h.is_invalid() {
        return None;
    }
    Some(Listener(h))
}

impl Listener {
    /// Block until a second launch connects, then report it. Loops forever; run it on its
    /// own thread. Anything other than "show" is ignored.
    pub fn serve(self, mut on_show: impl FnMut()) {
        loop {
            // SAFETY: our pipe handle; synchronous connect/read into a local buffer.
            unsafe {
                let connected = ConnectNamedPipe(self.0, None);
                // ERROR_PIPE_CONNECTED (client raced in first) also counts as connected.
                let ok = connected.is_ok() || connected.as_ref().err().map(|e| e.code().0 as u32 == 0x8007_0217).unwrap_or(false);
                if ok {
                    let mut buf = [0u8; 16];
                    let mut n = 0u32;
                    if ReadFile(self.0, Some(&mut buf), Some(&mut n), None).is_ok() && buf[..n as usize].starts_with(b"show") {
                        on_show();
                        let _ = WriteFile(self.0, Some(b"k"), None, None);
                        let _ = FlushFileBuffers(self.0);
                    }
                }
                let _ = DisconnectNamedPipe(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_claim_fails_and_signal_arrives() {
        let name = format!("\\\\.\\pipe\\hideout-test-{}", crate::crypto::random_hex(6));
        let l = claim(&name).expect("first claim");
        assert!(claim(&name).is_none(), "a second copy must not claim the same pipe");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || l.serve(move || { let _ = tx.send(()); }));
        let mut ok = false;
        for _ in 0..50 {
            if signal_existing(&name) {
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(ok, "could not reach the listener");
        rx.recv_timeout(std::time::Duration::from_secs(3)).expect("show signal");
    }
}
