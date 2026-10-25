# Phase 1 report: skeleton, single binary, parity harness

Status: **READY FOR REVIEW. The gate is not fully met.** The clean-VM and dirty-VM parity runs did not happen (see *What is not done*). Everything else on the gate is met, with evidence below.

## What changed

A Rust workspace in `rust/` builds one binary, `hideout.exe`. It runs no Node and no PowerShell.

| crate | what it is |
|---|---|
| `hideout` | The app. It runs the loopback server, the background worker, the window and the single-instance pipe, plus `hideout scan` on the command line. |
| `hideout-win` | The only crate that talks to Windows directly, and the only one with `unsafe`. Everything in it is read-only: Authenticode (catalog and embedded), the registry, services, Task Scheduler, WMI, shortcuts, known folders, time, the admin check and the named pipe. |
| `hideout-scan` | The quick scan: a line-by-line port of `hideout.ps1`'s rules and of its JSON shape. |
| `hideout-parity` | A developer tool that is never shipped. It runs the PowerShell engine and the Rust engine on the same PC and fails on any difference nobody has explained. |
| `hideout-redact`, `hideout-money`, `hideout-guide` | Placeholders for Phases 4 and 5. They are empty on purpose. |

The binary serves the existing `app/ui/index.html` unchanged. It applies `server.mjs`'s rules in the same order:
- It binds a random `127.0.0.1` port.
- Each launch gets a fresh 256-bit key, handed over once at `/launch` and kept in an HttpOnly, SameSite=Strict cookie.
- The Host header must be exact, and a wrong one gets 421.
- Every POST needs the same origin and JSON.
- Bodies are capped at 64 KB, and statement imports at 3 MB.
- Oversized uploads are read to the end first, so the sender gets a real 413 instead of a dropped connection.
- The page carries the strict CSP.
- The app exits once its window has been closed for 90 seconds.

The deep check, Money and the guide answer exactly the way a build without them does today. The deep check says plainly that it is not in this build yet; it never shows a fake result.

`--print-url`, the launch key and the single-instance pipe name all match `main.mjs`. The Rust and Node builds share one data folder and never run at the same time.

## Dependencies (every one has a reason)

| crate | why |
|---|---|
| `serde`, `serde_json` | Reports, the local API and the targets file are all JSON. |
| `regex` | The scan rules are regular expressions taken word for word from the PowerShell engine. Hand-porting them is how parity breaks quietly. The engine runs in linear time, so names chosen by malware cannot make it backtrack forever. |
| `windows` (Microsoft) | Windows APIs. Only `hideout-win` uses them. |

`cargo audit` checked 38 crates against 1352 advisories and found **0 vulnerabilities**. `cargo clippy --workspace --all-targets -D warnings` is clean.

The binary has no HTTP library, no async runtime and no crypto crate. Randomness and SHA-256 come from Windows' own CNG.

## Gate evidence

| gate item | result |
|---|---|
| `cargo test` green | **59 passed, 0 failed.** That is 25 in `hideout-win`, 8 in `hideout-scan`, 20 in `hideout`, and 6 in `hideout-parity` (including its negative controls). |
| Parity, this PC (Windows 11 26200, not elevated) | **0 unexplained differences.** All 462 of PowerShell's start items match one for one. Rust finds 4 more, each explained by a known difference and proven by the harness (see below). Both engines report 0 findings, the same Defender status and the same counts once the explained items are taken out. |
| Parity, planted fixtures | **10 of 10 expected verdicts on both engines, 0 unexplained.** The fixtures are built from a real signed file on the PC: the real-case replica (Tampered file, Unsigned DLLs, Random folder, Hidden payload, rated high), tampered-only, an unsigned neighbour, a payload alone, a random folder alone, an orphaned signer, an unsigned program, a clean folder, and a hidden tampered DLL. Rust catches the hidden tampered DLL as high. PowerShell never sees it. |
| Parity, clean and dirty VM | **NOT RUN.** See below. |
| Zero secrets in the binary | **Passes, and is enforced.** No key, token or private-key shapes appear in the strings. The first build *did* carry the build machine's home path and user name in about 150 panic locations. `rust/build-release.ps1` now remaps those paths, then re-reads the finished binary and fails the build if a home folder, user name or machine name is left. That check has its own negative control (`-SelfTest`). |
| The UI loads from the Rust server as today | **Passes.** It was opened live in a browser: the first scan ran by itself and showed 466 items, 10 in user folders, Defender on, "Nothing hiding". Scan again worked. The deep check showed its honest "not in this build" message. There were no console errors. |

### Signature calibration

Before any verdict code was written, the Rust Authenticode check ran against `Get-AuthenticodeSignature` on 1030 files. Those included system files, drivers, program files, user-folder programs, a flipped-byte copy, random bytes, empty and text files, and scripts. **1025 were identical.**

The other 5:
- **Two missing paths:** PowerShell throws an error. Rust reports `FileMissing`, which counts as not checked and never as clean.
- **One console-encoding artifact:** it happens only in the calibration pipe.
- **Two dual-signed .NET DLLs:** Windows hands back the other certificate of the pair as the signer. Both answers are Valid, and the organization the scan uses is the same.

The check never goes online. Revocation checks are off, as in PowerShell, and certificates come from the cache only.

### Explained differences (Rust is right in each)

| id | what PowerShell did |
|---|---|
| `ps-prefixed-run-value` | It skipped any Run or RunOnce value whose name starts with "PS". |
| `hidden-startup-file` | It never looked at hidden files in the Startup folders. |
| `hidden-file-in-program-folder` | It never looked at hidden DLLs or payloads beside a program. |
| `wmi-empty-service-path` | It skipped services whose WMI `PathName` comes back empty. On this PC those are `LSM` and `NetSetupSvc`; `sc qc` reads them fine. |

The harness proves each one before it accepts it: the file really is hidden, or WMI really does return an empty path. Totals are compared only after the explained items are taken out.

## Numbers

| | target | measured |
|---|---|---|
| Binary size | under 15 MB | **1.95 MB** (the Node exe is 104.5 MB) |
| Cold start (to a ready server and launch URL) | under 1 s | **0.36–0.38 s.** A bare `hideout.exe --version` takes 0.39–0.44 s on this PC, so nearly all of it is Windows starting a process. The first launch of a newly built exe took 1.6 s, most likely antivirus looking at a binary it hasn't seen before. |
| Idle RAM | under 50 MB | **26.8 MB working set, 7.1 MB private** |
| Quick scan, this PC | (Phase 2 target: under 2 s) | 6.9 s for Rust against 11.8 s for PowerShell. Not yet optimised; that is Phase 2's job. |

## What is not done

- **The clean-VM and dirty-VM runs.** `rust/sandbox/run.ps1` and `inside.ps1` are written. They start Windows Sandbox with networking off and the repo mapped read-only. The dirty mode plants the real-case replica the way malware would (a logon task, a service, two Run values, one of them named "PS...", and a hidden program in Startup), then runs both engines. On the build PC, Windows Sandbox would not cooperate. The `wsb` command line fails to start any sandbox (`0x80070780`), and the classic launcher opens a sandbox whose logon command never runs. **To finish the gate:** run `rust\build-release.ps1`, then `rust\sandbox\run.ps1 -Mode clean` and `-Mode dirty`, on a PC where Windows Sandbox works, or in any throwaway Windows VM by running `inside.ps1` there directly.
- Hidden files are a deliberate fix (see the table above). Some other quirks of `hideout.ps1` are kept on purpose until Phase 2 decides:
  - The folder verdict is cached per folder, so a second program in the same folder gets the first one's verdict.
  - The signer is read from the subject by an unanchored `O=` pattern.

## How to check this yourself

```
cd rust
cargo test --workspace
powershell -File build-release.ps1
target\release\hideout-parity.exe quick
target\release\hideout-parity.exe fixtures
```
