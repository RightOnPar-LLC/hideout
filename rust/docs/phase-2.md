# Phase 2 report: start-up persistence, read natively

Status: **READY FOR REVIEW. The gate is met except for the dirty-VM run, and the speed stretch goal is not met.** Details below.

## What changed

**The whole start-up surface** (`hideout-scan/src/autostart.rs`), read without PowerShell, with every item tagged by its source:

| source | what is read |
|---|---|
| Scheduled tasks | program actions, looking through rundll32, regsvr32, mshta and the script hosts, plus **COM-handler actions** resolved to their DLL |
| Run keys | Run, RunOnce, RunServices, RunServicesOnce and Policies\Explorer\Run, for the machine (64-bit and 32-bit) and for **every loaded user**, not only the current one |
| Startup folders | this user's, all users', and **every other profile's** |
| Services | each service's program, plus its **ServiceDll** when svchost hosts it |
| **Drivers** | their files, including the kernel-style paths (`\SystemRoot\`, `\??\`, `System32\`) |
| **Winlogon** | Shell, Userinit and Taskman, for the machine and the user |
| **Image File Execution Options** | debuggers that take over a program |
| **SilentProcessExit** | monitors that run when a program exits |
| **AppInit_DLLs, AppCertDlls** | DLLs loaded into other programs |
| **LSA packages** | authentication, security and notification packages |
| **Active Setup** | StubPath commands |
| **User COM overrides** | per-user CLSID registrations, which take priority over the machine's |
| **WMI event consumers** | program consumers and **script** consumers |
| **Browser policy** | extensions force-installed by Chrome, Edge or Brave policy |

A source that can't be read appears in `checked.sourcesNotRead`; it is never skipped quietly. Reading WMI subscriptions usually needs admin rights.

**Facts on every program** (`facts()`):
- whether it exists, or is there but closed to Hideout (Store apps' protected folder);
- the bare name resolved the way Windows resolves it (System32, then Windows, then PATH);
- signature state and signer;
- created and modified dates;
- PE headers: program, library or not a program, plus bytes appended after the last section;
- SHA-256 for programs in user-writable folders (up to 64 MB).

**A safe PE header reader** (`pe.rs`). Every offset is bounds-checked. It survives a 20,000-input mutation fuzz test with no panics.

**One new check, "Program dressed as media":** a .wav, .raw, .dat or similar file beside a program whose header shows it is really a Windows program. It adds 3 points, rated medium on its own, and applies only where no installer claims the folder (the same rule as the other weak signals).

**Per-item verdicts.** `items[]` gives each start-up item one of `threat`, `worth-a-look`, `clean` or `could-not-check`, with its reason chips and its facts. The mapping:
- high is threat;
- medium and low are worth-a-look;
- checked with nothing flagged is clean;
- program missing, or present but not readable, is could-not-check (never clean).

The findings list keeps exactly today's shape, so the window and the guide read it unchanged. A single weak signal (a random folder name alone, or one large data file alone) stays a chip on a clean item, as today. That keeps false alarms down.

**Speed:**
- Signature checks run in parallel, and each file is checked once per scan through a shared cache.
- Windows' signature verifier stops scaling past about 8 threads, measured at 1, 4, 8, 16 and 32. More threads only add contention, so the pool is capped at 8.
- The signature check now verifies the embedded signature before looking up the catalog. Both read the whole file, and doing the likely one first halves the work for signed programs. The SHA-1 catalog fallback was dropped because it never changed an answer in calibration.

## Gate evidence

| gate item | result |
|---|---|
| Parity with PowerShell on the real-case fixture (1 threat, same chips, same path) | **Passes.** F1 is rated high with Tampered file, Unsigned DLLs, Random folder and Hidden payload, on the same path, on both engines. |
| Synthetic set, one planted variant per trick | **12 of 12 expected verdicts on both engines, 0 failures, 0 unexplained.** The set: tampered, unsigned neighbour, payload alone, machine-made folder alone, orphaned signer, unsigned program, clean, a hidden tampered DLL (Rust only), a program dressed as media both above and below 100 KB (Rust only), and the same folder reached through a second start item. |
| No miss, no extra flag | **Passes.** Nothing outside the expected set was flagged on either engine. |
| No false positives on the clean set | **This PC: 1282 start items, 0 findings.** That includes 820 items only Rust reads. PowerShell finds 0 among its 462. |
| A file changed after signing is caught even with a trusted signer | **Passes.** F2 is a Microsoft-signed program with one byte flipped: HashMismatch, Tampered file, rated high. |
| `cargo test` | **72 passed.** clippy `-D warnings` is clean. |
| Dirty VM | **NOT RUN.** Windows Sandbox would not run on the build PC; see the Phase 1 report. |

### Explained differences, added in this phase

| id | why the Rust engine differs |
|---|---|
| `wider-surface` | Rust reads the places `hideout.ps1` never read (the table above). Each such target carries `scope: "wider"`, and the harness accepts a Rust-only item only when it is tagged that way. |
| `new-check` | Reasons only Rust gives ("Program dressed as media"). A finding is accepted only if, with those reasons taken out, it equals PowerShell's, or if what is left would not have made a finding at all. |

The harness also catches its own mistakes. A negative control found a bug: a severity change with identical reasons was being marked "explained". It was fixed in Phase 1, and every new explanation follows the same rule: something must actually differ, and the difference must be traceable to the stated cause.

### Known difference in signer naming

The embedded signature is now read before the catalog, which is PowerShell's order reversed. For a file that is both embedded-signed and listed in a catalog, the signer can come from the other certificate. Both answers are Valid. The folder check uses only the organization name, and none of the 12 fixtures or the 1282 items on this PC changed verdict.

## Numbers

| | target | measured on the build PC |
|---|---|---|
| Quick scan | under 2 s on the 465-item case | **Not met.** The full scan (1282 items, facts on about 900 programs) takes 3.5 s on a quiet machine and 9 to 10 s with other work running. PowerShell takes 12 to 24 s under the same conditions while reading 462 items. Planted fixtures take 0.3 s against 5.2 s. The floor is Windows' signature verifier: two installed apps on this PC carry about 1300 DLLs that must each be verified in full, and the verifier stops scaling at about 8 threads. **A real fix means hashing the files ourselves in parallel and checking the signed digest**, which is a large, security-critical change and belongs to a later phase rather than this one. |
| Binary | under 15 MB | 2.1 MB |

## What is not done

- The dirty-VM run.
- The quick scan under 2 s (see above).
- The window does not show `items[]` yet. The UI is unchanged in this phase on purpose; it is the same page the Node app serves.
