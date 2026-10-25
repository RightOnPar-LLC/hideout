# Phase 3 report: the deep check, all 16 areas, natively

Status: **READY FOR REVIEW. This closes Stage 1 and needs the owner's sign-off before Stage 2.** The gate is met, except for the VM runs, which Windows Sandbox would not perform on the build PC (see Phase 1).

## What changed

- **`hideout-scan/src/hunt.rs`**: a native port of `hunt.ps1`.
  - It keeps the same 16 sections, the same names and the same item fields, so the window's deep-check view and the guide summary read it unchanged.
  - Each section reports `ok`, its items, how long it took, and why it failed when it did. A section that could not be read is never shown as "nothing found".
  - Command lines are never copied whole. They get behaviour flags, the URL hosts they name, and a redacted snippet. File contents are never copied.
- **New Windows reads in `hideout-win`**, all read-only:
  - certificate stores;
  - the TCP connection table with owning processes;
  - local users and the Administrators group, including whether an account is local, a Microsoft account, Azure AD or Active Directory, read the same way PowerShell's LocalAccounts module reads it;
  - the elevated launch for "Deep check (admin)";
  - streaming SHA-256, so files of any size are hashed without holding them in memory.
- **The app runs the deep check.**
  - "Deep check" runs in-process.
  - "Deep check (admin)" re-runs this same binary through Windows' consent prompt. There is no script on disk that could be swapped before it gets admin rights, and declining the prompt gives a clear message.
  - Every deep check is saved under `%LOCALAPPDATA%\Hideout\hunts`, summarized for the window and the guide, and compared with the previous one.
- **`hideout hunt [--out file] [--days N]`** runs the deep check from the command line with `hunt.ps1`'s switches.

## The 16 areas, plus 3 new ones

| # | area | what is read | test |
|---|---|---|---|
| 1 | hideout | the quick scan's findings (the whole start-up surface) | `every_area_reports_on_this_pc`; quick-scan fixtures (Phase 2) |
| 2 | scheduledTasks | every task: folder, state, author, date, hidden, run-as, run level, triggers, last run and result, actions (program, signature, flags) | `every_area_reports_on_this_pc` |
| 3 | services | every service: program, signature, start type, account, plus its ServiceDll for svchost services | `every_area_reports_on_this_pc`; parity |
| 4 | drivers | drivers outside the normal folders or not validly signed | `every_area_reports_on_this_pc` (the filter rule) |
| 5 | registryAutoruns | Run-family keys for the machine and every loaded user; Winlogon; IFEO debuggers and the silent-exit flag; SilentProcessExit; AppInit_DLLs; AppCertDlls; LSA packages; Active Setup; per-user COM overrides | `every_area_reports_on_this_pc` (LSA, all three lists); `describe_redacts_and_flags_like_hunt_ps1` |
| 6 | startupFolders | the all-users and every profile's Startup folder, shortcuts resolved, hidden files included | `every_area_reports_on_this_pc`; parity |
| 7 | wmiSubscriptions | event filters, consumers (with their class) and bindings | `every_area_reports_on_this_pc`; parity |
| 8 | defender | status, preferences and exclusions, detections, threats | `every_area_reports_on_this_pc` |
| 9 | rootCertificates | LocalMachine Root and AuthRoot, CurrentUser Root | `accounts_and_certificates_and_settings_read` |
| 10 | network | listening and outbound connections with process, path and signature, **linked to the start-up item behind the program** (`startsBy`) | `network_lists_our_own_listener_with_its_program` |
| 11 | processes | processes from user folders, not validly signed, or with a suspicious command line | `processes_flags_a_program_running_from_a_user_folder` |
| 12 | recentFiles | programs and scripts created in user-writable folders in the last N days | `recent_files_finds_a_new_unsigned_program` |
| 13 | powershellProfiles | every profile: size, date, hash, flags (never the text) | `every_area_reports_on_this_pc`; parity |
| 14 | browserExtensions | Chrome, Edge, Brave and Vivaldi extensions with risky permissions | `extension_permissions_are_read_from_the_newest_version` |
| 15 | hostsAndProxy | hosts file entries and proxy settings for every user | `hosts_file_entries_skip_comments_and_the_bom` |
| 16 | accounts | local users and Administrators members with their source | `accounts_and_certificates_and_settings_read` |
| + | securitySettings | firewall per profile (including policy overrides), UAC, antivirus products and whether they are on and up to date, Remote Desktop and network-level authentication | `accounts_and_certificates_and_settings_read`; `security_settings_rules` |
| + | remoteAccess | the 20 remote-support tools from the Money tab: installed, running, or set to start by themselves | `every_area_reports_on_this_pc` |
| + | browserSettings | homepage, startup pages, search engine (flagged when it is not a known one), bookmarks that look like a bank but aren't, and files *named* like a password export (the file itself is never opened) | `lookalike_banks`; `every_area_reports_on_this_pc` |

Also tested: `changes_find_added_and_removed_but_ignore_unread_sections` ("what changed since the last deep check"), `deep_check_gives_summary_and_changes` and `declined_admin_prompt_is_a_clear_failure` (the worker).

## Gate evidence

**Full parity with `hunt.ps1` on the build PC: 0 unexplained differences across all 16 sections.** The two deep checks ran back to back.

| section | hunt.ps1 | Rust | matched | explained |
|---|---:|---:|---:|---:|
| accounts | 10 | 10 | 10 | 0 |
| browserExtensions | 16 | 16 | 16 | 0 |
| defender | 1 | 1 | 1 | 0 |
| drivers | 3 | 7 | 3 | 4 |
| hideout | 0 | 0 | 0 | 0 |
| hostsAndProxy | 12 | 12 | 12 | 0 |
| network | 143 | 136 | 129 | 21 |
| powershellProfiles | 5 | 5 | 5 | 0 |
| processes | 128 | 129 | 128 | 1 |
| recentFiles | 682 | 682 | 682 | 0 |
| registryAutoruns | 37 | 37 | 37 | 0 |
| rootCertificates | 140 | 140 | 140 | 0 |
| scheduledTasks | 250 | 250 | 250 | 0 |
| services | 312 | 312 | 312 | 32 |
| startupFolders | 15 | 15 | 15 | 0 |
| wmiSubscriptions | 3 | 3 | 3 | 0 |

Every explained difference carries its proof, gathered by the harness right after both runs:

| id | count | why the Rust engine differs |
|---|---:|---|
| `changed-between-snapshots` | 19 | Connections and processes that changed in the seconds between the two checks. A process counts only if it is gone now or started after the first check began. |
| `wmi-empty-service-path` | 17 | WMI hands PowerShell a thin record for some services (no path, no account, start type "Unknown"). Rust reads the service manager. |
| `signer-source` | 15 | Files signed both inside themselves and through a Windows catalog. PowerShell names the catalog's signer (Microsoft, for hardware-certified drivers); Rust names the maker (the hardware vendor). Both are Valid. Proven by reading both signatures of each file. |
| `cim-driver-list-incomplete` | 4 | `Get-CimInstance Win32_SystemDriver` returns 463 drivers; WMI asked directly returns 467. The dropped ones are drivers whose file is missing, plus a filter driver. |
| `dual-stack-listener` | 3 | `Get-NetTCPConnection` shows only the IPv6 socket of a program that listens on both. |

Three real bugs were found and fixed through parity:
- Linked files were skipped in recent files.
- The hosts file's byte-order mark turned a comment into an entry.
- Large files (over 256 MB) came back "unreadable" instead of hashed.

The harness also caught its own sloppy listener rule before it could hide anything.

**Other gate items:**

| | target | measured |
|---|---|---|
| Deep check | under 30 s | **21.4 to 26 s** on the build PC, against 122 to 226 s for `hunt.ps1` (5 to 10x faster). |
| Every area reports could-not-check with a reason | yes | Yes. `every_area_reports_on_this_pc` fails if any area fails without a reason. |
| "What changed since the last deep check" | yes | Yes. Unread sections are never reported as "everything removed". |
| Coverage table, 16 of 16 named, each with a test | yes | See above. |
| `cargo test` | green | **92 passed.** clippy `-D warnings` is clean; `cargo audit` finds 0 vulnerabilities in 38 crates. |
| The UI shows the deep check | yes | Checked live: the window's Deep check button ran it, and all 16 areas rendered with their "to look at" counts. |
| Clean and dirty VM | both | **NOT RUN**, for the same Windows Sandbox reason as Phase 1. |
| Elevated deep check | works | The worker logic is tested with a fake runner, including the declined prompt. **The real Windows consent prompt has not been clicked through**, because it needs a person at the PC. |

## Stage 1 gate summary (for the sign-off)

- Phases 1, 2 and 3 are built. They are in PRs #6, #7 and the Phase 3 PR, stacked in that order.
- Parity with the PowerShell engine has **0 unexplained differences** on a real PC: the quick scan, the planted fixtures, and the deep check across all 16 areas.
- The Rust binary is 2.7 MB, needs no Node and no PowerShell, and is 3 to 10x faster.
- **Still needed before Stage 2:**
  1. The owner's sign-off.
  2. One clean and one dirty VM run, on a PC where Windows Sandbox works or in any throwaway Windows VM (`rust/sandbox/`).
  3. One click-through of "Deep check (admin)" at the PC.
  4. The quick scan's stretch target of under 2 s is not met (3.5 s); see the Phase 2 report.
