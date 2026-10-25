# Phase 5 report: the guide, redacted by construction

Status: **READY FOR REVIEW, stacked on Phase 4 (and the Stage 1 PRs).** Every Phase 5 gate item is met. One stretch item is not met: the latency budget couldn't be measured, because the live gateway's Claude key is refused (see "Found along the way"). Built at the owner's go ("Claude can start Phase 5"). It lands only after the earlier PRs are approved.

## What changed

**`hideout-redact`**: everything sent to the guide passes through here.
- **The type.** The guide's request is built only from `Clean` text, and only the redactor can make a `Clean`: there's no public constructor, no `From`, no `Default`, no `Deserialize`. Four `compile_fail` tests prove that code handing the guide a plain string does not build. A fifth, ordinary test proves those four fail for the right reason.
- **The redactor.** First, a line-for-line port of `redact.mjs`'s four rules: profile folders, the PC's name, account names, long tokens. On top of those it removes:
  - card numbers (grouped, or 13-19 digits that pass the Luhn check);
  - account and other long numbers (9+ digits, in text and as JSON numbers);
  - keys with known prefixes;
  - JWTs;
  - recovery phrases (12+ words from the BIP-39 list, which is checked against its published SHA-256);
  - private-key blocks;
  - email addresses (except the companies' own cancellation addresses from Hideout's directory);
  - passwords and one-time codes typed into the chat.
- **The person's display name** is added to the names it removes (`hideout-win/identity.rs`).

**`hideout-guide`**, a port of `guide.mjs` and `guide-spec.mjs`, plus what the plan asks for:
- **`spec`**: the model, the instructions and the 11 tools, compiled in from data files generated from `guide-spec.mjs`. The request is byte-identical to the JavaScript one, and every one of 111 tool-input validation cases gets the same answer.
- **`wire`**: the conversation by type. The person's words and every tool result are `Clean`; the model's own replies are kept byte-for-byte (thinking blocks and their signatures must go back unchanged); tool-call ids come from the model. A transport can send only an `Outbound`, which `Outbound::seal` makes by running the redactor one last time over every string. If anything it would remove is still there, nothing is sent.
- **`transport`**:
  - gateway (newline-delimited JSON, a per-install pass in `install.json` shared with the Node build, one re-install only on the gateway's own "unknown install");
  - direct (`ANTHROPIC_API_KEY` from the environment, held in memory only, the streamed answer rebuilt from its events).
  - Neither contains network code.
- **`guide`**: the loop, its 11 tools and the cards (cancel steps, letters). The address on a letter comes only from the directory, and only for a company that takes cancellations by email. On top of `guide.mjs`:
  - The first message of every conversation says, from code, in plain words: *"I'm an AI guide, powered by Claude, and I can be wrong."*
  - Talk of recovering money gets the second-scam warning, from code.
  - When the AI can't be reached, the offline guide answers.
- **`case`**: the 13-step case file and the website guide's **six-step tracker**. Each step is fed by the case file and by what the Money tab already knows, and the person can tick a step. A step with nothing to check reads "Not checked yet", never done.
- **`letters`**: the **letter builder**. A company becomes a letter: the amounts and dates come from the statement when Hideout has them, typed values otherwise, and everything unknown goes in `[brackets]` or a `[Confirm: ...]` line.
- **`checks`**: the website guide's **deeper checks**, read from what is already on the PC:
  - scam drift since the scam date (new start-up items, tasks, programs, deep-check changes);
  - small test charges ($2 or less, with the large charge after);
  - leaked secrets (rotate at the provider, then delete; never paste);
  - rogue AI and agents (AI, automation and remote-access tools, risky browser extensions);
  - evidence to keep;
  - browser drift.
- **`offline`**: the **offline guide**: steps, money, scan, letters and checklists with no network at all.

**`hideout-win`**:
- `https.rs` is **the one door out**: WinHTTP (Windows' own TLS) to ONE host fixed when the door is opened.
  - A request names only a path; there's no way to name another host.
  - Redirects are refused; TLS 1.2 or 1.3 only.
  - It has time limits, at most two retries (and only before any answer arrived), and an 8 MB answer cap.
- `identity.rs` collects who is on this PC (accounts, profile folders, display name, PC name).
- **`tests/read_only.rs`**: `lib.rs` has long promised this test; it did not exist until now. It scans the crate's shipped code for every Windows call that changes something or opens a connection, and lists each allowed use with its reason. Its negative control catches a planted call.

**`hideout-scan/leaks.rs`**: the leak look-up for the deeper checks.
- It looks in Desktop, Documents, Downloads and the start-up folders: two levels deep, at most 4,000 entries, and the first 512 KB of text-like files.
- READ-ONLY: the test checks the folder is byte-identical before and after.
- The person sees paths; the guide sees only what kind of secret, redacted.

**In the app** (`server.rs`, `guide_app.rs`, `app.rs`):
- `/api/chat` streams the guide; `/api/chat/reset` clears it.
- `/api/guide/step`, `/api/guide/letter` and `/api/guide/checks` are new, with the same cookie, origin and JSON rules as every other POST.
- `/api/state` reports `ai`, `aiMode` (`gateway`, `direct` or `offline`) and `model`, plus the tracker.
- The app does not quit while the guide is answering.

**The window** (`app/ui/index.html`, shared with the Node build, which does not send the new fields):
- The six steps, with "Mark done".
- "Run the deeper checks".
- Money's **"what changed since your first statement"** panel (Phase 4's data).
- Chat works in offline mode, with its own greeting that says it is not an AI.
- Only the two known card types are drawn.

**The release build** compiles in the gateway address from the git-ignored `app/gateway-url.txt`, the way the Node packager does. It is an address, never a key; without it, the build uses the offline guide.

## Gate evidence

| gate item | result |
|---|---|
| Redaction suite at 100% on the known secret shapes (cards, accounts, keys, tokens, seeds, emails, PC names) | **229 of 229** (`hideout-redact/tests/shapes.rs`), across 11 shapes: card 84/84, account 20/20, key 36/36, token 9/9, seed 15/15, email 9/9, PC name 8/8, account name 20/20, private key 4/4, password 12/12, code 12/12. For number shapes, not even the digits may survive with the separators removed. 15 ordinary sentences a person needs (amounts, dates, `••1746`, the directory's cancel address, "PIN" as a word) come through unchanged. |
| The guide's input type cannot carry personal data, and the compiler rejects it | Four `compile_fail` tests: `Clean(...)`, `.into()`, `serde_json::from_str`, `Default`. A compiling control proves they fail for the reason claimed. |
| A runtime redactor as a second layer, tested | `Outbound::seal` re-checks every string, including the tool results' JSON values. Tests show it refusing a model reply that carries an account number; the conversation then starts over instead of getting stuck. |
| Property tests: randomised personal data never survives to a guide request | **12,000 rounds**: random Luhn cards (plain, spaced, dashed), 9-17 digit accounts, five key families, JWTs, 12-24-word recovery phrases, emails, PC names, profile paths and typed passwords and codes, placed in the person's words, in a scan finding and in a statement line. Nothing survives, and a second pass finds nothing. Negative control: `redact.mjs`'s rules alone let a card through. |
| The port is faithful | **Differential, 20,003 texts through `redact.mjs` (Node) and Rust: the port (the four `redact.mjs` rules) differs on 0.** The full redactor differs on 2,871, all explained (below). Each explanation is proven by turning that one rule off: the outputs then agree. Three seeded cases must be caught and explained, or the run fails. |
| A captured guide request (with test data) | `hideout-parity guide-capture` ran one turn **through the real WinHTTP door to the live gateway**. It used a made-up person, PC, statement and scan, with a planted card, account and routing number, key, email, PC name and profile path. The exact bytes sent are in the capture file (header names only; the install pass is not written down). **Planted secrets found in what was sent: none.** The person's words went out as: *"I'm `<you>` on `<this-pc>`, my card is `[removed: card number]` and my email is `[removed: email]`."* The turn went no further because the gateway's Claude key is refused (see below). The full tool round trip with the exact bytes is covered against a fake gateway (`e1_...` test), where the redacted tool results cross the wire. **For Frank:** run `hideout-parity guide-capture --gateway https://<gateway> --out capture.json` and read `sent`. |
| Offline mode verified with the network off | **No transport:** the real app answered the steps, the money, the scan, letters and the deeper checks in the window, with no network code in the path. **No network:** the real app pointed at an address that can never resolve answered in 2.2 s with "I can't reach the AI guide right now", then the offline guide's answer from local data. WinHTTP failed exactly as it does with the cable out. **Not done here:** a run with the cable really pulled. This box runs the session that builds Hideout, so its own network can't go down. It's a one-minute check for Frank or the owner. |
| One door out (allow-listed host, TLS, timeout, retry cap) | `https.rs` tests: only `https://host[:port]`; a request names only a path (no `//host`, no scheme, no `@`, no CR/LF, no Host header); an address that can't exist fails cleanly, with capped retries and nothing delivered. The app logs only the mode, never an address or a key. |
| Direct mode only with an environment key, memory only, never logged | `guide_app::make_transport` reads `ANTHROPIC_API_KEY` from the environment into the transport. It is written only into the request header: never logged, saved or sent to the window. A test rebuilds a streamed answer (thinking signature, text, tool input in pieces, usage) into the final message. |
| The guide says it is an AI and can be wrong, on every first message | From code, not the model: tested on the first message, not repeated mid-conversation, said again after a reset. The window's greeting says it too. The offline guide says it is not an AI. |
| Six-step tracker, letter builder, second-scam warning, deeper checks | Tested in `case.rs`, `letters.rs`, `checks.rs`, `offline.rs` and `conversation.rs`, and checked live in the window. Ticking a step updates over the event stream. A dispute letter built offline from a statement shows the cancel date and the charge after it, with `[Confirm: ...]` and placeholders, and no address. |
| `guide.mjs`'s own tests | selftest G1-G15 and money.selftest G1-G9 and E1 are ported to `hideout-guide/tests/conversation.rs` and pass. |
| `cargo test` | **178 passed** (117 at Phase 4). clippy `-D warnings` is clean on every target, tests included (two older test-file findings fixed). `cargo audit` finds no vulnerabilities in 38 crates. **No new dependencies.** The release build's leak scan is clean (3.6 MB `hideout.exe`). |

### Differences from the JavaScript (each one a fix, each one proven)

| id | what |
|---|---|
| `new-shapes` | `redact.mjs` let card numbers, account numbers, short keys, emails, recovery phrases and typed passwords through unless they happened to be 28+ token characters. The Rust redactor removes them. |
| `spec-vocabulary` | `redact.mjs` turned the guide's own case-step id `windows_security_folder_scan` (28 characters) into `[redacted 28 chars]`, so the guide could not read that step back. Only the spec's own words are left alone. |
| `noise-names` | A profile folder named like an ordinary word ("user", "admin") is still replaced in a path, but not as a bare word, so "run from user folders" stays readable. |
| unanswered tool call | When `guide.mjs` hit its 6-round limit, it stopped with the model's tool calls unanswered. The history then ended on a tool call the next request can't follow. Rust answers them ("not run") before stopping. Tested. |
| memory | `guide.mjs` refuses `update_case_step` without the sealed brain. This build keeps the case file and tracker in the session and says so ("kept until Hideout closes"). The sealed memory is Phase 6. |
| no AI | `guide.mjs` answers "isn't connected". This build answers with the offline guide. |

## Found along the way

- **The live gateway's Claude key is refused.** The gateway takes the install pass, but its call to Claude comes back 401, so every guide turn fails with "The guide couldn't sign in". This happens for the Node build too (checked with a plain Node request). `/healthz` still reads ok, because it never calls Claude. Fixing it means setting a working key on the gateway service, which is the owner's call. Until then the guide runs as the offline guide wherever the gateway is configured, and the latency budget can't be measured. Neither of the two `ANTHROPIC_API_KEY` entries in the vault works as-is: one is refused, and the other needs a workspace ID.
- **The leak look-up's first live run** flagged saved-webpage script folders (`<page>_files`): copies of websites whose wallet scripts ship the whole recovery-word list. Those folders are now skipped, and a "recovery phrase" means a run of 12 to 24 words. Both changes are tested.

## Not done

- **Latency budget** (first word under 2 s on a normal connection): not measured, for the reason above. The door itself answered in 317 ms (first byte, live).
- **A run with the network cable really out**: see the gate table.
- **Memory sealed to the PC**, and joining the Rust brain: Phase 6.

The guide gives general information, not legal or financial advice, and says so.
