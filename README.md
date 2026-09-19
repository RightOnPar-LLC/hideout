# Hideout

**https://hideout.meshtool.ai** — the website (source in `site/`: static files, no cookies, no tracking).

Finds where malware hides on a Windows PC. **Double-click `Hideout.cmd`**: it scans,
writes one report page, and opens it. It only looks. It never deletes, moves,
disables, runs or uploads anything.

## What it checks

Everything set to start by itself (scheduled tasks, Run keys, Startup folders,
services). It keeps the **programs** that live in folders any user can write to
(ProgramData, AppData, Temp, Downloads, Public), then checks each folder for
**signed-binary sideloading**: a trusted, signed program next to planted DLLs.

| Sign | Weight |
|---|---|
| A file changed after it was signed (`HashMismatch`) | 5 |
| The program itself unsigned | 3 |
| Unsigned DLLs beside a signed program | 2 |
| Signed by a vendor with nothing installed on this PC | 2 |
| Machine-made folder name (`kLmQzRtPx8`) | 1 |
| Large data files dressed as media (`.raw`, `.wav` …) beside code | 1 |

5+ = **Threat**, 3–4 = **Suspicious**, 2 = **Worth a look**. Folders that a
registered installer owns ignore the weak signs (apps ship unsigned helpers all the
time). A tampered file always counts. Scripts and Store-app aliases are skipped: they
are never signed, so checking them would only be noise.

**Not checked is never shown as clean.** If a program can't be checked, the report
says so.

## Why it exists

It was built after a real find: a logon task running a genuinely vendor-signed EXE from a
randomly named folder under `C:\ProgramData`. One sibling DLL failed its signature, three
were unsigned, and payload blobs were dressed as `.raw` / `.wav` files. The antivirus had
been on the whole time, for months, and never flagged it. Hideout reports it as a Threat
with all five signs, and on that same PC it reports nothing else out of 465 start-up
items. Signed-binary sideloading like this is a common way infostealers are delivered.

## Run it

- `Hideout.cmd`: scan and open the report (right-click → Run as administrator to
  include system-level tasks).
- `pwsh -File hideout.ps1 -Json`: findings as JSON.
- Works in PowerShell 7 and Windows PowerShell 5.1. No installs, no network.

## The desktop app (`app/`)

Hideout as an app: a window with the PC's status on the left and the **Hideout Guide** on
the right - an AI assistant (powered by Claude) that walks people through a malware or
scam scare in plain words, one step at a time.

- **Worker** - runs the engine as background jobs (quick scan, deep check, deep check
  with admin via a Windows prompt), live progress, one at a time. Read-only.
- **Guide** - eleven tools: six for the PC (read scan, run scan, start deep check, read
  deep-check summary, read the case file, tick a recovery step) and five for Money (below);
  no tool can change the PC. Sees only redacted data (no account, profile or PC name, no
  token-shaped strings). Reaches Claude through a gateway (below), or directly with
  `ANTHROPIC_API_KEY` on a developer's own machine. Without either, scans still work and
  the guide says it isn't connected.
- **Locked-down local server** - 127.0.0.1 on a random port, per-launch session key,
  Host + Origin checks, strict CSP; exits when the window closes.
- **Private brain (case file)** - each PC gets its own encrypted memory: the
  cognitive-mcp engine, run as a child process, with its own file under
  `%LOCALAPPDATA%\Hideout\brain` and its key **sealed by that PC's TPM**. It remembers
  scans, deep checks and 13 recovery steps; the guide reads it at the start of a chat and
  ticks steps off as the person reports them. Nothing leaves the PC. (Not the default
  "keystore" key mode: that uses one fixed Credential Manager slot for every cognitive-mcp
  store on a PC, so a second store would share another app's master key.) The engine is
  optional at build time (`HIDEOUT_BRAIN_EXE`); without it Hideout runs with memory off.
- **Network lock** - the app can open exactly one https host: the gateway (or
  api.anthropic.com in direct mode). Everything else is refused before a byte leaves.
- **Guide gateway** (`gateway/`) - a small Node service that holds the Claude key so no
  user's PC does. It enforces the guide spec itself (a client sends only the
  conversation), hands each install a signed pass, and caps usage: 60 turns/install/day,
  5 new installs/IP/day, one question at a time, and a daily dollar budget
  (`DAILY_BUDGET_USD`, default $5). It keeps counters only, never conversations. Run your
  own (`ANTHROPIC_API_KEY`, `GATEWAY_SECRET`, `DATA_DIR`), then build with its address in
  `HIDEOUT_GATEWAY_URL` or `app/gateway-url.txt` (git-ignored).
- **Money** (second tab) - import a statement downloaded from the bank's website (CSV;
  Chase, Amex, Capital One, Bank of America and Wells Fargo layouts are tested). Hideout
  shows every repeating charge (how often, per month, price rises), flags any company
  **STILL CHARGING** after the date the person says they cancelled (with an "act by" date
  for a bank dispute), and lists money sent and new companies since the day things went
  wrong. The guide gets five more tools: read the Money summary, record the incident date,
  record a cancellation, show a company's cancel steps (the vendor's own steps, the traps
  named in advance, and a button to the vendor's real cancel page from Hideout's checked
  directory), and hand over a drafted letter (refund request, cancel-by-email, bank
  dispute) as a card with Copy / Open-in-email. **Hideout never logs in, cancels or sends
  anything** - the person clicks and sends. Statements live only in the private brain;
  "Forget my statements" deletes them. Installed programs are read (never changed) to show
  "on your PC and on your bill" and remote-access tools a scammer may have left.
  Directory: `app/data/merchants.json` (46 consumer companies with the vendor pages each
  entry came from, plus 41 developer services). Provenance: `app/src/money/FOLDED-FROM.md`.
  Refund odds and "act by" dates are general information, not legal or financial advice.

Run: `node app/src/main.mjs` (dev) or build one file with
`powershell -File app/build-exe.ps1` -> `app/dist/Hideout.exe` (unsigned: sign it before
giving it to anyone). Tests: app 66, money 69, engine 23, gateway 20 - all four gate the build.

## Tests

`pwsh -File tests\selftest.ps1`: 23 checks. They build a fake sideloading folder from
real signed files (one with a single flipped byte, so its signature is a real
`HashMismatch`), check the verdicts and the report's escaping, and prove the engine
has no delete/move/run commands. Negative controls: removing tamper detection or
HTML escaping turns the matching checks red.
