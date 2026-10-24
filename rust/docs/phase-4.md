# Phase 4 report: Money, read on the PC, never uploaded

Status: **READY FOR REVIEW, stacked on the Stage 1 PRs.** Every Phase 4 gate item is met. The phase was built before the Stage 1 sign-off at the owner's request ("start next step"); it lands only after Stage 1 is approved.

## What changed

**`hideout-money`**, a line-by-line port of `app/src/money/*.mjs` with no `unsafe` and no network code at all:

| file | what |
|---|---|
| `statement.rs` | Reads a bank's CSV, tab or semicolon export: Chase, Amex, Capital One, Bank of America (with its summary block) and Wells Fargo (no header). Columns are found by header name or by what the cells hold, and the direction of money is decided per file. Long digit runs are masked to the last four the moment a line is read. Capped at 5,000 rows. |
| `directory.rs` | The 87-company directory (`app/data/merchants.json`, compiled in, one shared copy). It matches statement lines to companies and gives a stable key for unknown ones. A cancel page is used only if it is https on the vendor's own domain with no `user:password` part. |
| `analyze.rs` | Repeating charges (weekly, monthly, quarterly, yearly), monthly cost, price rises, STILL CHARGING after a cancel date with an "act by" date, money that left after the incident date, small new companies, transfers, and refund odds from the companies' own policies. |
| `money.rs` | The tab's state: import, cancel dates, incident date, forget, the window's view, the guide's trimmed view, cancel steps, installed programs and remote-access tools, plus **"what changed since the first statement"** (new payees, new subscriptions, price rises). |
| `js.rs` | The places JavaScript and Rust disagree, pinned down: what `trim()` treats as whitespace, day arithmetic, rounding, the median. |

**In the app:** the Rust server now serves `/api/money/import`, `/incident`, `/cancel`, `/steps`, `/open` and `/forget` with `server.mjs`'s rules:
- imports have their own 3 MB limit;
- every request needs the session cookie and the same origin;
- "open" uses only the directory's URL, never one from the request;
- "forget" needs `confirm: true`.

The window's state carries the Money view, and installed programs are read once in the background, read-only.

**Memory:** statements live for the session only. The window says so ("Memory is off - statements are only kept until Hideout closes"). The encrypted case file sealed to the PC is Phase 6.

## Gate evidence

| gate item | result |
|---|---|
| Golden fixtures from today's money tests, byte for byte on amounts, dates and odds | **Passes.** `rust/tools/money-golden.mjs` runs the JavaScript engine itself over the five bank layouts from `money.selftest.mjs` and writes `tests/golden.json`. Rust matches it exactly: all 5 parses, 5 analysis scenarios (plain, three cancels, incident date, installed programs, and the real 87-company directory), 28 helper inputs, all 87 shipped cancel links, and every directory match and key. A negative control proves the comparator catches a one-cent change. |
| Fuzz over the statement parser, 10k+ mutated inputs, zero panics | **Passes.** 12,000 mutated statements (a cargo test) with zero panics. Every row has a real date, a positive finite amount, a descriptor of at most 120 characters, and no surviving long number. A 20,000-row file is capped at 5,000 with a warning. |
| Differential fuzz against the JavaScript engine | **10,002 statements through both engines, 0 unexplained.** 10,000 are mutations of the five banks and 2 are seeded cases that must differ. All 10,000 mutations agree exactly. |
| Redaction: a statement with a full account number gives a guide summary with none of it | **Passes.** A statement carrying a card number, an account number, a routing number, a Zelle confirmation and a 16-digit account produces a guide view and a window view containing none of them. Not even the digits survive with spaces and dashes removed. The last four remain, so a person can still tell which is which. |
| Money endpoints | **Passes.** `server.mjs`'s checks H1–H7 run against the Rust server. |
| Shown in the window | Checked live: the Money tab rendered "1 company still charging you", $315.48 a month, 3 repeating charges, and $2,648.98 sent since the incident date. There were no console errors. |
| `cargo test` | **117 passed.** clippy `-D warnings` is clean; `cargo audit` finds no vulnerabilities in 38 crates. No new dependencies. |

### Differences from the JavaScript engine (each one a fix, each one proven)

| id | what |
|---|---|
| `full-month-names` | `statement.mjs` looked a month up by its first **four** letters, so "June 1, 2026", "July", "March" and "April" were unreadable and their rows were skipped. Rust uses the first three. The differential run accepts this only when shortening every full month name to three letters makes the two engines agree. |
| impossible dates | JavaScript's `Date.parse` rolls "2026-02-30" over to 2 March, so a cancel date or incident date that does not exist was accepted even though the message says "must be a real date". Rust refuses it. |
| price rises in "what changed" | The main view compares only a company's last two charges, as before. The new "what changed" view looks at every charge after the first statement, so a rise between earlier months is not missed. |

## Not done

- **Saving between sessions.** That is Phase 6 (memory sealed to the PC).
- **The guide's money tools** (`get_money_summary`, `mark_canceled`, `show_cancel_steps`, `offer_letter`). That is Phase 5. The guide still says it isn't connected.
- **The window's "what changed" panel.** The data is in `money.drift`; the page shows it once the UI work lands with the guide.

Refund odds and "tell your bank by" dates are general information, not legal or financial advice. The window and the guide already say so.
