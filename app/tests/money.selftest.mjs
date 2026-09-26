// Hideout Money selftest - offline. Statement fixtures are shaped like the real exports of
// five US banks (header names, sign conventions, BofA's summary block, Wells Fargo's
// missing header); the values are made up. One LIVE check stores a large statement in the
// real cognitive-mcp engine (TPM, temp dir) when it is present.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { fileURLToPath } from "node:url";
import { parseStatement, parseDelimited, parseAmount, parseDate, maskDigits, classify } from "../src/money/statement.mjs";
import { analyze, mergeRows } from "../src/money/analyze.mjs";
import { prepareMerchants, matchMerchant, merchantKey, safeCancelUrl, loadMerchants, REFUND_LIKELIHOOD, SUBSCRIPTION_CATEGORIES } from "../src/money/directory.mjs";
import { Money, packRows, unpackRows } from "../src/money/money.mjs";
import { parseInstalled, remoteToolsIn, INSTALLED_SCRIPT } from "../src/money/pc.mjs";
import { Guide, gatewayTransport } from "../src/guide.mjs";
import { MODEL, validateToolInput } from "../src/guide-spec.mjs";
import { makeRedactor, collectIdentity } from "../src/redact.mjs";
import { startServer } from "../src/server.mjs";
import { Brain } from "../src/brain.mjs";
import { createGateway } from "../../gateway/server.mjs";

const APP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
let pass = 0, fail = 0;
const check = (name, ok, detail = "") => { if (ok) { pass++; console.log(`  ok    ${name}`); } else { fail++; console.log(`  FAIL  ${name}  ${detail}`); } };
const src = (f) => fs.readFileSync(path.join(APP, f), "utf8");
const code = (f) => src(f).replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

// ------------------------------------------------------------------ fixtures (real bank layouts)
const CHASE_CARD = `Transaction Date,Post Date,Description,Category,Type,Amount,Memo
09/01/2026,09/02/2026,NETFLIX.COM,Entertainment,Sale,-15.49,
08/28/2026,08/29/2026,Payment Thank You-Mobile,,Payment,500.00,
08/15/2026,08/16/2026,SAFEWAY #1234,Groceries,Sale,-82.13,
08/01/2026,08/02/2026,NETFLIX.COM,Entertainment,Sale,-15.49,
07/22/2026,07/23/2026,SAFEWAY #1234,Groceries,Sale,-41.07,
07/01/2026,07/02/2026,NETFLIX.COM,Entertainment,Sale,-15.49,
07/05/2026,07/06/2026,"AMAZON MKTPL*2K3LM4, SEATTLE",Shopping,Sale,-23.50,
07/19/2026,07/20/2026,AMAZON MKTPL*9Z8Y7X,Shopping,Return,23.50,
`;
const AMEX = `Date,Description,Amount
09/05/2026,ADOBE *CREATIVE CLD SAN JOSE CA,59.99
09/10/2026,AUTOPAY PAYMENT - THANK YOU,-300.00
08/05/2026,ADOBE *CREATIVE CLD SAN JOSE CA,54.99
07/05/2026,ADOBE *CREATIVE CLD SAN JOSE CA,54.99
08/09/2026,UBER   *TRIP HELP.UBER.COM CA,18.20
`;
const CAPONE = `Transaction Date,Posted Date,Card No.,Description,Category,Debit,Credit
2026-06-03,2026-06-04,1234,SPOTIFY USA,Entertainment,11.99,
2026-07-03,2026-07-04,1234,SPOTIFY USA,Entertainment,11.99,
2026-08-20,2026-08-21,1234,CAPITAL ONE MOBILE PYMT,Payment/Credit,,200.00
2026-09-30,2026-09-30,1234,CORNER CAFE,Dining,4.50,
`;
const BOFA = `Description,,Summary Amt.
Beginning balance as of 07/01/2026,,"2,000.00"
Total credits,,"3,000.00"
Total debits,,"-1,500.00"
Ending balance as of 09/30/2026,,"3,500.00"

Date,Description,Amount,Running Bal.
07/01/2026,Beginning balance as of 07/01/2026,,"2,000.00"
07/12/2026,"NORTON *AP1234567890 NORTON.COM AZ","-99.99","1,900.01"
07/15/2026,"PAYROLL ACME CORP","1,500.00","3,400.01"
08/14/2026,"Zelle payment to JOHN DOE Conf# 5829301746","-1,500.00","1,900.01"
08/14/2026,"ANYDESK SOFTWARE GMBH","-49.00","1,851.01"
08/15/2026,"TECH SUPPORT SOLUTIONS LLC 8005551234 FL","-299.99","1,551.02"
09/15/2026,"TECH SUPPORT SOLUTIONS LLC 8005551234 FL","-299.99","1,251.03"
09/16/2026,"CHECKCARD 0916 GOOGLE *PLAY GIFT CARD","-500.00","751.03"
`;
const WELLS = `"09/02/2026","-9.99","*","","APPLE.COM/BILL 866-712-7753 CA"
"08/02/2026","-9.99","*","","APPLE.COM/BILL 866-712-7753 CA"
"08/10/2026","1200.00","*","","PAYROLL DEPOSIT"
"08/11/2026","-64.20","*","","SHELL OIL 57444"
"07/02/2026","-9.99","*","","APPLE.COM/BILL 866-712-7753 CA"
`;

const DIR = prepareMerchants([
  { provider: "netflix", name: "Netflix", category: "streaming", descriptorPatterns: ["NETFLIX"], domain: "netflix.com", cancelUrl: "https://www.netflix.com/cancelplan", cancelSteps: ["Sign in", "Account", "Cancel membership"], traps: [], refundLikelihood: "low", refundBasis: "No refunds for partial months.", cancelByEmail: null, software: [] },
  { provider: "spotify", name: "Spotify", category: "music", descriptorPatterns: ["SPOTIFY"], domain: "spotify.com", cancelUrl: "https://www.spotify.com/account/subscription/", cancelSteps: [], traps: [], refundLikelihood: "unknown", refundBasis: null, cancelByEmail: null, software: [] },
  { provider: "adobe", name: "Adobe", category: "software", descriptorPatterns: ["ADOBE"], domain: "adobe.com", cancelUrl: "https://account.adobe.com/plans", cancelSteps: ["Sign in", "Plans", "Cancel"], traps: ["Annual plan paid monthly: a fee after 14 days"], refundLikelihood: "decent", refundBasis: "Full refund within 14 days.", cancelByEmail: null, software: ["Adobe Creative Cloud"] },
  { provider: "norton", name: "Norton", category: "security-software", descriptorPatterns: ["NORTON"], domain: "norton.com", cancelUrl: "https://my.norton.com/", cancelSteps: [], traps: [], refundLikelihood: "good", refundBasis: "60-day money-back.", cancelByEmail: null, software: ["Norton 360"] },
  { provider: "apple", name: "Apple", category: "app-store", descriptorPatterns: ["APPLE COM BILL"], domain: "apple.com", cancelUrl: "https://support.apple.com/en-us/118428", cancelSteps: [], traps: [], refundLikelihood: "decent", refundBasis: "Request at reportaproblem.apple.com.", cancelByEmail: null, software: [] },
  { provider: "maxtest", name: "Max", category: "streaming", descriptorPatterns: ["MAX"], domain: "max.com", cancelUrl: "https://evil.example/cancel", cancelSteps: [], traps: [], refundLikelihood: "unknown", cancelByEmail: null, software: [] },
  { provider: "mailco", name: "MailCo", category: "software", descriptorPatterns: ["MAILCO"], domain: "mailco.com", cancelUrl: "http://mailco.com/cancel", cancelSteps: [], traps: [], refundLikelihood: "unknown", cancelByEmail: "cancel@mailco.com", software: [] },
]);

// ------------------------------------------------------------------ parsing
check("P1 amounts: $, commas, parentheses, trailing minus, currency words", parseAmount("$1,234.56") === 1234.56 && parseAmount("(15.99)") === -15.99 && parseAmount("15.99-") === -15.99 && parseAmount("USD 9.99") === 9.99 && parseAmount("abc") === null && parseAmount("") === null);
check("P2 dates: US slashes, ISO, month names; impossible dates refused", parseDate("09/01/2026") === "2026-09-01" && parseDate("9/1/26") === "2026-09-01" && parseDate("2026-09-01") === "2026-09-01" && parseDate("Sep 1, 2026") === "2026-09-01" && parseDate("01 Sep 2026") === "2026-09-01" && parseDate("02/30/2026") === null && parseDate("hello") === null);
check("P3 quoted fields with commas and doubled quotes", JSON.stringify(parseDelimited(`a,"b, c","say ""hi"""\n1,2,3`)) === JSON.stringify([["a", "b, c", 'say "hi"'], ["1", "2", "3"]]));
check("P4 card and account numbers are masked on the way in", maskDigits("Zelle Conf# 5829301746") === "Zelle Conf# ••1746" && maskDigits("card 4111 1111 1111 1111 x") === "card ••1111 x" && maskDigits("SHELL OIL 57444") === "SHELL OIL 57444");
{
  const c = parseStatement(CHASE_CARD);
  const nf = c.rows.filter((r) => /NETFLIX/.test(r.descriptor));
  check("P5 Chase card export: negative = spending, payment + return come in", c.format === "header" && nf.length === 3 && nf.every((r) => r.direction === "out" && r.amount === 15.49) && c.rows.find((r) => /Payment Thank You/.test(r.descriptor)).direction === "in" && c.rows.find((r) => /9Z8Y7X|••/.test(r.descriptor) && r.amount === 23.5 && r.direction === "in"));
  const a = parseStatement(AMEX);
  check("P6 Amex export: positive = spending (sign decided by the file, not assumed)", a.rows.filter((r) => /ADOBE/.test(r.descriptor)).every((r) => r.direction === "out") && a.rows.find((r) => /AUTOPAY/.test(r.descriptor)).direction === "in");
  const o = parseStatement(CAPONE);
  check("P7 Capital One Debit/Credit columns", o.rows.filter((r) => /SPOTIFY/.test(r.descriptor)).every((r) => r.direction === "out" && r.amount === 11.99) && o.rows.find((r) => /MOBILE PYMT/.test(r.descriptor)).direction === "in");
  const b = parseStatement(BOFA);
  check("P8 Bank of America: summary block skipped, header found below it, balance rows dropped", b.format === "header" && b.rows.length === 7 && !b.rows.some((r) => /Beginning balance/.test(r.descriptor)) && b.rows.find((r) => /Zelle/.test(r.descriptor)).amount === 1500 && b.rows.find((r) => /PAYROLL/.test(r.descriptor)).direction === "in");
  const w = parseStatement(WELLS);
  check("P9 Wells Fargo (no header): columns found from what the cells hold", w.format === "inferred" && w.rows.length === 5 && w.rows.filter((r) => /APPLE/.test(r.descriptor)).every((r) => r.direction === "out") && w.rows.find((r) => /PAYROLL/.test(r.descriptor)).direction === "in");
  check("P10 transfers, gift cards and card payments are told apart from merchants", classify("Zelle payment to JOHN") === "transfer" && classify("CHECKCARD GOOGLE *PLAY GIFT CARD") === "transfer" && classify("AUTOPAY PAYMENT - THANK YOU") === "payment" && classify("NETFLIX.COM") === "merchant");
  const junk = parseStatement("hello there\nthis is not a statement\n");
  check("P11 a file that isn't a statement says so plainly, reads nothing", junk.rows.length === 0 && /CSV/.test(junk.warnings[0] || ""));
  const tsv = parseStatement("Date\tDescription\tAmount\n2026-09-01\tNETFLIX.COM\t-15.49\n2026-08-01\tNETFLIX.COM\t-15.49\n");
  check("P12 tab-separated exports read the same way", tsv.rows.length === 2 && tsv.rows[0].direction === "out");
}

// ------------------------------------------------------------------ directory
check("D1 match by word, not by substring ('MAX' is not 'MAXWELL')", matchMerchant("MAXWELL HOUSE COFFEE", DIR) === null && matchMerchant("MAX.COM 855-442-6629 NY", DIR).merchant.provider === "maxtest");
check("D2 statement noise doesn't change the match", matchMerchant("PAYPAL *NETFLIX.COM 402-935-7733", DIR).merchant.provider === "netflix" && matchMerchant("APPLE.COM/BILL 866-712-7753 CA", DIR).merchant.provider === "apple");
check("D3 unknown companies get a stable key without store numbers, cities or prefixes", merchantKey("SQ *BLUE BOTTLE #123 SAN FRANCISCO CA") === "BLUE BOTTLE" && merchantKey("TECH SUPPORT SOLUTIONS LLC 8005551234 FL") === "TECH SUPPORT" && merchantKey("TST* JOE'S PIZZA 555") === "JOE PIZZA");
{
  const byId = (id) => DIR.find((m) => m.provider === id);
  check("D4 cancel page: https on the vendor's own domain only", safeCancelUrl(byId("netflix")) === "https://www.netflix.com/cancelplan" && safeCancelUrl(byId("adobe")) === "https://account.adobe.com/plans");
  check("D5 cancel page refused: other domain, plain http, placeholders, userinfo", safeCancelUrl(byId("maxtest")) === null && safeCancelUrl(byId("mailco")) === null && safeCancelUrl({ domain: "x.com", cancelUrl: "https://<space>.x.com/billing" }) === null && safeCancelUrl({ domain: "x.com", cancelUrl: "https://user:pw@x.com/" }) === null && safeCancelUrl({ domain: "x.com", cancelUrl: "https://x.com.evil.example/" }) === null);
}
{
  const real = loadMerchants();
  const ids = real.map((m) => m.provider);
  const consumer = real.filter((m) => m.category !== "developer");
  check("D6 shipped directory loads; ids unique; every category and refund value is from the closed lists", real.length >= 40 && new Set(ids).size === ids.length && real.every((m) => (SUBSCRIPTION_CATEGORIES.has(m.category) || ["shopping", "other"].includes(m.category)) && REFUND_LIKELIHOOD.includes(m.refundLikelihood)));
  const bad = real.filter((m) => m.cancelUrl && !safeCancelUrl(m) && !/[<{]/.test(m.cancelUrl));
  check("D7 every shipped cancel link is safe to open (or a marked placeholder that is never opened)", bad.length === 0, bad.map((m) => `${m.provider}: ${m.cancelUrl}`).join("; "));
  check("D8 every consumer entry cites the vendor pages it came from and when it was checked", consumer.every((m) => Array.isArray(m.sources) && m.sources.length && /^\d{4}-\d{2}-\d{2}$/.test(m.checked || "")), consumer.filter((m) => !(m.sources || []).length).map((m) => m.provider).join(","));
}

// ------------------------------------------------------------------ analysis (a scam timeline)
const TODAY = "2026-10-01";
const stmts = [CHASE_CARD, AMEX, CAPONE, BOFA, WELLS].map((t, i) => ({ name: `s${i}`, ...parseStatement(t) }));
{
  const a = analyze(stmts, { merchants: DIR, today: TODAY });
  const by = (k) => a.recurring.find((r) => r.merchant === k);
  check("A1 monthly subscriptions found across banks, groceries and one-offs are not", by("netflix")?.cadence === "monthly" && by("adobe")?.cadence === "monthly" && by("apple")?.cadence === "monthly" && !a.recurring.some((r) => /SAFEWAY|SHELL|CORNER/.test(r.merchant)));
  check("A2 a known subscription company counts after one charge (as once - maybe yearly - never as quiet)", by("norton")?.cadence === "one charge so far" && by("norton").monthly === null && by("norton").status === "once");
  check("A3 a price rise is caught (Adobe 54.99 -> 59.99)", by("adobe").priceUp?.from === 54.99 && by("adobe").priceUp.to === 59.99);
  check("A4 an unknown company billing monthly shows up as a repeating charge", by("TECH SUPPORT")?.cadence === "monthly" && by("TECH SUPPORT").known === false);
  check("A5 monthly total counts active repeating charges", a.monthlyTotal === Math.round((15.49 + 59.99 + 9.99 + 299.99 + (by("spotify").status === "active" ? 11.99 : 0)) * 100) / 100, String(a.monthlyTotal));
  check("A6 Spotify, last charged in July, reads as quiet - not active", by("spotify").status === "quiet");
}
{
  const a = analyze(stmts, { merchants: DIR, today: TODAY, cancels: [{ merchant: "netflix", on: "2026-08-05" }, { merchant: "spotify", on: "2026-07-10" }, { merchant: "adobe", on: "2026-09-20" }] });
  const by = (k) => a.recurring.find((r) => r.merchant === k);
  check("A7 STILL CHARGING: billed again after the cancel date, with the date and an act-by", by("netflix").status === "still-charging" && by("netflix").afterCancel.length === 1 && by("netflix").afterCancel[0].date === "2026-09-01" && by("netflix").afterCancel[0].actBy === "2026-10-31" && a.stillCharging === 1 && a.recurring[0].merchant === "netflix");
  check("A8 stopped only once a later statement proves it", by("spotify").status === "stopped" && by("adobe").status === "waiting");
  const grace = analyze([{ rows: [{ date: "2026-09-01", descriptor: "NETFLIX.COM", amount: 15.49, direction: "out", kind: "merchant" }, { date: "2026-08-01", descriptor: "NETFLIX.COM", amount: 15.49, direction: "out", kind: "merchant" }] }], { merchants: DIR, today: TODAY, cancels: [{ merchant: "netflix", on: "2026-08-31" }] });
  check("A9 a charge already in flight on the cancel day isn't called still-charging", grace.recurring[0].status !== "still-charging");
}
{
  const a = analyze(stmts, { merchants: DIR, today: TODAY, incidentDate: "2026-08-14" });
  const d = a.sinceIncident.map((x) => x.descriptor).join(" | ");
  check("A10 since the incident: the Zelle, the remote tool, the 'support' company and the gift card", /Zelle/.test(d) && /ANYDESK/.test(d) && /TECH SUPPORT/.test(d) && /GIFT CARD/.test(d), d);
  check("A11 since the incident: subscriptions that were already running are not news", !/NETFLIX|ADOBE|APPLE/.test(d));
  check("A12 total that left since the incident (every new company counts, even a cafe), and days left to tell the bank", a.sinceTotal === 2653.48 && /CORNER CAFE/.test(d) && a.sinceIncident.find((x) => /Zelle/.test(x.descriptor)).actBy === "2026-10-13" && a.sinceIncident.find((x) => /Zelle/.test(x.descriptor)).daysLeft === 12);
}
{
  const merged = mergeRows([{ rows: stmts[0].rows }, { rows: stmts[0].rows }]);
  check("A13 importing the same statement twice changes nothing", merged.length === stmts[0].rows.length);
  const inst = parseInstalled(JSON.stringify([{ n: "Norton 360", p: "Gen Digital", d: "20260712" }, { n: "AnyDesk", p: "AnyDesk Software GmbH", d: "20260814" }, { n: "7-Zip 24.08", p: "Igor Pavlov", d: "" }]));
  const a = analyze(stmts, { merchants: DIR, today: TODAY, installed: inst.map((p) => p.name) });
  check("A14 'installed on this PC AND on your bill' (Norton)", a.recurring.find((r) => r.merchant === "norton").onThisPc[0] === "Norton 360");
  check("A15 remote-access tools are picked out of the installed list", remoteToolsIn(inst).map((p) => p.name).join() === "AnyDesk" && inst[1].installed === "2026-08-14");
  const big = { rows: Array.from({ length: 5000 }, (_, i) => ({ date: new Date(Date.UTC(2025, 0, 1) + (i % 600) * 86_400_000).toISOString().slice(0, 10), descriptor: `STORE ${i % 400} NETFLIX`.replace(/ NETFLIX$/, i % 50 ? "" : " NETFLIX"), amount: 5 + (i % 97), direction: "out", kind: "merchant" })) };
  const t0 = Date.now(); analyze([big], { merchants: DIR, today: TODAY }); const ms = Date.now() - t0;
  check("A16 a 5,000-row year of statements analyses in under a second", ms < 1000, `${ms} ms`);
}

// ------------------------------------------------------------------ Money (storage through the brain)
function fakeBrain() {
  return { available: true, entries: [], seq: 0, forgot: [],
    records(k) { return this.entries.filter((e) => e.kind === k); },
    async remember(kind, data) { this.seq++; this.entries.push({ id: this.seq, kind, at: new Date(Date.UTC(2026, 8, 1) + this.seq * 1000).toISOString(), ...JSON.parse(JSON.stringify(data)) }); return true; },
    async forget(ids) { this.forgot.push(...ids); this.entries = this.entries.filter((e) => !ids.includes(e.id)); return true; } };
}
const NOW = () => Date.parse("2026-10-01T12:00:00Z");
{
  const brain = fakeBrain();
  const m = new Money({ brain, merchants: DIR, now: NOW });
  const r = await m.importStatement("chase.csv", CHASE_CARD);
  check("M1 import saves the statement into the brain (packed), and reads back identically", r.ok && r.saved && brain.records("statement").length === 1 && JSON.stringify(m.statements()[0].rows) === JSON.stringify(parseStatement(CHASE_CARD).rows));
  check("M2 pack/unpack round trip keeps cents exact", JSON.stringify(unpackRows(packRows([{ date: "2026-01-01", descriptor: "X", amount: 0.1 + 0.2, direction: "out", kind: "transfer" }]))) === JSON.stringify([{ date: "2026-01-01", descriptor: "X", amount: 0.3, direction: "out", kind: "transfer" }]));
  check("M3 cancel refused for a company that isn't a repeating charge, and for a future date", !(await m.markCanceled("nobody", "2026-09-01")).ok && !(await m.markCanceled("netflix", "2027-01-01")).ok && !(await m.markCanceled("netflix", "2026-13-01")).ok);
  check("M4 cancel saved -> the next analysis flags the later charge", (await m.markCanceled("netflix", "2026-08-05")).ok && m.summary().recurring[0].status === "still-charging");
  check("M5 incident date saved and used", (await m.setIncident("2026-08-14")).ok && m.summary().incidentDate === "2026-08-14" && !(await m.setIncident("next tuesday")).ok);
  const bad = await m.importStatement("x.csv", "not,a\nstatement,at all");
  check("M6 a bad file is refused with a reason, and nothing is saved", !bad.ok && bad.warnings.length && brain.records("statement").length === 1);
  const ids = brain.entries.map((e) => e.id);
  await m.forgetAll();
  check("M7 'forget my statements' deletes exactly Money's own entries", brain.entries.length === 0 && JSON.stringify(brain.forgot.sort()) === JSON.stringify(ids.sort()));
  const off = new Money({ brain: { available: false }, merchants: DIR, now: NOW });
  const r2 = await off.importStatement("a.csv", AMEX);
  check("M8 memory off: still works this session, and says it isn't saving", r2.ok && r2.saved === false && off.view().saving === false && off.summary().recurring.some((x) => x.merchant === "adobe"));
  check("M9 cancel info: vendor steps and traps; a link only when it is safe", (() => { const a = off.cancelInfo("adobe"); return a.canOpen && a.traps.length === 1 && a.steps[0] === "Sign in"; })() && off.cancelUrl("maxtest") === null && off.cancelInfo("nobody") === null);
}

// ------------------------------------------------------------------ guide + Money tools
function fakeTransport(script) {
  const calls = [];
  return { kind: "fake", calls, async turn(messages, onText) {
    calls.push(JSON.parse(JSON.stringify(messages)));
    const step = script.shift();
    for (const t of step.content.filter((b) => b.type === "text")) onText(t.text);
    return { stop_reason: step.stop, content: step.content, model: MODEL };
  } };
}
const noWorker = { latestScan: null, latestHunt: null, jobs: [], enqueue() { return { done: Promise.resolve({ state: "done" }) }; } };
const red = makeRedactor({ names: ["jdoe"], computer: "HOME-PC" });
{
  const m = new Money({ brain: fakeBrain(), merchants: DIR, now: NOW });
  await m.importStatement("bofa.csv", BOFA.replace("JOHN DOE", "JDOE"));
  await m.importStatement("chase.csv", CHASE_CARD);
  await m.setIncident("2026-08-14");
  const t = fakeTransport([
    { stop: "tool_use", content: [{ type: "tool_use", id: "t1", name: "get_money_summary", input: {} }] },
    { stop: "tool_use", content: [{ type: "tool_use", id: "t2", name: "mark_canceled", input: { merchant: "netflix", canceled_on: "2026-08-05" } }, { type: "tool_use", id: "t3", name: "show_cancel_steps", input: { merchant: "netflix" } }] },
    { stop: "tool_use", content: [{ type: "tool_use", id: "t4", name: "offer_letter", input: { kind: "bank_dispute", merchant: "netflix", subject: "Dispute: charge after cancellation", body: "Dear [Bank],\nI cancelled Netflix on 2026-08-05 but was charged $15.49 on 2026-09-01.\n[Your name]" } }] },
    { stop: "end_turn", content: [{ type: "text", text: "Here's your letter." }] },
  ]);
  const g = new Guide({ transport: t, worker: noWorker, money: m, redactor: red });
  const ev = []; await g.chat("check my bank charges", (e) => ev.push(e));
  const summary = t.calls[1].at(-1).content[0].content;
  check("G1 get_money_summary gives the guide the repeating charges and the post-incident money", /TECH SUPPORT/.test(summary) && /Zelle/.test(summary) && /repeatingChargesPerMonth/.test(summary));
  check("G2 what the guide sees about money is redacted too", !/jdoe/i.test(summary) && /<you>|\[redacted/.test(summary) || !/JDOE/.test(summary), summary.slice(0, 200));
  check("G3 mark_canceled records it; the company then reads still-charging", m.summary().recurring.find((r) => r.merchant === "netflix").status === "still-charging");
  const cards = ev.filter((e) => e.type === "card").map((e) => e.card);
  check("G4 show_cancel_steps puts a card in front of the person (steps + safe link flag), never opens anything", cards[0]?.type === "cancel" && cards[0].canOpen === true && cards[0].steps.length === 3 && !("url" in cards[0]));
  check("G5 offer_letter puts the draft in front of the person to send themselves", cards[1]?.type === "letter" && cards[1].kind === "bank_dispute" && /2026-09-01/.test(cards[1].body) && cards[1].to === null);
  check("G6 the guide can't choose where a letter goes (no 'to' field; an address only from the directory)", validateToolInput("offer_letter", { kind: "refund_request", subject: "s", body: "b", to: "scammer@evil.example" }) === "unexpected field");
  const t2 = fakeTransport([
    { stop: "tool_use", content: [{ type: "tool_use", id: "a", name: "offer_letter", input: { kind: "cancel_by_email", merchant: "nobody", subject: "s", body: "b" } }, { type: "tool_use", id: "b", name: "mark_canceled", input: { merchant: "netflix", canceled_on: "2099-01-01" } }, { type: "tool_use", id: "c", name: "set_incident_date", input: { date: "last week" } }] },
    { stop: "end_turn", content: [{ type: "text", text: "ok" }] },
  ]);
  const ev2 = []; await new Guide({ transport: t2, worker: noWorker, money: m, redactor: red }).chat("x", (e) => ev2.push(e));
  const res = t2.calls[1].at(-1).content;
  check("G7 unknown company, future date and non-date are all refused, and no card appears", /isn't in the repeating charges/.test(res[0].content) && /future/.test(res[1].content) && res[2].is_error === true && !ev2.some((e) => e.type === "card"));
  const mc = new Money({ brain: fakeBrain(), merchants: DIR, now: NOW });
  await mc.importStatement("m.csv", "Date,Description,Amount\n2026-09-01,MAILCO,-5.00\n2026-08-01,MAILCO,-5.00\n");
  const t3 = fakeTransport([{ stop: "tool_use", content: [{ type: "tool_use", id: "a", name: "offer_letter", input: { kind: "cancel_by_email", merchant: "mailco", subject: "Cancel", body: "Please cancel. [Your name]" } }] }, { stop: "end_turn", content: [{ type: "text", text: "ok" }] }]);
  const ev3 = []; await new Guide({ transport: t3, worker: noWorker, money: mc, redactor: red }).chat("cancel mailco", (e) => ev3.push(e));
  check("G8 a cancel-by-email letter is addressed from the directory only", ev3.find((e) => e.type === "card").card.to === "cancel@mailco.com");
  const t4 = fakeTransport([{ stop: "tool_use", content: [{ type: "tool_use", id: "a", name: "offer_letter", input: { kind: "refund_request", merchant: "mailco", subject: "Refund", body: "Please refund. [Your name]" } }] }, { stop: "end_turn", content: [{ type: "text", text: "ok" }] }]);
  const ev4 = []; await new Guide({ transport: t4, worker: noWorker, money: mc, redactor: red }).chat("refund mailco", (e) => ev4.push(e));
  check("G9 only a cancel-by-email letter gets an address; a refund letter is left for the person to address", ev4.find((e) => e.type === "card").card.to === null);
}

// ------------------------------------------------------------------ server endpoints
function request(port, { method = "GET", path: p = "/", headers = {}, body } = {}) {
  return new Promise((resolve) => {
    const req = http.request({ host: "127.0.0.1", port, method, path: p, headers: { host: `127.0.0.1:${port}`, ...headers } }, (res) => {
      let data = ""; res.on("data", (c) => (data += c)); res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", () => resolve({ status: 0 }));
    if (body) req.write(body);
    req.end();
  });
}
{
  const opened = [];
  const money = new Money({ brain: fakeBrain(), merchants: DIR, now: NOW });
  const fakeWorker = Object.assign(new EventEmitter(), { active: null, state() { return { busy: false, jobs: [] }; }, enqueue() { return { id: 1, state: "queued" }; } });
  const fakeGuide = { available: false, busy: false, model: MODEL, transport: null, reset() {}, async chat() {} };
  const srv = await startServer({ worker: fakeWorker, guide: fakeGuide, money, openUrl: (u) => opened.push(u), uiHtml: "x" });
  const { port, token } = srv, origin = `http://127.0.0.1:${port}`;
  const H = { cookie: `hideout=${token}`, origin, "content-type": "application/json" };
  const post = (p, b) => request(port, { method: "POST", path: p, headers: H, body: JSON.stringify(b) });
  const imp = JSON.parse((await post("/api/money/import", { name: "chase.csv", text: CHASE_CARD + "\n".repeat(80_000) })).body);
  check("H1 a statement bigger than the 64 KB chat limit imports (its own 3 MB limit)", imp.ok === true && imp.rows === 8);
  check("H2 over 3 MB is refused", (await post("/api/money/import", { name: "x", text: "x".repeat(3_200_000) })).status === 413);
  check("H3 Money endpoints need the session cookie and same-origin", (await request(port, { method: "POST", path: "/api/money/open", headers: { "content-type": "application/json", origin }, body: '{"merchant":"netflix"}' })).status === 403 && (await request(port, { method: "POST", path: "/api/money/open", headers: { ...H, origin: "https://evil.example" }, body: '{"merchant":"netflix"}' })).status === 403 && opened.length === 0);
  const o1 = await post("/api/money/open", { merchant: "netflix", url: "https://evil.example/phish" });
  check("H4 'open cancel page' opens the DIRECTORY's page, ignoring any url in the request", o1.status === 200 && opened.length === 1 && opened[0] === "https://www.netflix.com/cancelplan");
  check("H5 no safe page on file = nothing opens", (await post("/api/money/open", { merchant: "maxtest" })).status === 404 && (await post("/api/money/open", { merchant: "nobody" })).status === 404 && opened.length === 1);
  check("H6 forget needs an explicit confirm", (await post("/api/money/forget", {})).status === 400);
  const stRaw = await request(port, { path: "/api/state", headers: { cookie: `hideout=${token}` } }); const st = JSON.parse(stRaw.body || "{}"); if (!st.money) console.log("    state:", stRaw.status, String(stRaw.body).slice(0, 300));
  check("H7 the window's state carries the Money view", st.money && st.money.statements.length === 1 && st.money.recurring.some((r) => r.merchant === "netflix"));
  await srv.close();
}

// ------------------------------------------------------------------ static fences
{
  const moneySrc = ["src/money/statement.mjs", "src/money/analyze.mjs", "src/money/directory.mjs", "src/money/money.mjs"].map(code).join("\n");
  check("F1 Money's engine has no network and runs no programs", !/\bfetch\(|node:http|node:https|child_process|(?<![.\w])spawn\(|(?<![.\w])exec\(|writeFile|unlink/.test(moneySrc));
  check("F2 the installed-programs read only reads (Get-ItemProperty; no Set/Remove/New/Start)", /Get-ItemProperty/.test(INSTALLED_SCRIPT) && !/\b(Set|Remove|New|Start|Stop|Invoke|Uninstall)-/.test(INSTALLED_SCRIPT));
  check("F3 the only thing the server opens is a URL the directory vouched for", /money\.cancelUrl\(/.test(code("src/server.mjs")) && !/openUrl\(\s*body/.test(code("src/server.mjs")));
  // F4, widened (public-repo-hygiene PR0): the FILE SET is every text file `git ls-files`
  // returns for the whole repo - not only app/src/**, ui/index.html and data/merchants.json
  // - because the leak this guards against (the governance engine's private-template door,
  // AGENTS.md / .github/copilot-instructions.md) lives at the repo ROOT, outside app/ entirely.
  const ROOT = path.resolve(APP, "..");
  const BINARY_EXT = /\.(png|jpe?g|gif|ico|exe|dll|zip|pdf|woff2?|ttf|eot|wav|mp3|mp4)$/i;
  const trackedFiles = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" }).split("\n").map((f) => f.trim()).filter((f) => f && !BINARY_EXT.test(f));
  const shippedText = trackedFiles.map((f) => { try { return fs.readFileSync(path.join(ROOT, f), "utf8"); } catch { return ""; } }).join("\n").toLowerCase();
  // The IDENTIFIER LIST is widened the same way: username + COMPUTERNAME (as before) plus
  // the home-folder name and every name collectIdentity() returns (redact.mjs:14-28) - the
  // two-name list here would not have caught a profile-folder name in the door files.
  // "user"/"admin"/etc. are excluded: a plain profile-folder-exclusion gap in collectIdentity
  // (measured on this machine - a literal "user" folder under C:\Users survives its
  // /^(public|default|default user|all users)$/i exclude) turns a common dictionary word
  // into a false positive across nearly every file; filtered here, not in redact.mjs (see
  // doors.selftest.mjs for why that fix belongs to a dedicated change, not this one).
  const NOISE = new Set(["user", "users", "admin", "administrator", "guest", "test", "default", "public", "owner", "service", "temp"]);
  const id = collectIdentity();
  const identifiers = (fn) => [...new Set([os.userInfo().username, process.env.COMPUTERNAME, path.basename(os.homedir()), id.computer, ...id.names])]
    .filter((n) => n && n.length > 3 && !NOISE.has(n.toLowerCase()))
    .map((n) => n.toLowerCase())
    .filter(fn);
  const me = identifiers(() => true);
  const identityHits = (text, names) => names.filter((n) => text.includes(n));
  check("F4 no builder identity (account, PC name, home-folder name, or any local profile name) ends up in ANY tracked file, not just app/src", identityHits(shippedText, me).length === 0, identityHits(shippedText, me).join(", "));
  // Negative control (proves F4 isn't vacuously green): a synthetic "shipped" string that
  // plants the home-folder name / an identifier makes the SAME check go red.
  check("F4b negative control: a fixture string carrying an identifier is caught", me.length > 0 && identityHits(`totally normal text ${me[0]} more text`, me).length === 1);
  check("F4c negative control: a fixture string carrying none of them stays clean", identityHits("totally normal text with no identifiers at all", me).length === 0);
  check("F5 the guide is told it never logs in, cancels or sends", /never logs into accounts, cancels anything, or sends email/.test(src("src/guide-spec.mjs")));
  check("F6 letters never state facts the person did not give: unconfirmed lines go in [Confirm: ...] brackets", /Never state a fact the person hasn't told you and Hideout doesn't show/.test(src("src/guide-spec.mjs")) && src("src/guide-spec.mjs").includes("[Confirm: "));
}

// ------------------------------------------------------------------ E2E: Money tools through the real gateway
{
  const calls = [];
  const fakeClaude = { beta: { messages: { stream(params) {
    calls.push(params); const n = calls.length, h = {};
    return { on(ev, fn) { h[ev] = fn; return this; }, async finalMessage() {
      if (n === 1) return { stop_reason: "tool_use", content: [{ type: "tool_use", id: "x1", name: "get_money_summary", input: {} }], model: MODEL, usage: { input_tokens: 5, output_tokens: 5 } };
      if (n === 2) return { stop_reason: "tool_use", content: [{ type: "tool_use", id: "x2", name: "offer_letter", input: { kind: "refund_request", merchant: "adobe", subject: "Refund", body: "Please refund. [Your name]" } }], model: MODEL, usage: { input_tokens: 5, output_tokens: 5 } };
      h.text?.("Done."); return { stop_reason: "end_turn", content: [{ type: "text", text: "Done." }], model: MODEL, usage: { input_tokens: 5, output_tokens: 3 } };
    } };
  } } } };
  const gw = createGateway({ client: fakeClaude, secret: "m".repeat(48) });
  const port = await new Promise((res) => gw.server.listen(0, "127.0.0.1", () => res(gw.server.address().port)));
  const base = `http://127.0.0.1:${port}`, f = (u, i) => fetch(u, i);
  const tok = (await (await f(`${base}/v1/install`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).json()).token;
  const m = new Money({ brain: fakeBrain(), merchants: DIR, now: NOW }); await m.importStatement("amex.csv", AMEX);
  const ev = []; await new Guide({ transport: gatewayTransport(base, async () => tok, { fetchImpl: f }), worker: noWorker, money: m, redactor: red }).chat("refund adobe", (e) => ev.push(e));
  check("E1 app -> gateway -> Claude uses the Money tools; the letter card reaches the window", ev.some((e) => e.type === "card" && e.card.type === "letter" && e.card.name === "Adobe") && ev.at(-1).type === "done" && calls.length === 3);
  gw.server.close();
}

// ------------------------------------------------------------------ LIVE: a big statement through the real engine
{
  const liveExe = path.resolve(APP, "..", "..", "..", "cognitive-mcp", "rust", "target", "release", "cognitive-mcp.exe");
  if (fs.existsSync(liveExe)) {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), "hideout-money-live-"));
    try {
      const b = new Brain({ exe: liveExe, dir: d }); await b.start();
      const lines = ["Date,Description,Amount"]; for (let i = 0; i < 400; i++) lines.push(`2026-${String(1 + (i % 9)).padStart(2, "0")}-${String(1 + (i % 28)).padStart(2, "0")},MERCHANT NUMBER ${i} SOMEWHERE CA,-${(i % 90) + 1}.25`);
      const m = new Money({ brain: b, merchants: DIR, now: NOW });
      const r = await m.importStatement("big.csv", lines.join("\n"));
      b.stop(); await new Promise((res) => setTimeout(res, 300));
      const raw = fs.readFileSync(path.join(d, "memory.db"));
      const b2 = new Brain({ exe: liveExe, dir: d }); await b2.start();
      const back = new Money({ brain: b2, merchants: DIR, now: NOW }).statements();
      check("L1 LIVE: a 400-row statement is stored encrypted (TPM) and survives a restart intact", r.ok && r.saved && back.length === 1 && back[0].rows.length === 400 && !raw.includes(Buffer.from("MERCHANT NUMBER")));
      b2.stop(); await new Promise((res) => setTimeout(res, 300));
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  } else console.log("  skip  L1 (cognitive-mcp engine not on this machine)");
}

console.log(`\nhideout money selftest: ${pass} passed, ${fail} failed`);
// MEASURED on this machine (Node v26.1.0, Windows): an immediate process.exit() here
// deterministically (5/5 repeated runs, including on the unmodified file from origin/main)
// tripped a native libuv assertion (`UV_HANDLE_CLOSING`, src/win/async.c) and aborted the
// process AFTER every check had already passed - a red exit code behind a clean test run.
// Root cause: the global `fetch()` the E1 test uses (gatewayTransport -> Node's built-in
// undici) creates a process-wide connection-pool dispatcher on first use that is not
// reference-counted away on `server.close()`; closing it isn't reachable from userland on
// this Node build (no `node:undici` export here to call `getGlobalDispatcher().close()`).
// Plain `process.exitCode` (no forced exit) proved the dispatcher's own timer never drains
// on its own either - it hung past 90s instead of crashing. A short, empirically-checked
// delay before the same forced exit gives that one background timer time to go idle first,
// so the exit no longer races a closing handle: 16/16 clean runs (money + app selftest) at
// 1500ms, 0/16 at this delay's floor (200ms still crashed 1/5). This is a known undici/Node
// gotcha (a process holding open after `fetch()`), not a bug this PR introduced or fixes at
// the source - flagged for a dedicated follow-up rather than a deeper rewrite here.
setTimeout(() => process.exit(fail ? 1 : 0), 1500);
