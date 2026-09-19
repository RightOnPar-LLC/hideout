// statement.mjs — reads the statement a person downloads from their bank's website (CSV,
// or tab/semicolon separated) into plain rows: { date, descriptor, amount, direction }.
//
// Banks disagree on everything: Chase card exports show purchases as NEGATIVE, Amex as
// POSITIVE; Capital One splits Debit/Credit columns; Bank of America puts a summary block
// above the header; Wells Fargo has no header at all. So columns are found by header name
// when there is one and by what the cells look like when there isn't, and the sign of a
// charge is decided per file (whichever sign most rows carry).
//
// Nothing here touches the network or the disk. Long digit runs (card, account and
// reference numbers) are masked on the way in, so they never reach memory or the guide.

const DATE_HEAD = /^(trans(action|\.)?\s*date|date|posted\s*date|post(ing)?\s*date|booking\s*date)$/i;
const DATE_PREFER = /^trans/i; // transaction date beats post date
const DESC_HEAD = [/^description$/i, /^(payee|merchant|merchant name|name|payee name)$/i, /^(transaction|details|memo|narrative|original description)$/i];
const AMOUNT_HEAD = /^(amount|transaction amount|amount \(usd\)|amt)$/i;
const DEBIT_HEAD = /^(debit|debits|withdrawal|withdrawals|money out|charges?|debit amount)$/i;
const CREDIT_HEAD = /^(credit|credits|deposit|deposits|money in|payments?|credit amount)$/i;

// Money that moved but isn't a merchant charging on a schedule. Kept (a scam victim's
// Zelle or wire IS the story) but never counted as a subscription.
const TRANSFER = /\b(ZELLE|VENMO|CASH ?APP|SQUARE CASH|WIRE|TRANSFER|XFER|ATM|WITHDRAWAL|CHECK ?#?\d*|DEPOSIT|WESTERN UNION|MONEYGRAM|REMITLY|WISE\b|COINBASE|CRYPTO|BITCOIN|GIFT ?CARD)\b/;
const CARD_PAYMENT = /\b(PAYMENT THANK YOU|AUTOPAY|AUTO PAY|ONLINE PAYMENT|MOBILE PAYMENT|PAYMENT RECEIVED|CRD AUTOPAY|EPAY|INTEREST CHARGE|LATE FEE|ANNUAL FEE|BALANCE TRANSFER)\b/;

export const MAX_ROWS = 5000;

export function maskDigits(s) {
  // 6+ digits in a row (with spaces/dashes inside) -> keep only the last 4.
  return String(s ?? "").replace(/\d[\d -]{4,}\d/g, (m) => {
    const d = m.replace(/\D/g, "");
    return d.length >= 6 ? `••${d.slice(-4)}` : m;
  });
}

function detectDelimiter(text) {
  const head = text.split(/\r?\n/).slice(0, 15).join("\n");
  const n = (c) => (head.match(new RegExp(c === "\t" ? "\t" : `\\${c}`, "g")) || []).length;
  const [best, count] = Object.entries({ ",": n(","), "\t": n("\t"), ";": n(";") }).sort((a, b) => b[1] - a[1])[0];
  return count ? best : ",";
}

// RFC 4180-ish: quoted fields, doubled quotes, CRLF, a delimiter inside quotes.
export function parseDelimited(text, delim = detectDelimiter(text)) {
  const t = String(text ?? "").replace(/^﻿/, "");
  const rows = []; let row = [], field = "", q = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) {
      if (c === '"') { if (t[i + 1] === '"') { field += '"'; i++; } else q = false; }
      else field += c;
    } else if (c === '"') q = true;
    else if (c === delim) { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && t[i + 1] === "\n") i++;
      row.push(field); rows.push(row); row = []; field = "";
      if (rows.length > MAX_ROWS + 50) break;
    } else field += c;
  }
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  return rows.map((r) => r.map((s) => s.trim())).filter((r) => r.some(Boolean));
}

const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, sept: 9, oct: 10, nov: 11, dec: 12 };
const pad = (n) => String(n).padStart(2, "0");
function ymd(y, m, d) {
  if (y < 100) y += 2000;
  if (!(m >= 1 && m <= 12 && d >= 1 && d <= 31 && y >= 1990 && y <= 2100)) return null;
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCMonth() === m - 1 ? `${y}-${pad(m)}-${pad(d)}` : null;
}
// US order for a/b/yyyy (the banks Hideout's people use); ISO and month names always.
export function parseDate(s) {
  const v = String(s ?? "").trim();
  let m;
  if ((m = /^(\d{4})-(\d{1,2})-(\d{1,2})/.exec(v))) return ymd(+m[1], +m[2], +m[3]);
  if ((m = /^(\d{1,2})\/(\d{1,2})\/(\d{2,4})$/.exec(v))) return ymd(+m[3], +m[1], +m[2]);
  if ((m = /^(\d{1,2})-(\d{1,2})-(\d{2,4})$/.exec(v))) return ymd(+m[3], +m[1], +m[2]);
  if ((m = /^(\d{1,2})[ -]([A-Za-z]{3,4})[a-z]*[ -,]*(\d{2,4})$/.exec(v))) return MONTHS[m[2].toLowerCase()] ? ymd(+m[3], MONTHS[m[2].toLowerCase()], +m[1]) : null;
  if ((m = /^([A-Za-z]{3,4})[a-z]*\.? (\d{1,2}),? (\d{4})$/.exec(v))) return MONTHS[m[1].toLowerCase()] ? ymd(+m[3], MONTHS[m[1].toLowerCase()], +m[2]) : null;
  return null;
}

// "$1,234.56" / "(15.99)" / "-15.99" / "15.99-" / "USD 15.99" -> number, else null.
export function parseAmount(s) {
  let v = String(s ?? "").trim();
  if (!v) return null;
  let neg = false;
  if (/^\(.*\)$/.test(v)) { neg = true; v = v.slice(1, -1); }
  if (/-$/.test(v)) { neg = true; v = v.slice(0, -1); }
  v = v.replace(/[$€£]|USD|CAD|EUR|GBP|,|\s/gi, "");
  if (v.startsWith("-")) { neg = !neg; v = v.slice(1); }
  if (v.startsWith("+")) v = v.slice(1);
  if (!/^\d+(\.\d{1,2})?$/.test(v)) return null;
  const n = Number(v);
  return neg ? -n : n;
}

const looksDate = (c) => parseDate(c) !== null;

function findHeader(rows) {
  for (let i = 0; i < Math.min(rows.length, 20); i++) {
    const r = rows[i];
    const ai = r.findIndex((c) => AMOUNT_HEAD.test(c));
    const dbi = r.findIndex((c) => DEBIT_HEAD.test(c));
    let desc = -1;
    for (const re of DESC_HEAD) { desc = r.findIndex((c) => re.test(c)); if (desc >= 0) break; }
    if (desc >= 0 && (ai >= 0 || dbi >= 0)) {
      const dates = r.map((c, k) => (DATE_HEAD.test(c) ? k : -1)).filter((k) => k >= 0);
      const date = dates.find((k) => DATE_PREFER.test(r[k])) ?? dates[0] ?? -1;
      return { at: i, date, desc, amount: ai, debit: dbi, credit: r.findIndex((c) => CREDIT_HEAD.test(c)) };
    }
  }
  return null;
}

// No header (Wells Fargo) or an unrecognised one: pick columns by what the cells hold.
function inferColumns(rows) {
  const sample = rows.slice(0, 60);
  const width = Math.max(...sample.map((r) => r.length));
  const score = (k, fn) => sample.filter((r) => r[k] && fn(r[k])).length;
  const cols = [...Array(width).keys()];
  const date = cols.sort((a, b) => score(b, looksDate) - score(a, looksDate))[0];
  const amtCols = [...Array(width).keys()].filter((k) => k !== date && score(k, (c) => parseAmount(c) !== null && /\./.test(c)) >= sample.length * 0.6);
  const amount = amtCols[0] ?? -1;
  const text = [...Array(width).keys()].filter((k) => k !== date && k !== amount)
    .sort((a, b) => sample.reduce((s, r) => s + ((r[b] || "").replace(/[^A-Za-z]/g, "").length), 0) - sample.reduce((s, r) => s + ((r[a] || "").replace(/[^A-Za-z]/g, "").length), 0))[0];
  if (score(date, looksDate) < sample.length * 0.6 || amount < 0 || text == null) return null;
  return { at: -1, date, desc: text, amount, debit: -1, credit: -1 };
}

export function classify(descriptor) {
  const d = String(descriptor).toUpperCase();
  if (CARD_PAYMENT.test(d)) return "payment";
  if (TRANSFER.test(d)) return "transfer";
  return "merchant";
}

/**
 * Parse statement text. Returns { rows, from, to, format, skipped, warnings }.
 * rows: { date: "YYYY-MM-DD", descriptor, amount (>0), direction: "out"|"in", kind }
 */
export function parseStatement(text) {
  const all = parseDelimited(text);
  const warnings = [];
  if (!all.length) return { rows: [], from: null, to: null, format: "empty", skipped: 0, warnings: ["The file is empty."] };
  let cols = findHeader(all);
  const format = cols ? "header" : "inferred";
  if (!cols) cols = inferColumns(all);
  if (!cols) return { rows: [], from: null, to: null, format: "unknown", skipped: all.length, warnings: ["Couldn't find the date, description and amount columns. Download the statement as CSV from your bank's website and try again."] };

  const body = all.slice(cols.at + 1);
  const raw = [];
  let skipped = 0;
  for (const r of body) {
    const date = cols.date >= 0 ? parseDate(r[cols.date]) : null;
    const descriptor = maskDigits((r[cols.desc] || "").replace(/\s+/g, " ")).slice(0, 120);
    let signed = null, split = false;
    if (cols.debit >= 0) {
      const d = parseAmount(r[cols.debit]); const c = cols.credit >= 0 ? parseAmount(r[cols.credit]) : null;
      if (d) { signed = -Math.abs(d); split = true; } else if (c) { signed = Math.abs(c); split = true; }
    }
    if (signed === null && cols.amount >= 0) signed = parseAmount(r[cols.amount]);
    if (!date || !descriptor || signed === null || signed === 0) { skipped++; continue; }
    raw.push({ date, descriptor, signed, split });
    if (raw.length >= MAX_ROWS) { warnings.push(`Only the first ${MAX_ROWS} rows were read.`); break; }
  }
  // Which sign is money going out? Split columns say so directly; a single Amount column
  // is decided by the majority of merchant rows (most rows on any statement are spending).
  const merchantRows = raw.filter((x) => !x.split && classify(x.descriptor) === "merchant");
  const neg = merchantRows.filter((x) => x.signed < 0).length;
  const outIsNegative = merchantRows.length ? neg >= merchantRows.length - neg : true;
  const rows = raw.map((x) => {
    const out = x.split ? x.signed < 0 : (outIsNegative ? x.signed < 0 : x.signed > 0);
    return { date: x.date, descriptor: x.descriptor, amount: Math.round(Math.abs(x.signed) * 100) / 100, direction: out ? "out" : "in", kind: classify(x.descriptor) };
  }).sort((a, b) => a.date.localeCompare(b.date));
  if (skipped > 3 && skipped > rows.length / 5) warnings.push(`${skipped} lines couldn't be read and were skipped.`);
  return { rows, from: rows[0]?.date || null, to: rows.at(-1)?.date || null, format, skipped, warnings };
}
