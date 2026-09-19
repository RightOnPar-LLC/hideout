// analyze.mjs — turns statement rows into what a person needs to see:
//   - repeating charges (how often, how much a month, did the price go up)
//   - STILL CHARGING: a company that billed again after the person said they cancelled,
//     with the dates as receipts (the dispute that actually wins)
//   - money that left after the day things went wrong (new companies, transfers, Zelle)
//   - honest refund odds and a conservative "act by" date
// Pure functions: no network, no disk, no clock except the `today` passed in.
import { matchMerchant, merchantKey, safeCancelUrl, SUBSCRIPTION_CATEGORIES } from "./directory.mjs";

const DAY = 86_400_000;
const days = (a, b) => Math.round((Date.parse(b) - Date.parse(a)) / DAY);
const addDays = (d, n) => new Date(Date.parse(d) + n * DAY).toISOString().slice(0, 10);
const money = (n) => Math.round(n * 100) / 100;
const median = (xs) => { const s = [...xs].sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

export const CADENCES = {
  weekly: { min: 5, max: 9, period: 7, perMonth: 52 / 12 },
  monthly: { min: 25, max: 35, period: 31, perMonth: 1 },
  quarterly: { min: 80, max: 100, period: 92, perMonth: 1 / 3 },
  yearly: { min: 330, max: 400, period: 366, perMonth: 1 / 12 },
};
// Bank dispute windows are commonly 60 days from the statement that showed the charge.
// We can't see the statement's date, so count from the charge itself: never later than
// the real deadline, sometimes earlier. Shown as "act by", never as legal advice.
export const DISPUTE_DAYS = 60;
const STOP_GRACE = 2; // a charge within 2 days of the cancel date was usually already in flight

function cadenceOf(dates) {
  if (dates.length < 2) return null;
  const gaps = dates.slice(1).map((d, i) => days(dates[i], d)).filter((g) => g > 0);
  if (!gaps.length) return null;
  const g = median(gaps);
  for (const [name, c] of Object.entries(CADENCES)) if (g >= c.min && g <= c.max) return name;
  return null;
}

/** De-duplicate rows from overlapping statements (same day, same amount, same descriptor). */
export function mergeRows(statements) {
  const seen = new Set(), out = [];
  for (const s of statements) for (const r of s.rows || []) {
    const k = `${r.date}|${r.amount}|${r.direction}|${r.descriptor}`;
    if (seen.has(k)) continue;
    seen.add(k); out.push(r);
  }
  return out.sort((a, b) => a.date.localeCompare(b.date));
}

/**
 * @param statements [{name, rows, from, to}]
 * @param opts { cancels: [{merchant, on}], incidentDate, installed: [displayName], today }
 */
export function analyze(statements, { cancels = [], incidentDate = null, installed = [], today = new Date().toISOString().slice(0, 10), merchants } = {}) {
  const rows = mergeRows(statements);
  const to = rows.at(-1)?.date || null, from = rows[0]?.date || null;
  const groups = new Map(), groupOf = new Map();
  for (const r of rows) {
    if (r.kind === "payment") continue;
    const m = r.kind === "merchant" ? matchMerchant(r.descriptor, merchants) : null;
    const key = m ? m.merchant.provider : (r.kind === "transfer" ? `transfer:${merchantKey(r.descriptor)}` : merchantKey(r.descriptor));
    if (!groups.has(key)) groups.set(key, { key, m: m?.merchant || null, ambiguous: !!m?.ambiguous, rows: [] });
    groups.get(key).rows.push(r); groupOf.set(r, groups.get(key));
  }
  const cancelOf = new Map();
  for (const c of cancels) if (c && c.merchant && c.on) cancelOf.set(c.merchant, c.on); // latest wins (callers pass oldest first)
  const lowerInstalled = installed.map((p) => String(p));

  const recurring = [];
  for (const g of groups.values()) {
    if (g.key.startsWith("transfer:")) continue;
    const out = g.rows.filter((r) => r.direction === "out");
    if (!out.length) continue;
    const dates = [...new Set(out.map((r) => r.date))];
    const amounts = out.map((r) => r.amount);
    const cadence = cadenceOf(dates);
    const med = median(amounts);
    const stable = amounts.filter((a) => Math.abs(a - med) <= med * 0.1).length >= Math.ceil(amounts.length * 2 / 3);
    const knownSub = !!g.m && SUBSCRIPTION_CATEGORIES.has(g.m.category);
    // Two charges a month apart at the same price is a subscription; so is any charge from a
    // company the directory knows only sells subscriptions (even if we've seen it once).
    if (!((cadence && stable) || knownSub)) continue;
    const last = out.at(-1);
    const prev = out.length > 1 ? out.at(-2) : null;
    const canceledOn = cancelOf.get(g.key) || null;
    const after = canceledOn ? out.filter((r) => days(canceledOn, r.date) > STOP_GRACE) : [];
    const period = CADENCES[cadence]?.period || 31;
    let status;
    if (canceledOn && after.length) status = "still-charging";
    else if (canceledOn) status = to && days(canceledOn, to) >= period + 5 ? "stopped" : "waiting";
    else if (!cadence) status = "once"; // one charge (often a yearly plan): can't call it quiet or active yet
    else status = to && days(last.date, to) > period * 1.5 ? "quiet" : "active";
    const m = g.m;
    const onThisPc = m?.software?.length ? lowerInstalled.filter((p) => m.software.some((s) => p.toLowerCase().includes(String(s).toLowerCase()))) : [];
    recurring.push({
      merchant: g.key,
      name: m?.name || g.key,
      known: !!m,
      ambiguous: g.ambiguous,
      category: m?.category || null,
      sample: last.descriptor,
      cadence: cadence || (out.length === 1 ? "one charge so far" : "irregular"),
      charges: out.length,
      firstDate: out[0].date,
      lastDate: last.date,
      lastAmount: last.amount,
      monthly: cadence ? money(last.amount * CADENCES[cadence].perMonth) : null,
      priceUp: prev && last.amount > prev.amount * 1.01 && cadence ? { from: prev.amount, to: last.amount, on: last.date } : null,
      status,
      canceledOn,
      afterCancel: after.map((r) => ({ date: r.date, amount: r.amount, actBy: addDays(r.date, DISPUTE_DAYS) })),
      nextExpected: cadence && status !== "stopped" ? addDays(last.date, CADENCES[cadence].period) : null,
      refundLikelihood: m?.refundLikelihood || "unknown",
      refundBasis: m?.refundBasis || null,
      hasCancelPage: !!safeCancelUrl(m),
      cancelByEmail: m?.cancelByEmail || null,
      onThisPc,
    });
  }
  const order = { "still-charging": 0, active: 1, once: 2, waiting: 3, quiet: 4, stopped: 5 };
  recurring.sort((a, b) => order[a.status] - order[b.status] || (b.monthly || 0) - (a.monthly || 0));
  const monthlyTotal = money(recurring.filter((r) => r.status === "active" || r.status === "still-charging").reduce((s, r) => s + (r.monthly || 0), 0));

  // Money that left after the incident: transfers of any kind, and companies first seen
  // on or after that day. (Subscriptions that were already running aren't news.)
  const firstSeen = new Map();
  for (const g of groups.values()) firstSeen.set(g.key, g.rows[0].date);
  let sinceIncident = [];
  if (incidentDate) {
    sinceIncident = rows.filter((r) => r.direction === "out" && r.kind !== "payment" && r.date >= incidentDate).map((r) => ({ r, g: groupOf.get(r) || null }))
      .filter(({ r, g }) => r.kind === "transfer" || (g && firstSeen.get(g.key) >= incidentDate))
      .map(({ r, g }) => ({ date: r.date, descriptor: r.descriptor, amount: r.amount, kind: r.kind, merchant: g?.key || null, known: !!g?.m, actBy: addDays(r.date, DISPUTE_DAYS), daysLeft: days(today, addDays(r.date, DISPUTE_DAYS)) }))
      .slice(-60);
  }
  const sinceTotal = money(sinceIncident.reduce((s, x) => s + x.amount, 0));

  return {
    period: { from, to }, statementCount: statements.length, rows: rows.length,
    monthlyTotal, recurring,
    stillCharging: recurring.filter((r) => r.status === "still-charging").length,
    incidentDate, sinceIncident, sinceTotal,
  };
}
