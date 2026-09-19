// money.mjs — Hideout's Money section. Holds the person's imported statements, the
// companies they told us they cancelled, and the day things went wrong - all in Hideout's
// private brain (TPM-sealed, never leaves the PC). If memory is off, it still works for
// this session and says it isn't saving.
//
// Hideout never logs into anything, never sends anything and never cancels anything. It
// shows, drafts, and opens the vendor's own cancel page when the person clicks.
import { parseStatement } from "./statement.mjs";
import { analyze } from "./analyze.mjs";
import { loadMerchants, safeCancelUrl } from "./directory.mjs";
import { remoteToolsIn } from "./pc.mjs";

const ISO = /^\d{4}-\d{2}-\d{2}$/;
const KIND = { m: "merchant", t: "transfer", p: "payment" };
const KIND_CODE = { merchant: "m", transfer: "t", payment: "p" };

// Compact storage: [date, descriptor, cents, "o"|"i", kind]. A year of rows fits easily.
export const packRows = (rows) => rows.map((r) => [r.date, r.descriptor, Math.round(r.amount * 100), r.direction === "out" ? "o" : "i", KIND_CODE[r.kind] || "m"]);
export const unpackRows = (rows) => (rows || []).map(([date, descriptor, cents, dir, k]) => ({ date, descriptor, amount: cents / 100, direction: dir === "o" ? "out" : "in", kind: KIND[k] || "merchant" }));
export const validDate = (d, today) => ISO.test(d) && !Number.isNaN(Date.parse(d)) && d >= "2000-01-01" && (!today || d <= today);

export class Money {
  constructor({ brain = null, merchants = null, now = () => Date.now(), log = () => {} }) {
    this.brain = brain; this.now = now; this.log = log;
    this.merchants = merchants || loadMerchants();
    this.session = { statements: [], cancels: [], incident: null }; // used only when memory is off
    this.installed = null; // null = not looked yet
    this.onChange = null;
  }
  today() { return new Date(this.now()).toISOString().slice(0, 10); }
  get saving() { return !!this.brain?.available; }

  #records(kind) { return this.saving ? this.brain.records(kind) : []; }
  statements() {
    if (!this.saving) return this.session.statements;
    return this.#records("statement").map((e) => ({ id: e.id, name: e.name, from: e.from, to: e.to, at: e.at, rows: unpackRows(e.rows) }));
  }
  cancels() { return this.saving ? this.#records("cancel").sort((a, b) => String(a.at).localeCompare(String(b.at))).map((e) => ({ merchant: e.merchant, on: e.on })) : this.session.cancels; }
  incidentDate() {
    if (!this.saving) return this.session.incident;
    const e = this.#records("incident").sort((a, b) => String(a.at).localeCompare(String(b.at))).at(-1);
    return e?.date || null;
  }

  async #save(kind, data) {
    if (this.saving) {
      const ok = await this.brain.remember(kind, data);
      if (!ok) throw new Error("couldn't save to Hideout's memory");
    } else if (kind === "statement") this.session.statements.push({ ...data, rows: unpackRows(data.rows) });
    else if (kind === "cancel") this.session.cancels.push({ merchant: data.merchant, on: data.on });
    else if (kind === "incident") this.session.incident = data.date;
    try { this.onChange?.(); } catch {}
  }

  async importStatement(name, text) {
    const parsed = parseStatement(text);
    if (!parsed.rows.length) return { ok: false, warnings: parsed.warnings.length ? parsed.warnings : ["No charges found in that file."] };
    const safeName = String(name || "statement").replace(/[^\w .()-]/g, "_").slice(0, 80);
    // The same file twice adds nothing new: rows are de-duplicated when analysed.
    await this.#save("statement", { name: safeName, from: parsed.from, to: parsed.to, rows: packRows(parsed.rows) });
    return { ok: true, rows: parsed.rows.length, from: parsed.from, to: parsed.to, warnings: parsed.warnings, saved: this.saving };
  }

  knows(merchant) { return this.summary().recurring.some((r) => r.merchant === merchant); }

  async markCanceled(merchant, on) {
    if (!this.knows(merchant)) return { ok: false, error: "That company isn't in the repeating charges." };
    if (!validDate(on, this.today())) return { ok: false, error: "The cancel date must be a real date, not in the future (YYYY-MM-DD)." };
    await this.#save("cancel", { merchant, on });
    return { ok: true, saved: this.saving };
  }

  async setIncident(date) {
    if (!validDate(date, this.today())) return { ok: false, error: "That date must be a real date, not in the future (YYYY-MM-DD)." };
    await this.#save("incident", { date });
    return { ok: true, saved: this.saving };
  }

  async forgetAll() {
    if (this.saving) {
      const ids = ["statement", "cancel", "incident"].flatMap((k) => this.brain.records(k).map((e) => e.id));
      await this.brain.forget(ids);
    }
    this.session = { statements: [], cancels: [], incident: null };
    try { this.onChange?.(); } catch {}
    return { ok: true };
  }

  summary() {
    return analyze(this.statements(), { cancels: this.cancels(), incidentDate: this.incidentDate(), installed: (this.installed || []).map((p) => p.name), today: this.today(), merchants: this.merchants });
  }

  /** How to cancel one company: the vendor's own steps, the traps, and whether we have a safe page to open. */
  cancelInfo(merchant) {
    const m = this.merchants.find((x) => x.provider === merchant);
    const r = this.summary().recurring.find((x) => x.merchant === merchant);
    if (!r) return null;
    return {
      merchant, name: r.name,
      steps: m?.cancelSteps?.length ? m.cancelSteps : ["Sign in to your account on the company's own website (type the address yourself - don't use a link from an email).", "Find Account, Billing, Membership or Subscription.", "Choose Cancel, and keep going past any offers until it says the cancellation is confirmed.", "Save the confirmation email or take a screenshot."],
      traps: m?.traps || [],
      canOpen: !!safeCancelUrl(m),
      cancelByEmail: m?.cancelByEmail || null,
      refundLikelihood: r.refundLikelihood, refundBasis: r.refundBasis,
      known: !!m,
    };
  }
  cancelUrl(merchant) { return safeCancelUrl(this.merchants.find((x) => x.provider === merchant)); }

  /** Everything the window shows (local only). */
  view() {
    const s = this.summary();
    return {
      saving: this.saving,
      statements: this.statements().map(({ name, from, to, rows }) => ({ name, from, to, rows: rows.length })),
      remoteTools: this.installed ? remoteToolsIn(this.installed).map((p) => ({ name: p.name, installed: p.installed })) : null,
      ...s,
    };
  }

  /** What the guide sees: the same facts, trimmed. (The guide's redactor runs on top.) */
  guideView() {
    const v = this.view();
    return {
      statementsImported: v.statements.length, period: v.period, savedInMemory: v.saving,
      incidentDate: v.incidentDate,
      repeatingChargesPerMonth: v.monthlyTotal,
      repeating: v.recurring.slice(0, 40).map((r) => ({ merchant: r.merchant, name: r.name, knownCompany: r.known, cadence: r.cadence, lastAmount: r.lastAmount, lastDate: r.lastDate, perMonth: r.monthly, status: r.status, canceledOn: r.canceledOn, chargedAfterCancel: r.afterCancel, priceWentUp: r.priceUp, refundOdds: r.refundLikelihood, refundPolicy: r.refundBasis, cancelPageAvailable: r.hasCancelPage, acceptsCancelByEmail: r.cancelByEmail, installedOnThisPc: r.onThisPc })),
      sinceIncident: v.sinceIncident.slice(-30), sinceIncidentTotal: v.sinceTotal,
      remoteAccessToolsInstalled: v.remoteTools,
    };
  }
}
