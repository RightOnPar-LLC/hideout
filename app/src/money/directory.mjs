// directory.mjs — who a statement line really is, how to cancel it, and whether a refund
// is realistic. Data: app/data/merchants.json (folded in from the money-out scanner's
// directory, plus a consumer set with the vendor's own cancel pages and refund policies).
//
// The cancel co-pilot opens a page ONLY from this directory, and only after safeCancelUrl
// agrees it is an https page on the vendor's own domain — never a link from a statement,
// an email, the guide, or the page.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readStaticText } from "../engine.mjs";

let HERE;
try { HERE = path.dirname(fileURLToPath(import.meta.url)); } catch { HERE = process.cwd(); } // CJS bundle has no import.meta
const DATA = path.join(HERE, "..", "..", "data", "merchants.json");

export const SUBSCRIPTION_CATEGORIES = new Set(["streaming", "music", "software", "security-software", "cloud-storage", "news", "fitness", "dating", "gaming", "app-store", "phone-internet", "developer"]);
export const REFUND_LIKELIHOOD = ["good", "decent", "low", "near-zero", "unknown"];

let cache = null;
export function loadMerchants(file) {
  if (!file && cache) return cache;
  const list = JSON.parse(file ? readStaticText("data/merchants.json", file) : readStaticText("data/merchants.json", DATA));
  const prepared = prepareMerchants(list);
  if (!file) cache = prepared;
  return prepared;
}

export function prepareMerchants(list) {
  return list.map((m) => ({ ...m, _patterns: (m.descriptorPatterns || []).map(normalize).filter(Boolean).sort((a, b) => b.length - a.length) }));
}

export function normalize(s) {
  return String(s ?? "").toUpperCase().replace(/[^A-Z0-9 ]/g, " ").replace(/\s+/g, " ").trim();
}

// Word-boundary match ("MAX" must not match "MAXWELL"); long patterns may also match inside
// a run-together descriptor ("AMAZONPRIME").
function hit(norm, pat) {
  return (` ${norm} `).includes(` ${pat} `) || (pat.length >= 7 && norm.replace(/ /g, "").includes(pat.replace(/ /g, "")));
}

/** Best directory match for a statement descriptor (longest matching pattern wins). */
export function matchMerchant(descriptor, merchants = loadMerchants()) {
  const norm = normalize(descriptor);
  let best = null, bestLen = 0, others = 0;
  for (const m of merchants) {
    const p = m._patterns.find((x) => hit(norm, x));
    if (!p) continue;
    if (p.length > bestLen) { if (best) others++; best = m; bestLen = p.length; } else others++;
  }
  return best ? { merchant: best, ambiguous: others > 0 } : null;
}

const NOISE = new Set(["SQ", "TST", "PAYPAL", "PP", "SP", "POS", "DEBIT", "PURCHASE", "CARD", "RECURRING", "WWW", "COM", "NET", "ORG", "HTTPS", "HTTP", "INC", "LLC", "LTD", "CO", "USA", "US", "BILL", "HELP", "ONLINE", "PMT", "PAYMENT", "ACH", "WEB", "CHECKCARD", "VISA", "MC"]);
const STATES = new Set("AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC".split(" "));

/** A stable key for a merchant the directory doesn't know: "SQ *BLUE BOTTLE #123 SF CA" -> "BLUE BOTTLE". */
export function merchantKey(descriptor) {
  const toks = normalize(descriptor).split(" ").filter((t) => t.length > 1 && !/\d/.test(t) && !NOISE.has(t));
  while (toks.length > 1 && STATES.has(toks.at(-1))) toks.pop();
  return toks.slice(0, 2).join(" ") || normalize(descriptor).slice(0, 24) || "UNKNOWN";
}

/** The vendor's cancel page, if it is a real https page on the vendor's own domain. */
export function safeCancelUrl(m) {
  if (!m || !m.cancelUrl || /[<>{}\s]/.test(m.cancelUrl)) return null;
  let u; try { u = new URL(m.cancelUrl); } catch { return null; }
  if (u.protocol !== "https:" || u.username || u.password) return null;
  const host = u.hostname.toLowerCase();
  const domains = [m.domain, ...(m.otherDomains || [])].filter(Boolean).map((d) => d.toLowerCase());
  if (!domains.some((d) => host === d || host.endsWith(`.${d}`))) return null;
  return u.href;
}
