// node site/test/guide.test.mjs
// The website guide: same words as the app, nothing leaves the browser, nothing sensitive is asked for or kept,
// and every status on the page is honest. Controls at the end prove each check can go red.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SITE = path.join(HERE, "..");
const ROOT = path.join(SITE, "..");
const PUB = path.join(SITE, "public");
const read = (...p) => fs.readFileSync(path.join(...p), "utf8");
const core = await import(pathToFileURL(path.join(PUB, "guide-core.js")).href);
const { STEPS, CHECKS, LETTER_KINDS, buildLetter, createStore, checkStatus, NOT_AI, AI_STATUS, URGENT } = core;

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => { if (cond) { pass++; console.log("  ok   " + name); } else { fail++; console.log("  FAIL " + name + (detail ? "  " + detail : "")); } };
const norm = (s) => String(s).replace(/[—–]/g, "-").replace(/\s+-\s+/g, " - ").replace(/\s+/g, " ").trim();
const unesc = (s) => s.replace(/\\"/g, '"');
const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");

const html = read(PUB, "index.html");
const siteJs = read(PUB, "site.js");
const coreJs = read(PUB, "guide-core.js");
const headers = read(PUB, "_headers");
const wrangler = read(SITE, "wrangler.toml");
const caseRs = read(ROOT, "rust/crates/hideout-guide/src/case.rs");
const lettersRs = read(ROOT, "rust/crates/hideout-guide/src/letters.rs");
const checksRs = read(ROOT, "rust/crates/hideout-guide/src/checks.rs");
const offlineRs = read(ROOT, "rust/crates/hideout-guide/src/offline.rs");

const panel = (() => { const a = html.indexOf('id="p-guide"'); const b = html.indexOf("</section>", a); return html.slice(a, b); })();
const panelText = panel.replace(/<script[\s\S]*?<\/script>/g, "").replace(/<[^>]+>/g, " ").replace(/&[a-z]+;/g, " ").replace(/\s+/g, " ");

// ---------------------------------------------------------------- same words as the app
console.log("same words as the app (rust/crates/hideout-guide):");
const rustSteps = [...caseRs.matchAll(/TrackerStep\s*\{\s*title:\s*"((?:[^"\\]|\\.)*)",\s*text:\s*"((?:[^"\\]|\\.)*)"/g)].map((m) => ({ title: unesc(m[1]), text: unesc(m[2]) }));
ok("found the app's six tracker steps to compare against", rustSteps.length === 6, `found ${rustSteps.length}`);
ok("guide-core.js has the same six steps as case.rs, title and text", STEPS.length === 6 && STEPS.every((s, i) => rustSteps[i] && norm(s.title) === norm(rustSteps[i].title) && norm(s.text) === norm(rustSteps[i].text)));
const htmlSteps = [...html.matchAll(/<button class="guide-step" data-step="(\d)"[^>]*>[^<]*<\/button>\s*<strong>([^<]*)\.<\/strong>\s*([^<]*)<\/li>/g)].map((m) => ({ i: Number(m[1]), title: m[2], text: m[3].trim() }));
ok("the page lists the same six steps, in order, as guide-core.js", htmlSteps.length === 6 && htmlSteps.every((s, i) => s.i === i && norm(s.title) === norm(STEPS[i].title) && norm(s.text) === norm(STEPS[i].text)));
const letterPhrases = [
  "Please cancel my subscription, effective today, and stop all future charges.",
  "The account is under [Email on the account].",
  "Please confirm the cancellation in writing, with the date it takes effect.",
  "Please refund it to the card it was charged to, and confirm in writing.",
  "[Confirm: the reason.]",
  "[Confirm: this charge was taken after I cancelled, or was not authorised by me.]",
  "Please reverse this charge and block further charges from this merchant.",
  "[Your name] · [Last 4 digits of card] · [Phone number]",
  "To [Bank or card company]:",
];
ok("every fixed sentence in the letters is the app's own (letters.rs)", letterPhrases.every((p) => lettersRs.includes(p)));
const allLetters = LETTER_KINDS.map((k) => buildLetter(k.id, { who: "", amount: "", date: "" })).join("\n");
ok("…and each of them really appears in a letter this page builds", letterPhrases.every((p) => allLetters.includes(p)));
ok("the urgent box opens with the app's first instruction", offlineRs.includes("Hang up, and stop typing any codes.") && URGENT.steps[0] === "Hang up, and stop typing any codes.");
const advicePhrases = [
  "treat it as part of the scam until proven otherwise",
  "Windows Settings > Apps",
  "evidence, not just clutter",
  "Never paste a key, token, password or recovery phrase into this guide, into email, or into chat",
  "rotate it at its provider first",
  "Don't delete",
];
const adviceBlob = CHECKS.map((c) => c.advice).join(" ");
ok("the deeper-check advice carries the app's own key sentences (checks.rs)", advicePhrases.every((p) => adviceBlob.includes(p) && checksRs.includes(p)));
ok("the six deeper checks are the app's six (by title)", ["Scam drift since the scam date", "Small test charges first", "look, never paste", "Rogue AI and agents", "preserve it", "Browser drift"].every((t, i) => CHECKS[i].title.includes(t) && checksRs.includes(t)));

// ---------------------------------------------------------------- letters
console.log("letters:");
const blank = buildLetter("bank_dispute", {});
ok("with nothing typed, every unknown is a [bracket]", /\[\$ amount\]/.test(blank) && /\[Date\]/.test(blank) && /\[Company name\]/.test(blank) && /\[Your name\]/.test(blank));
ok("a dispute always carries a [Confirm: ...] line the person must keep or delete", /\[Confirm: [^\]]+\]/.test(blank));
const filled = buildLetter("refund_request", { who: "Example Co", amount: "$12.50", date: "June 3" });
ok("what the person typed is used, and only that", filled.includes("Example Co") && filled.includes("$12.50") && filled.includes("June 3") && !/\[\$ amount\]/.test(filled));
ok("a letter never contains a card number, an address or a phone number it was not given", !/\d{4}[ -]?\d{4}[ -]?\d{4}/.test(blank + filled) && !/@\w+\./.test(blank + filled));
ok("the cancel-by-email letter does not pretend to know an address", !/@[a-z0-9-]+\.[a-z]/i.test(buildLetter("cancel_by_email", { who: "Example Co" })) && /\[Email on the account\]/.test(buildLetter("cancel_by_email", {})));
ok("an unknown kind falls back to the bank dispute, never a made-up letter", buildLetter("something_else", {}) === buildLetter("bank_dispute", {}));
const hostile = buildLetter("bank_dispute", { who: "<img src=x onerror=alert(1)>", amount: "$1", date: "x" });
ok("typed text is carried through as plain text (the page only ever uses textContent)", hostile.includes("<img src=x onerror=alert(1)>") && /\.textContent\s*=\s*buildLetter/.test(siteJs) && !/innerHTML|insertAdjacentHTML|document\.write|outerHTML/.test(stripComments(siteJs) + stripComments(coreJs)));

// ---------------------------------------------------------------- storage: ticks only, browser only
console.log("storage:");
const mem = () => { const m = new Map(); return { m, getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => void m.set(k, String(v)), removeItem: (k) => void m.delete(k) }; };
const st = mem();
let s1 = createStore(st);
s1.toggleStep(0); s1.toggleStep(3); s1.toggleCheck(0, 1); s1.toggleCheck(2, 0);
ok("steps and checks tick", s1.stepDone(0) && s1.stepDone(3) && !s1.stepDone(1) && s1.checkDone(0, 1) && s1.checkedIn(0) === 1);
const s2 = createStore(st);
ok("they persist (a fresh store from the same storage sees them)", s2.stepDone(0) && s2.stepDone(3) && s2.checkDone(2, 0));
ok("only ticks are saved: every stored value is the boolean true under a known key", [...st.m.entries()].every(([k, v]) => ["hideout-guide-steps", "hideout-guide-checks"].includes(k) && Object.values(JSON.parse(v)).every((x) => x === true)));
ok("nothing but those two keys is ever written", st.m.size === 2);
s2.toggleStep(0);
ok("a tick can be undone", !createStore(st).stepDone(0) && createStore(st).stepDone(3));
s2.clearAll();
ok("clear removes everything, and the storage is empty afterwards", st.m.size === 0 && !createStore(st).stepDone(3) && !createStore(st).anySaved());
const dirty = mem(); dirty.setItem("hideout-guide-steps", JSON.stringify({ 0: true, 1: "yes", 9: true, x: true, 2: { a: 1 } })); dirty.setItem("hideout-guide-checks", "not json");
const d = createStore(dirty);
ok("junk in storage is ignored (only known keys set to true count)", d.stepDone(0) && !d.stepDone(1) && !d.stepDone(2) && !d.anySaved() === false && d.checkedIn(0) === 0);
const angry = { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); }, removeItem() { throw new Error("blocked"); } };
let threw = false; try { const a = createStore(angry); a.toggleStep(1); a.toggleCheck(0, 0); a.clearAll(); } catch (e) { threw = true; }
ok("storage that refuses (private window) never breaks the page", !threw);
ok("an out-of-range step or check is refused, not stored", (() => { const m = mem(); const x = createStore(m); return x.toggleStep(9) === false && x.toggleCheck(9, 9) === false && x.toggleCheck(0, 99) === false && m.m.size === 0; })());
ok("a box not ticked reads 'Not checked yet', never 'clean'", checkStatus(0, 5) === "Not checked yet" && !/clean/i.test([checkStatus(0, 5), checkStatus(2, 5), checkStatus(5, 5)].join(" ")));
ok("ticking is described as YOU checking, so it is never the page's claim", /checked by you/.test(checkStatus(2, 5)) && /checked by you/.test(checkStatus(5, 5)));

// ---------------------------------------------------------------- nothing leaves the browser
console.log("no network, no secrets:");
const code = stripComments(siteJs) + "\n" + stripComments(coreJs);
ok("no network API anywhere in the guide code", !/\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|WebTransport|RTCPeerConnection)\b/.test(code) && !/navigator\s*\.\s*(serviceWorker|connection)/.test(code) && !/\bimport\s*\(/.test(code) && !/new\s+(Worker|SharedWorker)\b/.test(code) && !/new\s+Image\b/.test(code));
ok("no web address appears in the guide code at all", !/https?:\/\//i.test(code) && !/\/\/[a-z0-9.-]+\.[a-z]{2,}\//i.test(code));
ok("the only import is the page's own module", [...siteJs.matchAll(/^import .* from "([^"]+)"/gm)].every((m) => m[1] === "./guide-core.js") && !/^import /m.test(coreJs));
ok("no cookies, no tracking, no analytics", !/document\s*\.\s*cookie/.test(code) && !/gtag|googletag|analytics|plausible|matomo|segment|mixpanel|hotjar|fbq\(/i.test(html + siteJs + coreJs));
const refs = [...html.matchAll(/\b(?:src|href|action|formaction|poster|data)="([^"]*)"/g)].map((m) => m[1]);
const external = refs.filter((u) => /^(https?:)?\/\//i.test(u));
ok("the page's only outside links are the GitHub repo and its own address", external.every((u) => u === "https://github.com/RightOnPar-LLC/hideout" || u === "https://hideout.meshtool.ai/"), external.join(" "));
ok("no form, no iframe, no embed, no preconnect: nothing that could send", !/<form\b|<iframe\b|<embed\b|<object\b|rel="(preconnect|dns-prefetch|prefetch|preload)"/i.test(html));
ok("one script on the page, the site's own module, none inline", [...html.matchAll(/<script\b[^>]*>/g)].length === 1 && /<script type="module" src="\/site\.js"><\/script>/.test(html));
ok("the content security policy still forbids every outside connection", /default-src 'none'/.test(headers) && /script-src 'self'/.test(headers) && !/connect-src/.test(headers) && !/unsafe-inline|unsafe-eval|\*/.test(headers.split("Content-Security-Policy:")[1].split("\n")[0]));
ok("nothing asks for a password, key, token, seed phrase, card or account number", !/type="password"/i.test(html) && !/<input[^>]*(name|id|placeholder|aria-label)="[^"]*(password|passcode|secret|token|api.?key|seed|recovery.?phrase|card.?number|account.?number|routing|ssn|cvv|pin)\b/i.test(html));
ok("and it tells people never to paste one", /Never paste a key, token, password or recovery phrase/.test(adviceBlob) && /never asks for one/.test(adviceBlob));
ok("the site is still static assets only: no worker script, no workers.dev, one custom-domain route", !/^\s*main\s*=/m.test(wrangler) && /workers_dev = false/.test(wrangler) && /preview_urls = false/.test(wrangler) && (wrangler.match(/pattern = /g) || []).length === 1 && /hideout\.meshtool\.ai/.test(wrangler) && /directory = "\.\/public"/.test(wrangler));

// ---------------------------------------------------------------- honest states
console.log("honest states:");
ok("the fake chat is gone: no transcript, no chat bubbles", !/class="[^"]*\bmsg\b/.test(html) && !/class="[^"]*\bchat\b/.test(html) && !/you &gt;|guide &gt;/.test(html));
ok("the page says plainly that this guide is not an AI and has no network", panelText.includes("This guide is not an AI") && panelText.includes("It doesn't connect to anything") && NOT_AI.includes("not an AI"));
ok("the page says the AI guide is not switched on, in plain words", panelText.includes(AI_STATUS) && /isn't switched on yet/.test(AI_STATUS));
ok("no 'powered by' claim, no live badge, no 'live' on a local answer", !/powered by claude|powered by ai|ai-powered/i.test(html) && !/class="[^"]*\b(live|badge)\b/i.test(html) && !/\blive\b/i.test(panelText));
ok("the Windows download still reads 'coming soon', and nothing is linked to download", /Windows download — coming soon/.test(html) && /aria-disabled="true"/.test(html) && !/href="[^"]*\.(exe|msi|zip|msix)"/i.test(html) && !/href="[^"]*(download|releases)/i.test(html) && !/\b[a-f0-9]{64}\b/i.test(html) && !/download now/i.test(html));
ok("the two example screens say they are examples, not your PC", /not from your PC/.test(html) && /None of this came from your PC/.test(html));
const cleanCtx = [...panelText.matchAll(/\bclean\w*/gi)].map((m) => panelText.slice(Math.max(0, m.index - 16), m.index + 12).toLowerCase());
ok("the guide panel never calls anything clean (only 'clean device', 'clean up', and the sentence that says it can't)", cleanCtx.length > 0 && cleanCtx.every((w) => /anything is clean|clean device|clean up|clean-up/.test(w)), cleanCtx.join(" | "));
ok("it says it is general information, not legal or financial advice", /not legal or financial advice/.test(panelText));
ok("it says it never logs in, cancels or sends anything for you", /never logs in to your accounts, never cancels anything and never sends email for you/.test(panelText));
ok("what the person types is never saved or sent, and the page says so", /Nothing you type here is saved or sent anywhere/.test(panelText));

// ---------------------------------------------------------------- the page holds together
console.log("page structure:");
const ids = ["guide-kind", "guide-who", "guide-amt", "guide-date", "guide-build", "guide-copy", "guide-letter", "guide-clear", "guide-saved", "guide-copied", "guide-checks", "guide-ai-status", "guide-urgent"];
ok("every element the script reaches for exists on the page", ids.every((i) => html.includes(`id="${i}"`)) && ids.filter((i) => siteJs.includes(`"${i}"`)).every((i) => html.includes(`id="${i}"`)));
const opens = (html.match(/<div\b/g) || []).length, closes = (html.match(/<\/div>/g) || []).length;
ok("the page's div tags balance", opens === closes, `${opens} open, ${closes} close`);
ok("the three tabs and their panels are all still there", ["t-pc", "t-money", "t-guide", "p-pc", "p-money", "p-guide"].every((i) => html.includes(`id="${i}"`)));
ok("each step has a button, and a Clear button resets steps and checks", (html.match(/class="guide-step"/g) || []).length === 6 && /store\.clearAll\(\)/.test(siteJs));

// ---------------------------------------------------------------- human voice
console.log("plain words:");
const voiceBlob = [NOT_AI, AI_STATUS, URGENT.title, URGENT.lead, ...URGENT.steps, URGENT.after, ...STEPS.map((s) => s.title + ". " + s.text), ...CHECKS.flatMap((c) => [c.title, ...c.items, c.advice]), panelText].join(". ");
const jargon = /\b(leverage|utili[sz]e|seamless(ly)?|robust|empower(s|ed|ing)?|delve|streamline|cutting-edge|state-of-the-art|synerg\w+|unlock(s|ed|ing)?|journey|holistic|game-changer|revolutioni[sz]e|in today's|it'?s important to note|please note that|i'?m here to|let'?s dive|dive in|supercharge|next-level|elevate)\b/i;
ok("no marketing or AI jargon in any new sentence", !jargon.test(voiceBlob), (voiceBlob.match(jargon) || [])[0]);
ok("no exclamation marks, no emoji", !/!/.test(voiceBlob) && !/\p{Extended_Pictographic}/u.test(voiceBlob));
const sentences = voiceBlob.split(/(?<=[.?])\s+/);
const longest = sentences.reduce((a, b) => (b.split(/\s+/).length > a.split(/\s+/).length ? b : a), "");
ok("no sentence runs past 45 words (the longest is shown to the reviewer)", longest.split(/\s+/).length <= 45, `${longest.split(/\s+/).length} words: ${longest.slice(0, 80)}`);
console.log("      longest sentence:", longest.split(/\s+/).length, "words");

// ---------------------------------------------------------------- controls: each check can go red
console.log("controls (each of these must be caught):");
const hasNet = (src) => /\b(fetch|XMLHttpRequest|WebSocket|sendBeacon)\b/.test(stripComments(src));
ok("[control] a fetch() added to the guide code is caught", hasNet(coreJs + "\nfetch('/x')") && !hasNet(coreJs));
ok("[control] a fake chat bubble would be caught", /class="[^"]*\bmsg\b/.test(html + '<div class="msg bot">hi</div>') && !/class="[^"]*\bmsg\b/.test(html));
ok("[control] a password box would be caught", /type="password"/i.test(html + '<input type="password">'));
ok("[control] a download link would be caught", /href="[^"]*\.(exe|msi|zip|msix)"/i.test(html + '<a href="/Hideout.exe">') && !/href="[^"]*\.(exe|msi|zip|msix)"/i.test(html));
ok("[control] a step whose words differ from case.rs is detected", (() => { const bad = { ...STEPS[0], text: STEPS[0].text + " Then relax." }; return norm(bad.text) !== norm(rustSteps[0].text); })());
ok("[control] storing a typed letter would be caught (a non-boolean value)", (() => { const m = mem(); m.setItem("hideout-guide-steps", JSON.stringify({ 0: "Dear Example Co" })); return !createStore(m).stepDone(0); })());

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
