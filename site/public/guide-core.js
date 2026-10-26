// The guide on the website: the six steps, the letter writer and the deeper checks.
// This file is plain data and plain functions. It has no network code at all (no fetch, no
// XMLHttpRequest, no WebSocket, no beacons, no imports), and the page's content security policy
// would refuse a connection anyway. tests/guide.test.mjs checks both.
//
// The words come from the Rust guide in rust/crates/hideout-guide so the site and the app say the
// same thing: the six steps are the ones in case.rs (that file says they are "the website guide's
// list"), the letters follow letters.rs, the urgent box is offline.rs, and the check advice is
// checks.rs. tests/guide.test.mjs fails if they drift apart.

export const STEPS_KEY = "hideout-guide-steps";
export const CHECKS_KEY = "hideout-guide-checks";

export const NOT_AI = "This guide is not an AI. It's a checklist and a letter writer, and it runs in your browser. It doesn't connect to anything, and what you type stays on this page.";
export const AI_STATUS = "The AI guide isn't switched on yet. When it is, this page will say so plainly, and you'll be able to tell which answers come from it.";

export const URGENT = {
  title: "If it's happening right now",
  lead: "Someone controlling your mouse, a caller on the phone, a pop-up demanding payment:",
  steps: [
    "Hang up, and stop typing any codes.",
    "Take this PC off the internet. Switch Wi-Fi off, or pull the cable out.",
    "Don't pay anything, don't buy gift cards, and don't call a number shown in a pop-up.",
  ],
  after: "Then change your passwords from a different device you trust. Start with your email, then your bank.",
};

export const STEPS = [
  { title: "Stop the bleeding", text: "End the remote session, change passwords from a clean device, turn on two-step sign-in. Then let Windows Security clean up." },
  { title: "List what they took", text: "Money sent, cards used, accounts touched, and the date it happened." },
  { title: "Call your bank", text: "On the number printed on your card — not a number from the caller. Say it was a scam." },
  { title: "Check for still-charging", text: "Any company charging again after you cancelled, with the cancel date and the charge date." },
  { title: "Send the letters", text: "One at a time. Keep copies." },
  { title: "Watch for the second scam", text: "Anyone offering to \"recover\" your money for a fee, a gift card or remote access is a scam. Only your bank, your card company or the official fraud-reporting service can help." },
];

// Things the person looks at themselves. This page cannot see their PC or their accounts.
export const CHECKS = [
  {
    id: "scam-drift", title: "Scam drift since the scam date",
    items: [
      "New scheduled tasks, services or programs that start when you sign in",
      "New user accounts on the PC",
      "Password or recovery-email changes on your accounts",
      "New email forwarding rules",
      "New devices signed in to your accounts",
    ],
    advice: "Check these from a device you trust. This page can't log in to look for you, and neither can Hideout.",
  },
  {
    id: "test-charges", title: "Small test charges first",
    items: [
      "Charges of $2 or less that you don't recognise",
      "Anything large that came soon after one of them",
    ],
    advice: "Scammers often try a tiny charge first to see if a card works. If you don't recognise one, tell your bank about it and anything large that came after.",
  },
  {
    id: "leaks", title: "API and secret leaks — look, never paste",
    items: [
      "Files in your startup folders, Downloads or Documents that hold a key, token, password or recovery phrase",
    ],
    advice: "If a file holds one, rotate it at its provider first (make a new one, cancel the old one), then delete the file. Never paste a key, token, password or recovery phrase into this guide, into email, or into chat. This page never asks for one, and a real guide never will.",
  },
  {
    id: "rogue-ai", title: "Rogue AI and agents",
    items: [
      "AI browser extensions or agent tools you didn't install",
      "Remote-access programs installed around the scam date",
      "Anything set to run by itself that can read your screen, files or browser",
    ],
    advice: "If you didn't install it, treat it as part of the scam until proven otherwise. Remove it through Windows Settings > Apps, after the Windows Security scans.",
  },
  {
    id: "evidence", title: "Drifting evidence — preserve it",
    items: [
      "Screenshots of the charges, with transaction IDs and dates",
      "The suspicious files, emails and call logs, left exactly where they are",
    ],
    advice: "Don't delete suspicious files, emails, call logs or transaction records before your bank or a report asks for them. A file changed after signing, a new folder with a machine-made name, and a task created after the scam date are evidence, not just clutter.",
  },
  {
    id: "browser-drift", title: "Browser drift",
    items: [
      "Your homepage or search engine changed",
      "Extensions you don't recognise",
      "Saved passwords exported",
      "New bookmarks to bank sites you don't use",
    ],
    advice: "Reset these from your browser's settings, on a clean device if you can.",
  },
];

export const LETTER_KINDS = [
  { id: "bank_dispute", label: "Dispute a charge with my bank" },
  { id: "refund_request", label: "Ask a company for a refund" },
  { id: "cancel_by_email", label: "Cancel a subscription by email" },
];

export const LETTER_PLACEHOLDER = "Your letter will appear here. Read it, fill in the [brackets], delete any [Confirm: …] line that isn't true, and send it yourself. This page never sends anything.";

const SIGN = "[Your name] · [Last 4 digits of card] · [Phone number]";
const orBlank = (v, placeholder) => { const t = String(v == null ? "" : v).trim(); return t || placeholder; };

// Everything the person didn't type becomes a [placeholder] or a [Confirm: ...] line. Nothing is guessed.
export function buildLetter(kind, typed) {
  const t = typed || {};
  const who = orBlank(t.who, "");
  const name = orBlank(t.who, "[Company name]");
  const amount = orBlank(t.amount, "[$ amount]");
  const date = orBlank(t.date, "[Date charged]");
  if (kind === "cancel_by_email") {
    return `To ${name}:\n\nPlease cancel my subscription, effective today, and stop all future charges.\n\nThe account is under [Email on the account].\n\nPlease confirm the cancellation in writing, with the date it takes effect.\n\n[Your name]`;
  }
  if (kind === "refund_request") {
    return `To ${name}:\n\nI am asking for a refund of the ${amount} charged on ${date}. [Confirm: the reason.]\n\nPlease refund it to the card it was charged to, and confirm in writing.\n\n${SIGN}`;
  }
  const from = who ? ` from ${who}` : " from [Company name]";
  return `To [Bank or card company]:\n\nI am disputing a charge of ${amount} on ${orBlank(t.date, "[Date]")}${from}. [Confirm: this charge was taken after I cancelled, or was not authorised by me.]\n\nPlease reverse this charge and block further charges from this merchant.\n\n${SIGN}`;
}

// Progress lives in the browser's own storage and nowhere else. Only "done" flags are ever written:
// no letter text, no names, no amounts, no dates. A storage that throws (private windows) never breaks the page.
export function createStore(storage) {
  const read = (key, valid) => {
    let raw = null;
    try { raw = JSON.parse(storage.getItem(key) || "{}"); } catch (e) { raw = null; }
    const out = {};
    if (raw && typeof raw === "object" && !Array.isArray(raw)) for (const k of Object.keys(raw)) if (raw[k] === true && valid(k)) out[k] = true;
    return out;
  };
  const write = (key, obj) => { try { if (Object.keys(obj).length) storage.setItem(key, JSON.stringify(obj)); else storage.removeItem(key); } catch (e) { /* keep going, just not saved */ } };
  const validStep = (k) => /^[0-5]$/.test(k);
  const validCheck = (k) => { const m = /^(\d)\.(\d)$/.exec(k); return !!m && !!CHECKS[+m[1]] && +m[2] < CHECKS[+m[1]].items.length; };
  let steps = read(STEPS_KEY, validStep);
  let checks = read(CHECKS_KEY, validCheck);
  return {
    stepDone: (i) => !!steps[String(i)],
    checkDone: (c, i) => !!checks[`${c}.${i}`],
    toggleStep(i) { const k = String(i); if (!validStep(k)) return false; if (steps[k]) delete steps[k]; else steps[k] = true; write(STEPS_KEY, steps); return !!steps[k]; },
    toggleCheck(c, i) { const k = `${c}.${i}`; if (!validCheck(k)) return false; if (checks[k]) delete checks[k]; else checks[k] = true; write(CHECKS_KEY, checks); return !!checks[k]; },
    checkedIn(c) { return CHECKS[c].items.filter((_, i) => checks[`${c}.${i}`]).length; },
    clearAll() { steps = {}; checks = {}; try { storage.removeItem(STEPS_KEY); storage.removeItem(CHECKS_KEY); } catch (e) { /* nothing to clear */ } },
    anySaved: () => Object.keys(steps).length + Object.keys(checks).length > 0,
  };
}

// Never "clean": a box you haven't ticked is "not checked yet", and ticking means YOU checked.
export function checkStatus(done, total) {
  if (done === 0) return "Not checked yet";
  if (done < total) return `${done} of ${total} checked by you`;
  return `All ${total} checked by you`;
}
