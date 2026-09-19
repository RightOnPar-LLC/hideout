// redact.mjs — everything sent to the AI guide passes through here first.
//
// Scan data is full of the user's identity: their Windows account name, their profile
// folder, their PC's name, and sometimes token-shaped strings in paths or snippets. The
// guide never needs any of that to help, so it never gets it. Placeholders keep the
// text readable ("C:\Users\<you>\AppData\...") so explanations still make sense.
import os from "node:os";
import fs from "node:fs";
import path from "node:path";

const LONG_TOKEN = /[A-Za-z0-9+/=_\-.%]{28,}/g;
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function collectIdentity() {
  const names = new Set();
  try { names.add(os.userInfo().username); } catch {}
  names.add(path.basename(os.homedir()));
  // Every profile folder on the machine: scan data names other accounts' paths too.
  try {
    for (const d of fs.readdirSync("C:\\Users", { withFileTypes: true })) {
      if (d.isDirectory() && !/^(public|default|default user|all users)$/i.test(d.name)) names.add(d.name);
    }
  } catch {}
  return {
    names: [...names].filter((n) => n && n.length >= 3),
    computer: os.hostname(),
  };
}

export function makeRedactor({ names = [], computer = "" } = {}) {
  const nameList = [...new Set(names)].filter((n) => n && n.length >= 3).sort((a, b) => b.length - a.length);
  const profileRe = nameList.length ? new RegExp(`([\\\\/]Users[\\\\/])(${nameList.map(esc).join("|")})(?=[\\\\/]|$|["'\\s])`, "gi") : null;
  const bareNameRe = nameList.length ? new RegExp(`(?<![A-Za-z0-9_])(${nameList.map(esc).join("|")})(?![A-Za-z0-9_])`, "gi") : null;
  const pcRe = computer && computer.length >= 3 ? new RegExp(`(?<![A-Za-z0-9_-])${esc(computer)}(?![A-Za-z0-9_-])`, "gi") : null;

  function text(s) {
    if (typeof s !== "string" || !s) return s;
    let r = s;
    if (profileRe) r = r.replace(profileRe, "$1<you>");
    if (pcRe) r = r.replace(pcRe, "<this-pc>");
    if (bareNameRe) r = r.replace(bareNameRe, "<you>");
    r = r.replace(LONG_TOKEN, (m) => (/^\[redacted/.test(m) ? m : `[redacted ${m.length} chars]`));
    return r;
  }
  function deep(v) {
    if (typeof v === "string") return text(v);
    if (Array.isArray(v)) return v.map(deep);
    if (v && typeof v === "object") {
      const o = {};
      for (const [k, val] of Object.entries(v)) o[k] = deep(val);
      return o;
    }
    return v;
  }
  return { text, deep };
}
