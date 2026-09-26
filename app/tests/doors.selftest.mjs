// Hideout Doors & power selftest - the D-series public-repo-hygiene guards.
//
// PR0 SCOPE: this file lands BEFORE any doors.ps1 / app/src/doors/** code exists
// (see AGENTS.md / .github/copilot-instructions.md's own FOLDED-FROM note once
// PR2 ships one). Its job right now is narrow but load-bearing: prove the two
// governance door files this PR commits (AGENTS.md, .github/copilot-instructions.md)
// carry the PUBLIC template and nothing private, and stand up the reusable guard
// functions (the estate-denylist scanner, the fabricated-name allow-list, the
// untracked-file sweep) that PR1's doors.ps1 and PR2's fixtures will be run
// through as they land - "applied to every shipped doors file and every fixture."
//
// WHY THE GUARD ITSELF NAMES NO ESTATE WORD: a denylist that hardcodes the very
// words it exists to keep out of a public repo would be self-defeating - this
// file's own source is one of the things it scans. So every pattern below is
// either (a) fully generic (a Windows/Unix home-path shape, the private door's
// own sentinel text, the ${ESTATE_ROOT} token) or (b) computed at RUNTIME from
// this machine (the account name, the computer name, the home-folder name -
// mirrors F4 in money.selftest.mjs) or (c) loaded, only when present, from the
// estate's own PRIVATE governance config (never shipped in this repo, never
// hardcoded here) so a builder on the estate's own machines gets the full
// estate-specific check while a stranger cloning this public repo still gets
// the generic + identity checks in full.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { collectIdentity } from "../src/redact.mjs";
import { decodeLastTaskResult, decodeBitLockerShellProperty } from "../src/doors/decode.mjs";
import {
  summarizeRemoteDesktop, summarizeExtraAccount, summarizeDiskEncryption, mapAdminBitlockerVolume,
  summarizeRemoteSupport, summarizeAntivirus, summarizeLeftovers, markRanFlat, summarizeSuddenShutdowns,
  clusterEpisodes, summarizeBatteryAndCharger, summarizeSleepTimers, summarizeRestartWaiting,
  summarizeStartupHealth, summarizeDiskSpace, summarizeDiskSpaceGroup, summarizeSpeedCap,
} from "../src/doors/summarize.mjs";

const APP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ROOT = path.resolve(APP, "..");
let pass = 0, fail = 0;
const check = (name, ok, detail = "") => { if (ok) { pass++; console.log(`  ok    ${name}`); } else { fail++; console.log(`  FAIL  ${name}  ${detail}`); } };

// ------------------------------------------------------------------ the scanner (pure, mirrors public-door.mjs's scanForLeaks)
export function scanText(text, patterns) {
  const t = String(text ?? "");
  const hits = [];
  for (const { id, re } of patterns) {
    const m = t.match(re);
    if (m) hits.push({ id, excerpt: String(m[0]).trim().slice(0, 60) });
  }
  return hits;
}

// ------------------------------------------------------------------ generic patterns (no proper nouns - safe to ship)
export const GENERIC_FORBID = [
  { id: "laws-block", re: /ESTATE-LAWS:/ },
  { id: "estate-root-token", re: /\$\{ESTATE_ROOT\}/ },
  { id: "private-door-marker", re: /Editor-agent door —/ },
  { id: "windows-home-path", re: /\b[A-Za-z]:\\+Users\\+[^\\\s`'"]+/ },
  { id: "unix-home-path", re: /(^|[\s`'"(])\/(home|Users)\/[A-Za-z0-9._-]+\//m },
];

// ------------------------------------------------------------------ identity patterns (computed at runtime, never hardcoded - mirrors money.selftest.mjs F4)
// MEASURED on this machine: collectIdentity()'s own exclude regex
// (/^(public|default|default user|all users)$/i, redact.mjs:21) does not exclude
// a literal "user" profile folder, so its names list can include a plain
// dictionary word that legitimately appears in ordinary source/docs everywhere
// - it flagged 13 unrelated files here before this filter was added. Filtered
// HERE (the widened denylist's own consumption of the list), not in redact.mjs:
// that file feeds the live redactor shown scan data, a different, more
// sensitive code path where a false NEGATIVE (missing a real account name)
// matters far more than a false positive here, so tightening its exclude list
// deserves its own dedicated change, not a drive-by from this hygiene PR.
const GENERIC_ACCOUNT_NOISE = new Set(["user", "users", "admin", "administrator", "guest", "test", "default", "public", "owner", "service", "temp"]);
export function identityPatterns() {
  const id = collectIdentity();
  const names = new Set([os.userInfo().username, process.env.COMPUTERNAME, path.basename(os.homedir()), id.computer, ...id.names].filter((n) => n && n.length > 3 && !GENERIC_ACCOUNT_NOISE.has(n.toLowerCase())));
  return [...names].map((n) => ({ id: `identity:${n.length}chars`, raw: n, re: new RegExp(`(?<![A-Za-z0-9_])${n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![A-Za-z0-9_])`, "i") }));
}

// ------------------------------------------------------------------ the estate's own extra patterns, loaded ONLY when present on this machine - never
// shipped in this repo. A stranger building this public repo simply does not have
// this file, and the generic + identity checks above still run in full.
export function estatePatterns() {
  // ONLY the env var — never a hardcoded estate path literal in committed source.
  // (A previous version of this function fell back to a literal default candidate
  // path when the env var was unset; that literal was itself an estate path shipped
  // in this public repo's source, exactly the class of leak this file exists to
  // catch. Fixed 2026-09-25: a stranger cloning this repo, or a builder who has not
  // set the env var, gets `null` here and the generic + identity checks still run
  // in full — see the file-header comment above for why that degrade is correct.)
  const candidates = [process.env.HIDEOUT_GOVERNANCE_CONFIG].filter(Boolean);
  for (const p of candidates) {
    try {
      const cfg = JSON.parse(fs.readFileSync(p, "utf8"));
      const extra = cfg?.doors?.publicForbid;
      if (Array.isArray(extra) && extra.length) return extra.map((src) => ({ id: `estate:${src}`, re: new RegExp(String(src), "i") }));
    } catch { /* not on this machine - fine, this layer is a bonus */ }
  }
  return null;
}

const estate = estatePatterns();
const ALL_FORBID = [...GENERIC_FORBID, ...identityPatterns(), ...(estate ?? [])];
console.log(estate ? `  (estate governance config found - checking its ${estate.length} extra pattern(s) too)` : "  (estate governance config not on this machine - generic + identity checks only)");

// ------------------------------------------------------------------ D1: the two committed door files carry the PUBLIC template, cleanly
{
  const doorFiles = ["AGENTS.md", ".github/copilot-instructions.md"];
  for (const f of doorFiles) {
    const p = path.join(ROOT, f);
    const exists = fs.existsSync(p);
    check(`D1 ${f} exists and is tracked (public door committed)`, exists);
    if (!exists) continue;
    const text = fs.readFileSync(p, "utf8");
    check(`D1 ${f} carries the public door heading, not the private one`, /## Agent operating rules/.test(text) && !/# Editor-agent door/.test(text));
    const hits = scanText(text, ALL_FORBID);
    check(`D1 ${f} has zero estate-denylist / identity hits`, hits.length === 0, hits.map((h) => h.id).join(", "));
  }
  const tracked = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" }).split("\n").map((s) => s.trim()).filter(Boolean);
  check("D1 both door files are TRACKED (git ls-files), not merely present on disk", doorFiles.every((f) => tracked.includes(f)));
}

// ------------------------------------------------------------------ D2: negative control - the scanner actually fires (fabricated tokens only, never a real estate word)
{
  const fixture = [{ id: "fixture-token", re: /faketown-9182/ }];
  check("D2 scanner flags a planted fixture token", scanText("this text contains faketown-9182 somewhere", fixture).length === 1);
  check("D2 scanner is clean when the token is absent", scanText("this text contains nothing of note", fixture).length === 0);
  // Both directions on the real generic list too, same style as the governance engine's own selftest.
  check("D2b generic list flags its own private-door marker", scanText("# Editor-agent door — control-repo", GENERIC_FORBID).length >= 1);
  check("D2c generic list is clean on ordinary prose", scanText("This project reads its config from environment variables.", GENERIC_FORBID).length === 0);
  // Identity patterns: prove they fire on THIS machine's own identifiers (planted in synthetic text, never in a shipped file).
  const idPats = identityPatterns();
  if (idPats.length) {
    check("D2d identity pattern fires on a synthetic string carrying it", scanText(`synthetic ${idPats[0].raw} example`, [idPats[0]]).length === 1);
  } else console.log("  skip  D2d (no identity strings long enough on this machine to probe)");
}

// ------------------------------------------------------------------ D3: fabricated-name allow-list (forward scaffolding for PR2's doors fixtures)
export const ALLOWED_FAKE_NAMES = new Set(["Nina", "helper-account", "HOME-PC", "Photo Sync", "Printer Helper"]);
export function checkFabricatedNames(names) {
  return names.filter((n) => !ALLOWED_FAKE_NAMES.has(n));
}
{
  check("D3 every allowed fake name passes its own allow-list", checkFabricatedNames([...ALLOWED_FAKE_NAMES]).length === 0);
  check("D3 a name outside the allow-list is rejected (proves the guard isn't vacuous)", checkFabricatedNames(["Nina", "RealSoundingSurname"]).length === 1);
}

// ------------------------------------------------------------------ D4: untracked-file sweep - the exact PR0 hazard (an untracked private door
// re-appearing and riding along on a bare `git add .`). MEASURED on the canonical
// checkout: its private AGENTS.md / .github/copilot-instructions.md are hidden
// from plain `git status` by a LOCAL .git/info/exclude entry (not .gitignore) -
// a rule that is itself invisible unless you go looking for it, and that a bare
// `git status --porcelain` respects. `git ls-files --others` WITHOUT
// --exclude-standard ignores every exclude rule (.gitignore AND
// .git/info/exclude) and so still sees such a file; node_modules/dist/out/
// .wrangler/build are the ordinary, expected reason a file is untracked and are
// carved out, so this stays a signal, not noise on every `npm ci`.
{
  const EXPECTED_IGNORED = /(^|\/)(node_modules|dist|out|\.wrangler|build)\//;
  const listOthers = (extra) => execFileSync("git", ["ls-files", "--others", ...extra], { cwd: ROOT, encoding: "utf8" }).split("\n").map((s) => s.trim()).filter(Boolean);
  const visible = listOthers(["--exclude-standard"]); // what a plain `git status` shows
  const raw = listOthers([]); // ignores every exclude rule, including a LOCAL .git/info/exclude
  const hiddenOnly = raw.filter((f) => !visible.includes(f) && !EXPECTED_IGNORED.test(f));
  check("D4 no source-tree file is hidden from `git status` by an exclude rule (.gitignore or a local .git/info/exclude) outside the expected dependency/build dirs", hiddenOnly.length === 0, hiddenOnly.join(", "));

  const candidates = [...new Set([...visible, ...hiddenOnly])].filter((f) => !EXPECTED_IGNORED.test(f));
  const TEXTY = /\.(md|mjs|js|json|html|css|ps1|cmd|toml|txt|svg)$/i;
  const leaked = [];
  for (const rel of candidates) {
    const hitsPath = scanText(rel, ALL_FORBID);
    if (hitsPath.length) { leaked.push(`${rel} [path: ${hitsPath.map((h) => h.id).join(",")}]`); continue; }
    if (!TEXTY.test(rel)) continue;
    try {
      const hitsBody = scanText(fs.readFileSync(path.join(ROOT, rel), "utf8"), ALL_FORBID);
      if (hitsBody.length) leaked.push(`${rel} [content: ${hitsBody.map((h) => h.id).join(",")}]`);
    } catch { /* unreadable/binary - not a text leak vector */ }
  }
  check("D4 no untracked file (visible or exclude-hidden) matches the estate-denylist / identity patterns by path or content", leaked.length === 0, leaked.join("; "));
}

// ------------------------------------------------------------------ D5: every shipped DOORS file and fixture, whole-file (mirrors the governance
// engine's public-repo scan: prose OUTSIDE any marker block leaks just as well
// as inside one) - publicRepoGuards item 3's own scope ("applied to every
// shipped doors file and every fixture"), not the whole pre-existing Money/
// engine tree: those files legitimately discuss and test path redaction with
// FAKE example Windows paths (redact.mjs's own doc comment, selftest.mjs's
// redaction fixtures), which the generic windows-home-path SHAPE pattern will
// always flag on sight - correctly, for a doors file that has no business
// containing one; a false positive everywhere else in a codebase whose whole
// point is discussing paths. The identity check across the WHOLE tree is F4's
// job (money.selftest.mjs), already widened there.
{
  const DOORS_GLOBS = ["doors.ps1", "app/src/doors", "app/tests/fixtures/doors"];
  const tracked = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" }).split("\n").map((s) => s.trim()).filter(Boolean);
  const doorsFiles = tracked.filter((rel) => DOORS_GLOBS.some((g) => rel === g || rel.startsWith(g + "/")));
  if (doorsFiles.length === 0) {
    console.log("  skip  D5 (no doors.ps1 / app/src/doors/** / app/tests/fixtures/doors/** yet - PR1+ lands them; this guard runs the moment they exist)");
  } else {
    const leaked = [];
    for (const rel of doorsFiles) {
      let text; try { text = fs.readFileSync(path.join(ROOT, rel), "utf8"); } catch { continue; }
      const hits = scanText(text, ALL_FORBID);
      if (hits.length) leaked.push(`${rel} [${hits.map((h) => h.id).join(",")}]`);
    }
    check("D5 no shipped doors file or fixture (whole file, not just inside a managed block) matches the estate-denylist / identity / path-shape patterns", leaked.length === 0, leaked.join("; "));
  }
}

// ------------------------------------------------------------------ E: decode.mjs / summarize.mjs -
// PR1's verdict layer, tested against JSON fixtures per engineChecks' own test descriptions.
// Every fixture name below is either generic (a made-up drive letter, a code, a boolean) or
// drawn from the D3 fabricated-name allow-list - never a real machine's data.

// -- decode.mjs --
{
  check("E0 LastTaskResult 0 decodes to ran", decodeLastTaskResult(0) === "ran");
  check("E0 LastTaskResult 267009 decodes to running", decodeLastTaskResult(267009) === "running");
  check("E0 LastTaskResult 267011 decodes to never-ran", decodeLastTaskResult(267011) === "never-ran");
  check("E0 LastTaskResult 0x800710E0 decodes to refused-by-condition, never 'failed'", decodeLastTaskResult(0x800710e0) === "refused-by-condition");
  check("E0 LastTaskResult 0xC000013A decodes to killed-at-signout, never 'failed'", decodeLastTaskResult(0xc000013a) === "killed-at-signout");
  check("E0 an unrecognised nonzero result is 'failed'", decodeLastTaskResult(17) === "failed");
  check("E0 a missing result is not_checked, never 'ran'", decodeLastTaskResult(null) === "not_checked" && decodeLastTaskResult("") === "not_checked");

  check("E0 BitLocker shell property 1 -> on", decodeBitLockerShellProperty(1) === "on");
  check("E0 BitLocker shell property 2 -> off", decodeBitLockerShellProperty(2) === "off");
  check("E0 BitLocker shell property 5 -> paused", decodeBitLockerShellProperty(5) === "paused");
  check("E0 BitLocker shell property 0 -> not_checked, never 'off' (ambiguous, never guessed shut)", decodeBitLockerShellProperty(0) === "not_checked");
  check("E0 BitLocker shell property empty -> not_checked", decodeBitLockerShellProperty("") === "not_checked" && decodeBitLockerShellProperty(null) === "not_checked");
}

// -- doors.remoteDesktop (engineChecks fixtures a-g) --
{
  const base = { fDeny: 0, remoteSessions: [], firewall: { checked: true, enabledRuleCount: 2 } };
  check("E1a fDeny=0 + 2 enabled rules -> open", summarizeRemoteDesktop(base).verdict === "open");
  check("E1b fDeny=1 -> shut", summarizeRemoteDesktop({ fDeny: 1 }).verdict === "shut");
  check("E1c key missing -> not_checked", summarizeRemoteDesktop({ fDeny: null }).verdict === "not_checked");
  check("E1d fDeny=0 + a remote session -> open-and-connected", summarizeRemoteDesktop({ ...base, remoteSessions: [{ startTime: "2026-01-01T00:00:00" }] }).verdict === "open-and-connected");
  check("E1e fDeny=0 + zero enabled rules -> open-but-blocked", summarizeRemoteDesktop({ ...base, firewall: { checked: true, enabledRuleCount: 0 } }).verdict === "open-but-blocked");
  { const r = summarizeRemoteDesktop({ ...base, partOfDomain: true }); check("E1f PartOfDomain=true -> set-by-your-organisation, doorOpen false", r.verdict === "set-by-your-organisation" && r.doorOpen === false); }
  { const r = summarizeRemoteDesktop({ ...base, firewall: { checked: false, enabledRuleCount: null } }); check("E1g firewall section threw -> row still open, firewall detail not_checked", r.verdict === "open" && r.firewallDetail === "not_checked"); }
  check("E1h the inverted boolean is asserted both ways (a sign flip fails this suite)", summarizeRemoteDesktop({ fDeny: 0, remoteSessions: [] }).doorOpen === true && summarizeRemoteDesktop({ fDeny: 1 }).doorOpen === false);
}

// -- doors.extraAccount (engineChecks fixtures a-g, fabricated names only) --
{
  const acct = (name, extra = {}) => ({ name, enabled: true, passwordRequired: false, passwordLastSet: "", principalSource: "Local", ...extra });
  check("E2a enabled admin, PasswordRequired=false, PasswordLastSet empty -> open", summarizeExtraAccount({ administrators: [acct("helper-account")], builtinsPresent: true }).verdict === "open");
  check("E2b same with a PasswordLastSet date -> worth-a-look", summarizeExtraAccount({ administrators: [acct("helper-account", { passwordLastSet: "2026-01-01T00:00:00" })], builtinsPresent: true }).verdict === "worth-a-look");
  check("E2c Enabled=false -> shut", summarizeExtraAccount({ administrators: [acct("helper-account", { enabled: false })], builtinsPresent: true }).verdict === "shut");
  check("E2d two enabled admins with passwords -> worth-a-look (second-admin)", summarizeExtraAccount({ administrators: [acct("Nina", { passwordRequired: true }), acct("helper-account", { passwordRequired: true })], builtinsPresent: true }).verdict === "worth-a-look");
  check("E2e built-ins missing from the list -> not_checked", summarizeExtraAccount({ administrators: [acct("Nina")], builtinsPresent: false }).verdict === "not_checked");
  check("E2f PartOfDomain=true -> set-by-your-organisation", summarizeExtraAccount({ administrators: [acct("Nina")], builtinsPresent: true, partOfDomain: true }).verdict === "set-by-your-organisation");
  check("E2g a MicrosoftAccount/AzureAD admin is never judged on PasswordRequired", summarizeExtraAccount({ administrators: [acct("Nina", { principalSource: "MicrosoftAccount" })], builtinsPresent: true }).verdict === "shut");
}

// -- doors.diskEncryption (engineChecks fixtures a-e) --
{
  check("E3a value 1 -> on", summarizeDiskEncryption({ shellProperty: 1 }).verdict === "on");
  { const r = summarizeDiskEncryption({ shellProperty: 2 }); check("E3b value 2 -> off / quick", r.verdict === "off" && r.confidence === "quick"); }
  check("E3c empty -> not_checked", summarizeDiskEncryption({ shellProperty: "" }).verdict === "not_checked");
  check("E3d value 5 -> paused", summarizeDiskEncryption({ shellProperty: 5 }).verdict === "paused");
  { const r = summarizeDiskEncryption({ shellProperty: 2, admin: { verdict: "on" } }); check("E3e a newer admin snapshot says on -> on / admin (overrides the quick reading)", r.verdict === "on" && r.confidence === "admin"); }
  check("E3f admin volume mapping: FullyEncrypted + On -> on", mapAdminBitlockerVolume({ volumeStatus: "FullyEncrypted", protectionStatus: "On" }) === "on");
  check("E3g admin volume mapping: FullyEncrypted + Off -> paused", mapAdminBitlockerVolume({ volumeStatus: "FullyEncrypted", protectionStatus: "Off" }) === "paused");
  check("E3h admin volume mapping: FullyDecrypted -> off", mapAdminBitlockerVolume({ volumeStatus: "FullyDecrypted" }) === "off");
}

// -- doors.remoteSupport --
{
  check("E4a installed ['AnyDesk'] -> installed", summarizeRemoteSupport({ installedMatches: ["AnyDesk"], knownProcessSeen: true }).verdict === "installed");
  check("E4b a live process match -> running-now (beats installed)", summarizeRemoteSupport({ installedMatches: ["AnyDesk"], runningMatches: ["Zoho Assist"], knownProcessSeen: true }).verdict === "running-now");
  check("E4c nothing installed or running -> none", summarizeRemoteSupport({ knownProcessSeen: true }).verdict === "none");
  check("E4d a process list without explorer/svchost -> not_checked", summarizeRemoteSupport({ knownProcessSeen: false }).verdict === "not_checked");
}

// -- doors.antivirus (engineChecks fixtures a-e) --
{
  { const r = summarizeAntivirus({ amRunningMode: "Normal", fullScanEndTime: "" }, { leftoversCount: 0 }); check("E5a Normal, never scanned, no leftovers -> fine + suggestion only", r.verdict === "fine" && r.suggestions.includes("full-scan-never")); }
  check("E5b same with leftovers=2 -> counts as open (full-scan-never)", summarizeAntivirus({ amRunningMode: "Normal", fullScanEndTime: "" }, { leftoversCount: 2 }).verdict === "full-scan-never");
  check("E5c Passive -> other-antivirus", summarizeAntivirus({ amRunningMode: "Passive", fullScanEndTime: "2026-01-01T00:00:00" }).verdict === "other-antivirus");
  check("E5d RealTimeProtectionEnabled=false -> open", summarizeAntivirus({ amRunningMode: "Normal", realTimeProtectionEnabled: false, fullScanEndTime: "2026-01-01T00:00:00" }).verdict === "open");
  check("E5e empty object -> not_checked", summarizeAntivirus({}).verdict === "not_checked");
  check("E5f real-time protection ON is never treated as 'already scanned' (the suggestion still fires)", summarizeAntivirus({ amRunningMode: "Normal", realTimeProtectionEnabled: true, fullScanEndTime: "" }).suggestions.includes("full-scan-never"));
}

// -- doors.leftovers --
{
  check("E6a no findings -> none, deleteAllowed false", summarizeLeftovers({ findingsCount: 0 }).verdict === "none" && summarizeLeftovers({ findingsCount: 0 }).deleteAllowed === false);
  check("E6b findings + no scan evidence + step not done -> deleteAllowed false", summarizeLeftovers({ findingsCount: 2, newestFindingArrivedAt: "2026-01-10", quickScanEndTime: "2026-01-05", folderScanStepDone: false }).deleteAllowed === false);
  { const r = summarizeLeftovers({ findingsCount: 2, newestFindingArrivedAt: "2026-01-10", fullScanEndTime: "2026-01-15" }); check("E6c a scan end time after the newest arrival -> unlocked by evidence", r.deleteAllowed === true && r.unlockedBy === "evidence"); }
  { const r = summarizeLeftovers({ findingsCount: 2, newestFindingArrivedAt: "2026-01-10", quickScanEndTime: "2026-01-05", folderScanStepDone: true }); check("E6d scan before arrival + step done -> unlocked by your word", r.deleteAllowed === true && r.unlockedBy === "your-word"); }
  check("E6e no scan yet -> not_checked", summarizeLeftovers({ findingsCount: 2, newestFindingArrivedAt: "2026-01-10" }).verdict === "not_checked");
  check("E6f deleting is never allowed before the gate opens, regardless of findings count", summarizeLeftovers({ findingsCount: 50 }).deleteAllowed === false);
}

// -- power.suddenShutdowns (engineChecks fixtures a-f) --
{
  const kp41a = Array.from({ length: 6 }, (_, i) => ({ timeCreated: `2026-01-0${(i % 9) + 1}T00:00:00`, bugcheckCode: 0, powerButtonTimestamp: 0 }));
  { const r = summarizeSuddenShutdowns({ kp41: kp41a, count1001: 0, minidumps: [], memoryDmp: false, crashDumpEnabled: 3, controlSampleCount: 50 }); check("E7a 6 KP41 bugcheck0, no evidence, CrashDumpEnabled=3 -> soon / power-loss", r.verdict === "soon" && r.classes.every((c) => c === "power-loss")); }
  { const r = summarizeSuddenShutdowns({ kp41: kp41a, count1001: 0, minidumps: [], memoryDmp: false, crashDumpEnabled: 0, controlSampleCount: 50 }); check("E7b same with CrashDumpEnabled=0 -> cant-tell", r.classes.every((c) => c === "cant-tell")); }
  { const r = summarizeSuddenShutdowns({ kp41: [{ timeCreated: "2026-01-01T00:00:00", bugcheckCode: "0x9F", powerButtonTimestamp: 0 }], count1001: 1, controlSampleCount: 50 }); check("E7c 1 KP41 0x9F + one 1001 -> note / crash", r.verdict === "note" && r.classes[0] === "crash"); }
  check("E7d control query unreadable -> not_checked", summarizeSuddenShutdowns({ kp41: kp41a, controlSampleCount: null }).verdict === "not_checked");
  { const r = summarizeSuddenShutdowns({ kp41: [{ timeCreated: "2026-01-01T00:00:00", bugcheckCode: 0, powerButtonTimestamp: 12345 }], controlSampleCount: 50 }); check("E7e PowerButtonTimestamp set -> held-power-button", r.classes[0] === "held-power-button"); }
  { const kp41ranFlat = [{ timeCreated: "2026-01-01T00:05:00" }, { timeCreated: "2026-01-02T00:05:00" }, { timeCreated: "2026-01-03T00:05:00" }];
    const kp524 = [{ timeCreated: "2026-01-01T00:03:00" }, { timeCreated: "2026-01-02T00:03:00" }, { timeCreated: "2026-01-03T00:03:00" }];
    const marked = markRanFlat(kp41ranFlat, kp524);
    const r = summarizeSuddenShutdowns({ kp41: marked, controlSampleCount: 10 });
    check("E7f 3 KP41 each preceded by a KP524 -> ran-flat 3, headline count 0", r.ranFlatCount === 3 && r.count === 0); }
}

// -- power.batteryAndCharger (engineChecks fixtures a-f) --
{
  const oneCluster = Array.from({ length: 30 }, (_, i) => ({ timeCreated: new Date(Date.parse("2026-01-01T00:00:00Z") + i * 1000).toISOString() }));
  check("E8a 30 reversals inside one 60s cluster on one day -> 1 episode, fine", clusterEpisodes(oneCluster).length === 1 && summarizeBatteryAndCharger({ hasBattery: true, kp105: oneCluster }).verdict === "fine");
  { const sixDays = [0, 1, 2, 3, 4, 5].map((d) => ({ timeCreated: `2026-01-0${d + 1}T12:00:00Z` })); const r = summarizeBatteryAndCharger({ hasBattery: true, kp105: sixDays }); check("E8b 6 distinct-day episodes -> soon", r.verdict === "soon" && r.chargerEpisodeDays === 6); }
  check("E8c died plugged in 2+ times -> fix-now", summarizeBatteryAndCharger({ hasBattery: true, diedPluggedInCount: 2 }).verdict === "fix-now");
  check("E8d no Win32_Battery -> no-battery", summarizeBatteryAndCharger({ hasBattery: false }).verdict === "no-battery");
  { const r = summarizeBatteryAndCharger({ hasBattery: true, designedCapacity: 0, kp105: oneCluster }); check("E8e DesignedCapacity 0 -> health null, episodes still counted", r.health === null && r.chargerEpisodeDays === 1); }
  check("E8f hasBattery null (control never answered) -> not_checked", summarizeBatteryAndCharger({}).verdict === "not_checked");
  check("E8g no implied watt arithmetic anywhere in this file", !/\bwatt/i.test(fs.readFileSync(path.join(APP, "src/doors/summarize.mjs"), "utf8")));
}

// -- power.sleepTimers (engineChecks fixtures a-e) --
{
  { const r = summarizeSleepTimers({ standbyIdleAc: 0, videoIdleAc: 300, videoConLockAc: 30, modelListed: true, registryOk: true }); check("E9a Modern Standby (STANDBYIDLE=0, VIDEOIDLE=300) -> effective 5 minutes alone, 30s after lock", r.verdict === "info" && r.standbyMinutes === 5 && r.videoConLockSeconds === 30); }
  { const r = summarizeSleepTimers({ standbyIdleAc: 0, videoIdleAc: 300, modelListed: false, registryOk: true }); check("E9b unmatched /a text (e.g. localized) -> model unknown, timers still read", r.modelKnown === false && r.standbyMinutes === 5); }
  { const r = summarizeSleepTimers({ standbyIdleAc: 30, videoIdleAc: 60, registryOk: true, qhAgrees: false }); check("E9c registry and powercfg disagree -> not_checked, never a guess", r.verdict === "not_checked"); }
  { const r = summarizeSleepTimers({ standbyIdleAc: 0, videoIdleAc: 300, registryOk: true }, { pcMustStayOn: true }); check("E9d pc_must_stay_on + 5 minutes -> soon (judged only because they said so)", r.verdict === "soon"); }
  check("E9e STANDBYIDLE=0 and VIDEOIDLE=0 -> never-sleeps", summarizeSleepTimers({ standbyIdleAc: 0, videoIdleAc: 0, registryOk: true }).verdict === "never-sleeps");
  check("E9f registry unreadable -> not_checked", summarizeSleepTimers({ registryOk: false }).verdict === "not_checked");
}

// -- power.restartWaiting (engineChecks fixtures a-d) --
{
  check("E10a RebootRequired present -> restart-waiting", summarizeRestartWaiting({ rebootRequired: true }).verdict === "restart-waiting");
  check("E10b only PendingFileRename -> possibly, never restart-waiting", summarizeRestartWaiting({ pendingFileRename: true }).verdict === "possibly");
  check("E10c none -> none", summarizeRestartWaiting({}).verdict === "none");
  check("E10d UX key unreadable -> not_checked", summarizeRestartWaiting({ uxKeyReadable: false }).verdict === "not_checked");
}

// -- power.startupHealth --
{
  const tasks = [{ lastTaskResult: 0 }, { lastTaskResult: 267009 }, { lastTaskResult: 267011 }, { lastTaskResult: 0x800710e0 }, { lastTaskResult: 0xc000013a }, { lastTaskResult: 999 }];
  { const r = summarizeStartupHealth({ tasks, microsoftTaskSeen: true, vbsLogReadable: true, vbsDeprecationCount: 400, vbsStartupEntries: ["Photo Sync"] }); check("E11a each LastTaskResult code lands in the right count (never-fair-chance=2, failed=1)", r.neverFairChance === 2 && r.failed === 1 && r.vbsCount === 400 && r.vbsStartupCount === 1); }
  check("E11b no Microsoft task in the list -> not_checked", summarizeStartupHealth({ tasks, microsoftTaskSeen: false }).verdict === "not_checked");
  check("E11c the VBScript sub-reading is not_checked when its OWN control query fails, even if the Id query returned a count", summarizeStartupHealth({ tasks: [], microsoftTaskSeen: true, vbsLogReadable: false, vbsDeprecationCount: 0 }).vbsCount === null);
}

// -- power.diskSpace (engineChecks fixtures a-e) --
{
  // NOTE: the spec's own worked example ("118 GB with 14 GB free -> soon") does not survive
  // its own stated rule (14/118 = 11.86%, which is already under BOTH the 12-percent and the
  // 15GB fix-now gates) - recomputed here rather than shipped as a silent typo. 20GB/118GB
  // (16.9%) demonstrates "soon" cleanly instead, and 9GB/118GB still demonstrates "fix-now"
  // exactly as the spec's own second number states.
  check("E12a C: 118GB with 20GB free (16.9%, under 20% but not under 12%) -> soon", summarizeDiskSpace([{ drive: "C:", sizeBytes: 118 * 1024 ** 3, freeBytes: 20 * 1024 ** 3 }])[0].verdict === "soon");
  check("E12b 9GB free on the same drive -> fix-now", summarizeDiskSpace([{ drive: "C:", sizeBytes: 118 * 1024 ** 3, freeBytes: 9 * 1024 ** 3 }])[0].verdict === "fix-now");
  check("E12c a 2TB drive at 10 percent (200GB free) -> fine, never a red headline on percent alone", summarizeDiskSpace([{ drive: "D:", sizeBytes: 2000 * 1024 ** 3, freeBytes: 200 * 1024 ** 3 }])[0].verdict === "fine");
  check("E12d system drive missing -> not_checked", summarizeDiskSpaceGroup([], { systemDrivePresent: false }).verdict === "not_checked");
}

// -- power.speedCap (engineChecks fixtures a-d) --
{
  check("E13a perf [0,34,33,35] util [0,85,90,88] -> capped", summarizeSpeedCap({ perf: [34, 33, 35], util: [85, 90, 88] }).verdict === "capped");
  check("E13b perf [0,98,99,97] with high utility -> full-speed", summarizeSpeedCap({ perf: [98, 99, 97], util: [85, 90, 88] }).verdict === "full-speed");
  check("E13c utility never reaches 60 -> unclear (an idle CPU is never judged)", summarizeSpeedCap({ perf: [95, 96, 94], util: [10, 15, 12] }).verdict === "unclear");
  check("E13d Get-Counter error -> not_checked, never a fallback to clock speed", summarizeSpeedCap({ counterOk: false }).verdict === "not_checked");
  check("E13e no implied clock-speed fallback anywhere in decode/summarize", !/CurrentClockSpeed/.test(fs.readFileSync(path.join(APP, "src/doors/summarize.mjs"), "utf8")) && !/CurrentClockSpeed/.test(fs.readFileSync(path.join(APP, "src/doors/decode.mjs"), "utf8")));
}

console.log(`\nhideout doors selftest: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
