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

console.log(`\nhideout doors selftest: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
