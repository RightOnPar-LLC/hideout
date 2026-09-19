// engine.mjs — where the PowerShell engine lives, and how it is run.
//
// Dev: the repo's own hideout.ps1 / hunt.ps1 (two folders up from app/src).
// Packaged .exe: the scripts ship INSIDE the exe as SEA assets and are written to
// %LOCALAPPDATA%\Hideout\engine on start (rewritten only when their content differs).
// Before anything runs ELEVATED, the on-disk copy is re-hashed against the shipped one,
// so a swapped script is refused instead of being handed admin rights.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import * as sea from "node:sea";

export const isPackaged = sea.isSea();
export const POWERSHELL = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

export function readStaticText(assetName, devPath) {
  if (isPackaged) return sea.getAsset(assetName, "utf8");
  return fs.readFileSync(devPath, "utf8");
}

export function dataDir() {
  const base = process.env.LOCALAPPDATA || path.join(process.env.USERPROFILE || ".", "AppData", "Local");
  const d = path.join(base, "Hideout");
  fs.mkdirSync(d, { recursive: true });
  return d;
}

export function ensureEngine({ repoRoot } = {}) {
  const files = ["hideout.ps1", "hunt.ps1", "report.html"];
  let dir, shipped = {};
  if (isPackaged) {
    dir = path.join(dataDir(), "engine");
    fs.mkdirSync(dir, { recursive: true });
    for (const f of files) {
      const body = sea.getAsset(`engine/${f}`, "utf8");
      shipped[f] = sha(body);
      const p = path.join(dir, f);
      let cur = null; try { cur = fs.readFileSync(p, "utf8"); } catch {}
      if (cur === null || sha(cur) !== shipped[f]) fs.writeFileSync(p, body);
    }
  } else {
    dir = repoRoot;
    for (const f of files) shipped[f] = sha(fs.readFileSync(path.join(dir, f), "utf8"));
  }
  return {
    dir,
    hideout: path.join(dir, "hideout.ps1"),
    hunt: path.join(dir, "hunt.ps1"),
    // True only if the file on disk is byte-identical to what shipped.
    verify(name) {
      try { return sha(fs.readFileSync(path.join(dir, name), "utf8")) === shipped[name]; } catch { return false; }
    },
  };
}

// The memory engine (cognitive-mcp). Packaged: shipped inside the exe, written out to
// %LOCALAPPDATA%\Hideout\brain-engine only when missing or different (byte-compared by
// hash each start, so a swapped binary is replaced before it ever runs). A build without the
// engine runs with memory off. Dev: HIDEOUT_BRAIN_EXE, or a cognitive-mcp checkout beside
// this repo's parent folder.
export function brainExe({ repoRoot }) {
  if (isPackaged) {
    let body;
    try { body = Buffer.from(sea.getAsset("brain/cognitive-mcp.exe")); } catch { return null; }
    const dir = path.join(dataDir(), "brain-engine");
    fs.mkdirSync(dir, { recursive: true });
    const p = path.join(dir, "cognitive-mcp.exe");
    let same = false;
    try { same = crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex") === crypto.createHash("sha256").update(body).digest("hex"); } catch {}
    if (!same) fs.writeFileSync(p, body);
    return p;
  }
  return process.env.HIDEOUT_BRAIN_EXE || path.resolve(repoRoot, "..", "..", "cognitive-mcp", "rust", "target", "release", "cognitive-mcp.exe");
}

// Run a program, collecting stdout (capped) and handing each output line to onLine.
export function runProcess(exe, args, { timeoutMs = 300_000, onLine, maxBytes = 25 * 1024 * 1024 } = {}) {
  return new Promise((resolve) => {
    let out = "", err = "", size = 0, partial = "", done = false;
    const child = spawn(exe, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    const timer = setTimeout(() => { if (!done) { child.kill(); finish(-1, "timed out"); } }, timeoutMs);
    function finish(code, why) {
      if (done) return; done = true; clearTimeout(timer);
      resolve({ code, stdout: out, stderr: err, why: why || "" });
    }
    child.stdout.on("data", (b) => {
      size += b.length;
      if (size <= maxBytes) out += b.toString("utf8");
      if (onLine) {
        partial += b.toString("utf8");
        const lines = partial.split(/\r?\n/); partial = lines.pop();
        for (const l of lines) if (l.trim()) onLine(l);
      }
    });
    child.stderr.on("data", (b) => { if (err.length < 64 * 1024) err += b.toString("utf8"); });
    child.on("error", (e) => finish(-1, e.message));
    child.on("close", (code) => finish(code ?? -1));
  });
}

// PowerShell single-quoted literal: the only escape is '' for '.
export const psq = (s) => `'${String(s).replace(/'/g, "''")}'`;
export const encodePs = (script) => Buffer.from(script, "utf16le").toString("base64");
