// brain.mjs — Hideout's private brain: a cognitive-mcp store that belongs to THIS PC only.
//
// Why private (not a shared, synced brain): Hideout runs on PCs that may already be
// infected. A key to a shared brain on such a PC can be stolen, and a victim's case file
// has no business leaving their machine. So each PC gets its own store:
//   - the cognitive-mcp engine, run as a child process over stdio (no network, no port)
//   - its own file: %LOCALAPPDATA%\Hideout\brain\memory.db
//   - COGNITIVE_MCP_KEY_MODE=tpm: the key is sealed by THIS machine's TPM into sidecar files
//     next to that db. NOT the default "keystore" mode - that one uses a single, fixed
//     Credential Manager slot for every cognitive-mcp store on the PC, so a second store
//     would silently share the main brain's master key.
//   - embeddings pointed at a dead port, so nothing is ever sent anywhere.
//
// What goes in: only facts Hideout's own code writes (scan results, case-step statuses from
// a closed list, and the Money section's statements, cancel dates and incident date). Each memory is base64url(JSON) behind a fixed prefix, so the store never
// holds readable attacker-chosen text that could later read like an instruction.
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { CASE_STEPS, STEP_STATUS } from "./guide-spec.mjs";

export const SCOPE = "app:hideout";
const PREFIX = "hideout1 ";
export { CASE_STEPS, STEP_STATUS };

const enc = (o) => PREFIX + Buffer.from(JSON.stringify(o), "utf8").toString("base64url");
export function parseList(text) {
  const out = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const m = /^#(\d+)\b.*?hideout1 ([A-Za-z0-9_-]+)/.exec(line);
    if (!m) continue;
    try { out.push({ id: Number(m[1]), ...JSON.parse(Buffer.from(m[2], "base64url").toString("utf8")) }); } catch {}
  }
  return out;
}

// Child env: only what the engine needs. Nothing secret-shaped from Hideout's own env.
function childEnv(dbPath) {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (!/KEY|TOKEN|SECRET|PASS|PEPPER|COGNITIVE_MCP/i.test(k)) env[k] = v;
  return { ...env, COGNITIVE_MCP_TRANSPORT: "stdio", COGNITIVE_MCP_DB_PATH: dbPath, COGNITIVE_MCP_KEY_MODE: "tpm", COGNITIVE_MCP_EMBED_URL: "http://127.0.0.1:1", RUST_LOG: "warn" };
}

export class Brain {
  constructor({ exe, dir, log = () => {}, spawnImpl = spawn }) {
    this.exe = exe; this.dir = dir; this.log = log; this.spawnImpl = spawnImpl;
    this.dbPath = path.join(dir, "memory.db");
    this.available = false; this.why = "not started"; this.child = null;
    this.seq = 0; this.pending = new Map(); this.buf = "";
    this.cache = null; this.entries = [];
    this.onChange = null; // set by the server: push the new case file to the window
  }

  async start() {
    try {
      if (!this.exe || !fs.existsSync(this.exe)) throw new Error("memory engine not found");
      fs.mkdirSync(this.dir, { recursive: true });
      const child = this.child = this.spawnImpl(this.exe, [], { env: childEnv(this.dbPath), stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
      child.stdout.on("data", (b) => this.#onData(b));
      child.stderr.on("data", (b) => { const t = b.toString("utf8").trim(); if (t) this.log(`brain: ${t.slice(0, 300)}`); });
      child.on("exit", (code) => { this.available = false; this.why = `memory engine stopped (${code})`; for (const p of this.pending.values()) p.reject(new Error(this.why)); this.pending.clear(); });
      child.on("error", (e) => { this.available = false; this.why = e.message; });
      await this.#request("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "hideout", version: "1" } }, 20_000);
      this.#send({ jsonrpc: "2.0", method: "notifications/initialized" });
      this.available = true; this.why = "";
      await this.refresh();
    } catch (e) {
      this.available = false; this.why = String(e && e.message || e);
      this.log(`brain unavailable: ${this.why}`);
      this.stop();
    }
    return this.available;
  }

  stop() { try { this.child?.kill(); } catch {} this.child = null; }

  #send(msg) { this.child.stdin.write(JSON.stringify(msg) + "\n"); }
  #request(method, params, timeoutMs = 10_000) {
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.pending.delete(id); reject(new Error(`memory engine timed out (${method})`)); }, timeoutMs);
      this.pending.set(id, { resolve: (v) => { clearTimeout(t); resolve(v); }, reject: (e) => { clearTimeout(t); reject(e); } });
      this.#send({ jsonrpc: "2.0", id, method, params });
    });
  }
  #onData(b) {
    this.buf += b.toString("utf8");
    let i;
    while ((i = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, i).trim(); this.buf = this.buf.slice(i + 1);
      if (!line) continue;
      let msg; try { msg = JSON.parse(line); } catch { continue; }
      const p = msg.id != null && this.pending.get(msg.id);
      if (!p) continue;
      this.pending.delete(msg.id);
      if (msg.error) p.reject(new Error(msg.error.message || "memory engine error"));
      else p.resolve(msg.result);
    }
  }
  async #tool(name, args) {
    if (!this.available) throw new Error(this.why || "memory unavailable");
    const r = await this.#request("tools/call", { name, arguments: args });
    const text = (r?.content || []).filter((c) => c.type === "text").map((c) => c.text).join("\n");
    if (r?.isError) throw new Error(text || "memory tool failed");
    return text;
  }

  async remember(kind, data) {
    if (!this.available) return false;
    try {
      await this.#tool("memory_store", { content: enc({ kind, at: new Date().toISOString(), ...data }), scope: SCOPE, tags: [kind] });
      await this.refresh();
      try { this.onChange?.(); } catch {}
      return true;
    } catch (e) { this.log(`brain store failed: ${e.message}`); return false; }
  }

  async refresh() {
    if (!this.available) return this.cache = null;
    try { this.entries = parseList(await this.#tool("memory_list", { scopes: [SCOPE], limit: 500 })); this.cache = buildCaseFile(this.entries); }
    catch (e) { this.log(`brain list failed: ${e.message}`); }
    return this.cache;
  }

  caseFile() { return this.available ? this.cache : null; }

  // Raw entries of one kind (Money keeps its statements, cancels and incident date here).
  records(kind) { return this.available ? this.entries.filter((e) => e.kind === kind) : []; }

  // Permanently delete Hideout's own entries - only when the person asks (Money: "forget").
  async forget(ids) {
    if (!this.available) return false;
    try {
      for (const id of ids) if (Number.isInteger(id) && this.entries.some((e) => e.id === id)) await this.#tool("memory_forget", { id });
      await this.refresh();
      try { this.onChange?.(); } catch {}
      return true;
    } catch (e) { this.log(`brain forget failed: ${e.message}`); return false; }
  }
}

// Newest-first entries -> the case file the guide and the window see.
export function buildCaseFile(entries) {
  const byTime = [...entries].sort((a, b) => String(a.at).localeCompare(String(b.at)));
  const steps = {};
  // Object.hasOwn, not CASE_STEPS[e.step]: "constructor" would pass a plain lookup.
  for (const e of byTime) if (e.kind === "step" && Object.hasOwn(CASE_STEPS, e.step) && STEP_STATUS.includes(e.status)) steps[e.step] = { status: e.status, at: e.at };
  const scans = byTime.filter((e) => e.kind === "scan").slice(-10).reverse();
  const deep = byTime.filter((e) => e.kind === "deep").slice(-5).reverse();
  return {
    opened: byTime[0]?.at || null,
    memories: entries.length,
    scans: scans.map(({ at, counts, threats }) => ({ at, counts, threats })),
    deepChecks: deep.map(({ at, admin, notable }) => ({ at, admin, notable })),
    steps: Object.entries(CASE_STEPS).map(([id, label]) => ({ id, label, status: steps[id]?.status || "not_yet", at: steps[id]?.at || null })),
  };
}
