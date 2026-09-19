// Hideout guide gateway — holds the Claude key so no customer PC ever does.
//
//   POST /v1/install      -> { token }   one anonymous pass per install (rate-limited per IP)
//   POST /v1/guide/turn   -> NDJSON      one guide turn: {type:"text",delta}... {type:"final",message}
//   GET  /healthz         -> readiness, no secrets
//
// The gateway, not the client, decides the model, the instructions, the tools and the
// limits (guide-spec.mjs): a client sends ONLY the conversation. So the key can't be
// repurposed as a general-purpose Claude, and a stolen install token buys at most one
// install's daily allowance of Hideout Guide turns. Nothing is stored but counters:
// conversations pass through and are never logged.
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import Anthropic from "@anthropic-ai/sdk";
import { GUIDE_TOOLS, requestParams, MODEL } from "./spec.mjs";

const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : d);
// $ per million tokens (Claude Opus 5; the fallback model bills the same tier).
const PRICE = { input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25 };
const BLOCK_TYPES = new Set(["text", "tool_use", "tool_result", "thinking", "redacted_thinking", "fallback"]);
const MAX_BODY = 512 * 1024;

export function costUsd(u = {}) {
  return ((u.input_tokens || 0) * PRICE.input + (u.output_tokens || 0) * PRICE.output
    + (u.cache_read_input_tokens || 0) * PRICE.cacheRead + (u.cache_creation_input_tokens || 0) * PRICE.cacheWrite) / 1e6;
}

// The conversation is the only thing a client controls - check its shape hard.
export function validateMessages(messages) {
  if (!Array.isArray(messages) || !messages.length || messages.length > 80) return "messages must be a list of 1-80 turns";
  if (messages[0].role !== "user" || messages.at(-1).role !== "user") return "conversation must start and end with the person";
  for (const m of messages) {
    if (!m || (m.role !== "user" && m.role !== "assistant")) return "bad role";
    if (typeof m.content === "string") { if (m.content.length > 8000) return "turn too long"; continue; }
    if (!Array.isArray(m.content) || m.content.length > 40) return "bad content";
    for (const b of m.content) {
      if (!b || !BLOCK_TYPES.has(b.type)) return `content type not allowed: ${b && b.type}`;
      if (b.type === "tool_use" && !GUIDE_TOOLS.includes(b.name)) return "unknown tool in history";
    }
  }
  return null;
}

export function createGateway({ client, secret, dataDir = null, now = () => Date.now(), limits = {} }) {
  if (!secret || secret.length < 32) throw new Error("GATEWAY_SECRET must be at least 32 characters");
  const L = {
    dailyBudgetUsd: num(limits.dailyBudgetUsd, 5),
    turnsPerInstallPerDay: num(limits.turnsPerInstallPerDay, 60),
    installsPerIpPerDay: num(limits.installsPerIpPerDay, 5),
    requestsPerMinute: num(limits.requestsPerMinute, 120),
  };
  const day = () => new Date(now()).toISOString().slice(0, 10);
  const file = dataDir ? path.join(dataDir, "usage.json") : null;
  let usage = { day: day(), spentUsd: 0, turns: {}, installsByIp: {} };
  try { if (file) { const u = JSON.parse(fs.readFileSync(file, "utf8")); if (u.day === day()) usage = u; } } catch {}
  let saveTimer = null;
  const save = () => { if (!file || saveTimer) return; saveTimer = setTimeout(() => { saveTimer = null; try { fs.writeFileSync(file, JSON.stringify(usage)); } catch {} }, 1000); };
  const roll = () => { if (usage.day !== day()) usage = { day: day(), spentUsd: 0, turns: {}, installsByIp: {} }; };
  const inFlight = new Set();
  let minute = { at: 0, n: 0 };

  const sign = (id) => crypto.createHmac("sha256", secret).update(`install:${id}`).digest("base64url");
  const verify = (token) => {
    const [id, mac] = String(token || "").split(".");
    if (!/^[0-9a-f]{32}$/.test(id || "") || !mac) return null;
    const a = Buffer.from(mac), b = Buffer.from(sign(id));
    return a.length === b.length && crypto.timingSafeEqual(a, b) ? id : null;
  };
  // The LAST X-Forwarded-For hop is the one the platform's proxy appended; the first is
  // whatever the client chose to send, so keying on it would make the limit optional.
  const ipOf = (req) => String(req.headers["x-real-ip"] || String(req.headers["x-forwarded-for"] || "").split(",").pop() || req.socket.remoteAddress || "").trim();
  const json = (res, status, obj) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
  const readBody = (req) => new Promise((resolve, reject) => {
    if (Number(req.headers["content-length"]) > MAX_BODY) { req.resume(); return reject(Object.assign(new Error("too large"), { status: 413 })); }
    let size = 0, over = false; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > MAX_BODY) { over = true; chunks.length = 0; } else chunks.push(c); });
    req.on("end", () => (over ? reject(Object.assign(new Error("too large"), { status: 413 })) : resolve(Buffer.concat(chunks).toString("utf8"))));
    req.on("error", reject);
  });

  async function handle(req, res) {
    roll();
    const p = new URL(req.url, "http://x").pathname;
    if (req.method === "GET" && p === "/healthz") return json(res, 200, { ok: true, model: MODEL, budgetLeftUsd: Math.max(0, +(L.dailyBudgetUsd - usage.spentUsd).toFixed(4)) });
    if (req.method !== "POST") return json(res, 404, { error: "not found" });
    const t = now();
    if (t - minute.at > 60_000) minute = { at: t, n: 0 };
    if (++minute.n > L.requestsPerMinute) return json(res, 429, { error: "busy" });

    if (p === "/v1/install") {
      const ip = ipOf(req);
      const n = usage.installsByIp[ip] || 0;
      if (n >= L.installsPerIpPerDay) return json(res, 429, { error: "too many new installs from this address today" });
      usage.installsByIp[ip] = n + 1; save();
      const id = crypto.randomBytes(16).toString("hex");
      return json(res, 200, { token: `${id}.${sign(id)}` });
    }

    if (p === "/v1/guide/turn") {
      const id = verify(String(req.headers.authorization || "").replace(/^Bearer\s+/i, ""));
      if (!id) return json(res, 401, { error: "unknown install" });
      if (usage.spentUsd >= L.dailyBudgetUsd) return json(res, 429, { error: "the guide is resting for today" });
      if ((usage.turns[id] || 0) >= L.turnsPerInstallPerDay) return json(res, 429, { error: "daily limit reached for this PC" });
      if (inFlight.has(id)) return json(res, 409, { error: "one question at a time" });
      let body;
      try { body = JSON.parse(await readBody(req)); } catch (e) { return json(res, e.status || 400, { error: e.status ? "too large" : "bad json" }); }
      const bad = validateMessages(body && body.messages);
      if (bad) return json(res, 400, { error: bad });

      inFlight.add(id);
      usage.turns[id] = (usage.turns[id] || 0) + 1; save();
      res.writeHead(200, { "content-type": "application/x-ndjson" });
      const line = (o) => res.write(JSON.stringify(o) + "\n");
      try {
        const stream = client.beta.messages.stream(requestParams(body.messages));
        stream.on("text", (delta) => line({ type: "text", delta }));
        const m = await stream.finalMessage();
        usage.spentUsd += costUsd(m.usage); save();
        line({ type: "final", message: { stop_reason: m.stop_reason, content: m.content, model: m.model, usage: m.usage } });
      } catch (e) {
        line({ type: "error", status: e.status || 502, message: e.status === 429 ? "busy" : "the guide couldn't answer" });
      } finally {
        inFlight.delete(id);
        res.end();
      }
      return;
    }
    return json(res, 404, { error: "not found" });
  }

  const server = http.createServer((req, res) => handle(req, res).catch(() => { if (!res.headersSent) json(res, 500, { error: "error" }); else res.end(); }));
  return { server, usage: () => usage, limits: L };
}

// Entry point (Railway): everything from the environment; the key never leaves this process.
if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
  const key = process.env.ANTHROPIC_API_KEY, secret = process.env.GATEWAY_SECRET;
  if (!key || !secret) { console.error("ANTHROPIC_API_KEY and GATEWAY_SECRET are required"); process.exit(1); }
  const dataDir = process.env.DATA_DIR || null;
  if (dataDir) fs.mkdirSync(dataDir, { recursive: true });
  const gw = createGateway({
    client: new Anthropic({ apiKey: key, maxRetries: 2 }), secret, dataDir,
    limits: { dailyBudgetUsd: process.env.DAILY_BUDGET_USD, turnsPerInstallPerDay: process.env.TURNS_PER_INSTALL_PER_DAY, installsPerIpPerDay: process.env.INSTALLS_PER_IP_PER_DAY },
  });
  gw.server.listen(Number(process.env.PORT) || 8080, "0.0.0.0", () => console.log(`hideout guide gateway up (model ${MODEL}, budget $${gw.limits.dailyBudgetUsd}/day)`));
}
