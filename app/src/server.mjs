// server.mjs — Hideout's local app server. It is only ever reachable from THIS PC and
// only by the window Hideout itself opened:
//   - binds 127.0.0.1 on a random free port (never 0.0.0.0, never a fixed port)
//   - a fresh 256-bit session key per launch; the window gets it once via /launch and
//     holds it as an HttpOnly SameSite=Strict cookie; every other request needs it
//   - Host header must be exactly 127.0.0.1:<port> (blocks DNS-rebinding pages)
//   - every POST must carry Origin = this server (blocks other sites / tabs)
//   - request bodies capped at 64 KB (a statement import: 3 MB); strict CSP on the page
//   - the only thing it ever opens outside itself is a vendor's cancel page from Hideout's
//     own directory, in the person's normal browser, when they click the button
//   - shuts itself down when the window has been closed for a while
import http from "node:http";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const MAX_BODY = 64 * 1024;
const MAX_IMPORT = 3 * 1024 * 1024;
const CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const SEC = { "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "cache-control": "no-store" };

const same = (a, b) => {
  const x = Buffer.from(String(a || "")), y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const cookieOf = (req, name) => {
  for (const part of String(req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return "";
};

// Over the cap: stop keeping bytes but let the upload finish, so the client gets a real
// 413 instead of a torn connection (destroying the socket kills the reply with it).
function readBody(req, limit = MAX_BODY) {
  const tooLarge = () => Object.assign(new Error("too large"), { status: 413 });
  if (Number(req.headers["content-length"]) > limit) { req.resume(); return Promise.reject(tooLarge()); }
  return new Promise((resolve, reject) => {
    let size = 0, over = false; const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) { over = true; chunks.length = 0; return; }
      chunks.push(c);
    });
    req.on("end", () => (over ? reject(tooLarge()) : resolve(Buffer.concat(chunks).toString("utf8"))));
    req.on("error", reject);
  });
}

// A vendor's cancel page, in the person's own browser (where they are signed in). Callers
// pass only URLs that came from Hideout's directory; this re-checks it is plain https.
export function openExternal(url) {
  const u = new URL(url);
  if (u.protocol !== "https:" || u.username || u.password) throw new Error("refused");
  spawn("explorer.exe", [u.href], { detached: true, stdio: "ignore" }).unref();
}

export function openWindow(url, profileDir) {
  const candidates = [
    path.join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Microsoft", "Edge", "Application", "msedge.exe"),
    path.join(process.env.ProgramFiles || "C:\\Program Files", "Microsoft", "Edge", "Application", "msedge.exe"),
  ];
  const edge = candidates.find((p) => fs.existsSync(p));
  // A dedicated Edge profile: an app window with no extensions and no shared cookies.
  if (edge) spawn(edge, [`--app=${url}`, `--user-data-dir=${profileDir}`, "--no-first-run", "--no-default-browser-check", "--window-size=1240,840"], { detached: true, stdio: "ignore" }).unref();
  else spawn("explorer.exe", [url], { detached: true, stdio: "ignore" }).unref();
}

export async function startServer({ worker, guide, brain = null, money = null, openUrl = openExternal, uiHtml, version = "dev", open = null, idleExitMs = 90_000, onIdleExit = null, log = () => {} }) {
  const token = crypto.randomBytes(32).toString("hex");
  const clients = new Set();
  let port = 0, everConnected = false, lastClient = Date.now();

  const send = (res, status, body, headers = {}) => {
    res.writeHead(status, { ...SEC, ...headers });
    res.end(body);
  };
  const json = (res, status, obj) => send(res, status, JSON.stringify(obj), { "content-type": "application/json; charset=utf-8" });
  const broadcast = (event, data) => {
    const line = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const c of clients) c.write(line);
  };
  const memoryState = () => ({ available: !!brain?.available, why: brain?.why || "", caseFile: brain?.caseFile() || null });
  const moneyState = () => { try { return money ? money.view() : null; } catch (e) { log(`money view failed: ${e.message}`); return null; } };
  const fullState = () => ({ worker: worker.state(), memory: memoryState(), money: moneyState() });
  worker.on("job", (j) => broadcast("job", j));
  worker.on("state", () => broadcast("state", fullState()));
  if (brain) brain.onChange = () => broadcast("state", fullState());
  if (money) money.onChange = () => broadcast("state", fullState());

  async function handle(req, res) {
    const origin = `http://127.0.0.1:${port}`;
    if (req.headers.host !== `127.0.0.1:${port}`) return send(res, 421, "wrong host");
    const url = new URL(req.url, origin);
    const p = url.pathname;

    if (p === "/launch" && req.method === "GET") {
      if (!same(url.searchParams.get("k"), token)) return send(res, 403, "This link has expired - open Hideout again.");
      return send(res, 302, "", { location: "/", "set-cookie": `hideout=${token}; HttpOnly; SameSite=Strict; Path=/` });
    }
    if (!same(cookieOf(req, "hideout"), token)) return send(res, 403, "Open Hideout from its shortcut.", { "content-type": "text/plain; charset=utf-8" });

    if (req.method === "POST") {
      if (req.headers.origin !== origin) return send(res, 403, "cross-site request refused");
      if (!/^application\/json\b/.test(String(req.headers["content-type"] || ""))) return send(res, 415, "json only");
    }

    if (p === "/" && req.method === "GET") return send(res, 200, typeof uiHtml === "function" ? uiHtml() : uiHtml, { "content-type": "text/html; charset=utf-8", "content-security-policy": CSP, "x-frame-options": "DENY" });
    if (p === "/api/state" && req.method === "GET") return json(res, 200, { version, ai: guide.available, aiMode: guide.transport ? guide.transport.kind : "off", model: guide.model, ...fullState() });

    if (p === "/api/events" && req.method === "GET") {
      res.writeHead(200, { ...SEC, "content-type": "text/event-stream", connection: "keep-alive" });
      res.write(`event: state\ndata: ${JSON.stringify(fullState())}\n\n`);
      clients.add(res); everConnected = true;
      const ping = setInterval(() => res.write(": ping\n\n"), 15_000);
      req.on("close", () => { clearInterval(ping); clients.delete(res); lastClient = Date.now(); });
      return;
    }

    if (req.method === "POST" && p.startsWith("/api/money/")) {
      if (!money) return json(res, 404, { error: "money section unavailable" });
      let body;
      try { body = JSON.parse((await readBody(req, p === "/api/money/import" ? MAX_IMPORT : MAX_BODY)) || "{}"); } catch (e) { return send(res, e.status || 400, e.status ? "too large" : "bad json"); }
      const str = (v) => (typeof v === "string" ? v : "");
      if (p === "/api/money/import") {
        if (!str(body.text).trim()) return json(res, 400, { ok: false, warnings: ["That file is empty."] });
        return json(res, 200, await money.importStatement(str(body.name), str(body.text)));
      }
      if (p === "/api/money/incident") return json(res, 200, await money.setIncident(str(body.date)));
      if (p === "/api/money/cancel") return json(res, 200, await money.markCanceled(str(body.merchant), str(body.on)));
      if (p === "/api/money/steps") {
        const info = money.cancelInfo(str(body.merchant));
        return info ? json(res, 200, info) : json(res, 404, { error: "unknown company" });
      }
      if (p === "/api/money/open") {
        // The URL comes from Hideout's directory by merchant id - never from the request.
        const url = money.cancelUrl(str(body.merchant));
        if (!url) return json(res, 404, { error: "no cancel page on file for that company" });
        try { openUrl(url); } catch { return json(res, 400, { error: "refused" }); }
        return json(res, 200, { ok: true });
      }
      if (p === "/api/money/forget") {
        if (body.confirm !== true) return json(res, 400, { error: "confirm required" });
        return json(res, 200, await money.forgetAll());
      }
      return send(res, 404, "not found");
    }

    if (req.method === "POST" && (p === "/api/scan" || p === "/api/chat" || p === "/api/chat/reset")) {
      let body;
      try { body = JSON.parse((await readBody(req)) || "{}"); } catch (e) { return send(res, e.status || 400, e.status ? "too large" : "bad json"); }
      if (p === "/api/scan") {
        const kind = body.kind;
        if (!["scan", "hunt", "hunt-admin"].includes(kind)) return json(res, 400, { error: "unknown kind" });
        const job = worker.enqueue(kind);
        return json(res, 202, { id: job.id, state: job.state });
      }
      if (p === "/api/chat/reset") { guide.reset(); return json(res, 200, { ok: true }); }
      const message = typeof body.message === "string" ? body.message.trim() : "";
      if (!message) return json(res, 400, { error: "empty message" });
      res.writeHead(200, { ...SEC, "content-type": "application/x-ndjson; charset=utf-8" });
      await guide.chat(message, (ev) => res.write(JSON.stringify(ev) + "\n"));
      return res.end();
    }
    return send(res, 404, "not found");
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      log(`request error: ${e && e.message}`);
      if (!res.headersSent) send(res, 500, "error"); else res.end();
    });
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  port = server.address().port;
  const launchUrl = `http://127.0.0.1:${port}/launch?k=${token}`;

  const idle = setInterval(() => {
    if (!onIdleExit || !everConnected || clients.size || worker.active || guide.busy) return;
    if (Date.now() - lastClient > idleExitMs) { clearInterval(idle); server.close(); onIdleExit(); }
  }, 5_000);
  idle.unref();

  if (open) open(launchUrl);
  return { port, token, launchUrl, close: () => { clearInterval(idle); for (const c of clients) c.end(); return new Promise((r) => server.close(r)); } };
}
