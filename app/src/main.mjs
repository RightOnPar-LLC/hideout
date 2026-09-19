// main.mjs — Hideout app entry (dev: `node app/src/main.mjs`; packaged: the .exe).
//   --no-open     start the server without opening the window
//   --print-url   print the one-time launch URL (dev only; it carries the session key)
import fs from "node:fs";
import net from "node:net";
import crypto from "node:crypto";
import path from "node:path";
import { startServer, openWindow } from "./server.mjs";
import { ensureEngine, brainExe, dataDir, readStaticText, isPackaged } from "./engine.mjs";
import { Worker } from "./worker.mjs";
import { Guide, directTransport, gatewayTransport, lockedFetch } from "./guide.mjs";
import { Brain } from "./brain.mjs";
import { Money } from "./money/money.mjs";
import { listInstalled } from "./money/pc.mjs";
import { makeRedactor, collectIdentity } from "./redact.mjs";

const dir = dataDir();
const logFile = path.join(dir, "hideout.log");
const log = (m) => { try { fs.appendFileSync(logFile, `${new Date().toISOString()} ${m}\n`); } catch {} };
process.on("uncaughtException", (e) => log(`uncaught: ${e && e.stack || e}`));
process.on("unhandledRejection", (e) => log(`unhandled: ${e && e.stack || e}`));

const appDir = isPackaged ? path.dirname(process.execPath) : path.resolve(path.dirname(process.argv[1]), "..");
const repoRoot = path.resolve(appDir, "..");
const version = isPackaged ? readStaticText("version.txt") : "dev";

// ---- how the guide reaches Claude --------------------------------------------------
// Gateway (the normal way): a cloud gateway (gateway/) holds the Claude key; this PC holds
// only a per-install pass. The gateway URL is set at build time (never a key). Direct (a
// developer's own machine): ANTHROPIC_API_KEY from the environment, held in memory only -
// never logged, written, or sent to the page.
function gatewayUrl() {
  if (process.env.HIDEOUT_GATEWAY_URL) return process.env.HIDEOUT_GATEWAY_URL;
  if (isPackaged) { try { return JSON.parse(readStaticText("gateway.json")).url || null; } catch {} }
  return null;
}
function makeTransport() {
  const gw = gatewayUrl();
  if (gw) {
    const installFile = path.join(dir, "install.json");
    const fetchGw = lockedFetch([new URL(gw).host]);
    let token = null;
    const getToken = async () => {
      if (token) return token;
      try { const saved = JSON.parse(fs.readFileSync(installFile, "utf8")); if (saved.gateway === gw && saved.token) return (token = saved.token); } catch {}
      const res = await fetchGw(new URL("/v1/install", gw).href, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      if (!res.ok) throw Object.assign(new Error(`install ${res.status}`), { status: res.status });
      token = (await res.json()).token;
      fs.writeFileSync(installFile, JSON.stringify({ gateway: gw, token }));
      return token;
    };
    return gatewayTransport(gw, getToken, { fetchImpl: fetchGw });
  }
  const key = process.env.ANTHROPIC_API_KEY || null;
  return key ? directTransport(key) : null;
}

const engine = ensureEngine({ repoRoot });
const brain = new Brain({ exe: brainExe({ repoRoot }), dir: path.join(dir, "brain"), log });
const worker = new Worker({ engine, dir, brain });
const money = new Money({ brain, log });
const guide = new Guide({
  transport: makeTransport(),
  worker, brain, money,
  redactor: makeRedactor(collectIdentity()),
  onUsage: (u) => log(`guide usage model=${u.model} stop=${u.stop} in=${u.input_tokens} cache_read=${u.cache_read_input_tokens || 0} cache_write=${u.cache_creation_input_tokens || 0} out=${u.output_tokens}`),
});
// Packaged: read once from the exe. Dev: re-read on every page load, so design edits show on refresh.
const uiHtml = isPackaged ? readStaticText("ui/index.html") : () => fs.readFileSync(path.join(appDir, "ui", "index.html"), "utf8");

const args = new Set(process.argv.slice(2));

// One Hideout per data folder: a second double-click brings the open window forward instead
// of starting a second copy on the same memory. (The pipe only ever carries "show".)
const PIPE = "\\\\.\\pipe\\hideout-" + crypto.createHash("sha256").update(dir.toLowerCase()).digest("hex").slice(0, 16);
const alreadyRunning = () => new Promise((resolve) => {
  const c = net.connect(PIPE, () => { c.end("show\n"); resolve(true); });
  c.on("error", () => resolve(false));
});
function listenForShow(launchUrl) {
  const srv = net.createServer((sock) => { sock.once("data", () => { if (!args.has("--no-open")) openWindow(launchUrl, path.join(dir, "window")); }); sock.on("error", () => {}); });
  srv.on("error", (e) => log(`single-instance pipe: ${e.message}`));
  srv.listen(PIPE);
  srv.unref();
}
// Not top-level await: the .exe build bundles this to CommonJS, which has none.
alreadyRunning().then((running) => {
  if (running) { log("second launch - showed the open window"); console.log("Hideout is already open - bringing its window forward."); process.exit(0); }
}).then(() => brain.start()).then((ok) => log(`brain ${ok ? "ready (tpm, private to this PC)" : "unavailable: " + brain.why}`)).then(() => startServer({
  worker, guide, brain, money, uiHtml, version, log,
  open: args.has("--no-open") ? null : (url) => openWindow(url, path.join(dir, "window")),
  onIdleExit: () => { log("window closed - exiting"); brain.stop(); process.exit(0); },
})).then((srv) => {
  listenForShow(srv.launchUrl);
  log(`started v${version} on 127.0.0.1:${srv.port} (ai=${guide.transport ? guide.transport.kind : "off"}, memory=${brain.available})`);
  if (args.has("--print-url")) console.log(srv.launchUrl);
  else console.log(`Hideout is running (window opened). Close the window to quit.`);
  worker.enqueue("scan"); // first look happens on its own
  // Installed programs (read-only), for "on your PC and on your bill" and remote-access tools.
  listInstalled().then((list) => { money.installed = list || []; money.onChange?.(); log(`installed programs: ${list ? list.length : "unreadable"}`); });
}).catch((e) => { log(`could not start: ${e && e.message}`); console.error("Hideout could not start."); process.exit(1); });
