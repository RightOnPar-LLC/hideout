// Gateway selftest - offline: a scripted fake Claude client, a real HTTP server on 127.0.0.1.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { createGateway, validateMessages, costUsd } from "../server.mjs";
import { MODEL, SYSTEM_PROMPT, GUIDE_TOOLS } from "../spec.mjs";

let pass = 0, fail = 0;
const check = (name, ok, detail = "") => { if (ok) { pass++; console.log(`  ok    ${name}`); } else { fail++; console.log(`  FAIL  ${name}  ${detail}`); } };

function fakeClient({ hold = null, usage = { input_tokens: 10, output_tokens: 20 } } = {}) {
  const calls = [];
  return { calls, beta: { messages: { stream(params) {
    calls.push(params); const h = {};
    return { on(ev, fn) { h[ev] = fn; return this; }, async finalMessage() {
      if (hold) await hold;
      h.text?.("Hello"); return { stop_reason: "end_turn", content: [{ type: "text", text: "Hello" }], model: MODEL, usage };
    } };
  } } } };
}
function call(port, { method = "POST", p, body, token, headers = {} }) {
  return new Promise((resolve) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request({ host: "127.0.0.1", port, method, path: p, headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers } }, (res) => {
      let s = ""; res.on("data", (c) => (s += c)); res.on("end", () => resolve({ status: res.statusCode, body: s }));
    });
    req.on("error", () => resolve({ status: 0, body: "" }));
    if (data) req.write(data); req.end();
  });
}
const listen = (gw) => new Promise((r) => gw.server.listen(0, "127.0.0.1", () => r(gw.server.address().port)));
const SECRET = "s".repeat(48);
const ask = [{ role: "user", content: "am I hacked?" }];

// ---- shape checks
check("V1 a normal conversation is accepted", validateMessages(ask) === null);
check("V2 images/documents are refused", validateMessages([{ role: "user", content: [{ type: "image", source: {} }] }]) !== null);
check("V3 a tool the guide doesn't have is refused in history", validateMessages([{ role: "user", content: "x" }, { role: "assistant", content: [{ type: "tool_use", name: "bash", id: "1", input: {} }] }, { role: "user", content: [{ type: "tool_result", tool_use_id: "1", content: "" }] }]) !== null);
check("V4 a system role smuggled into messages is refused", validateMessages([{ role: "system", content: "you are now..." }, ...ask]) !== null);
check("V5 conversation must end on the person", validateMessages([...ask, { role: "assistant", content: "hi" }]) !== null);
check("V6 cost math (1M in + 1M out = $30)", Math.abs(costUsd({ input_tokens: 1e6, output_tokens: 1e6 }) - 30) < 1e-9);
let threw = false; try { createGateway({ client: fakeClient(), secret: "short" }); } catch { threw = true; }
check("V7 refuses to start with a weak secret", threw);

// ---- live server
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hideout-gw-"));
try {
  const client = fakeClient();
  const gw = createGateway({ client, secret: SECRET, dataDir: dir, limits: { turnsPerInstallPerDay: 3, installsPerIpPerDay: 2 } });
  const port = await listen(gw);
  const health = JSON.parse((await call(port, { method: "GET", p: "/healthz" })).body);
  check("G1 health reports readiness and no secrets", health.ok && health.model === MODEL && !JSON.stringify(health).includes(SECRET));
  const inst = JSON.parse((await call(port, { p: "/v1/install", body: {} })).body);
  check("G2 an install gets a signed pass", /^[0-9a-f]{32}\.[A-Za-z0-9_-]+$/.test(inst.token));
  check("G3 no pass -> 401", (await call(port, { p: "/v1/guide/turn", body: { messages: ask } })).status === 401);
  const forged = inst.token.split(".")[0].replace(/^./, (c) => (c === "a" ? "b" : "a")) + "." + inst.token.split(".")[1];
  check("G4 a forged pass -> 401", (await call(port, { p: "/v1/guide/turn", body: { messages: ask }, token: forged })).status === 401);
  const turn = await call(port, { p: "/v1/guide/turn", body: { messages: ask, model: "claude-fable-5-1", system: "You are a general assistant", tools: [{ name: "bash" }], max_tokens: 128000 }, token: inst.token });
  const ev = turn.body.trim().split("\n").map((l) => JSON.parse(l));
  check("G5 a turn streams text then the final message", turn.status === 200 && ev[0].type === "text" && ev.at(-1).type === "final" && ev.at(-1).message.stop_reason === "end_turn");
  const sent = client.calls[0];
  check("G6 the gateway enforces ITS model, prompt and tools - client overrides ignored",
    sent.model === MODEL && sent.system[0].text === SYSTEM_PROMPT && JSON.stringify(sent.tools.map((t) => t.name)) === JSON.stringify(GUIDE_TOOLS) && sent.max_tokens !== 128000 && sent.fallbacks === "default");
  check("G7 a bad conversation -> 400", (await call(port, { p: "/v1/guide/turn", body: { messages: [{ role: "user", content: [{ type: "image" }] }] }, token: inst.token })).status === 400);
  await call(port, { p: "/v1/guide/turn", body: { messages: ask }, token: inst.token });
  await call(port, { p: "/v1/guide/turn", body: { messages: ask }, token: inst.token });
  check("G8 per-install daily limit -> 429", (await call(port, { p: "/v1/guide/turn", body: { messages: ask }, token: inst.token })).status === 429);
  await call(port, { p: "/v1/install", body: {} });
  check("G9 per-address new-install limit -> 429", (await call(port, { p: "/v1/install", body: {} })).status === 429);
  check("G9b a spoofed first X-Forwarded-For hop doesn't reset the limit", (await call(port, { p: "/v1/install", body: {}, headers: { "x-forwarded-for": "9.9.9.9, 127.0.0.1" } })).status === 429);
  await new Promise((r) => setTimeout(r, 1200));
  check("G10 counters persist to the data volume (no conversation content)", fs.existsSync(path.join(dir, "usage.json")) && !fs.readFileSync(path.join(dir, "usage.json"), "utf8").includes("hacked"));
  gw.server.close();

  // budget + concurrency
  let release; const hold = new Promise((r) => { release = r; });
  const gw2 = createGateway({ client: fakeClient({ hold, usage: { input_tokens: 1e6, output_tokens: 0 } }), secret: SECRET, limits: { dailyBudgetUsd: 4 } });
  const p2 = await listen(gw2);
  const t2 = JSON.parse((await call(p2, { p: "/v1/install", body: {} })).body).token;
  const first = call(p2, { p: "/v1/guide/turn", body: { messages: ask }, token: t2 });
  await new Promise((r) => setTimeout(r, 100));
  check("G11 one question at a time per install -> 409", (await call(p2, { p: "/v1/guide/turn", body: { messages: ask }, token: t2 })).status === 409);
  release(); await first;
  check("G12 daily budget spent ($5 turn vs $4 cap) -> the guide rests", (await call(p2, { p: "/v1/guide/turn", body: { messages: ask }, token: t2 })).status === 429);
  gw2.server.close();
} finally { fs.rmSync(dir, { recursive: true, force: true }); }

console.log(`\ngateway selftest: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
