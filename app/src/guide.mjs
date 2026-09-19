// guide.mjs — the Hideout Guide's conversation loop. The WHAT (model, instructions,
// tools) lives in guide-spec.mjs; this file runs turns and executes tool calls.
//
// Two ways to reach Claude (a "transport"):
//   direct   - the official SDK with a key held on this PC (the owner's own machines)
//   gateway  - Hideout's cloud gateway, which holds the key, enforces the spec and caps
//              usage; this PC holds only a per-install token (everyone else's machines)
// Both go through a fetch that may ONLY reach the one allowed host (network lock).
//
// Tools can read results, start read-only checks, keep the case file in Hideout's private
// brain, and put cancel steps and drafted letters in front of the person as cards. None can
// change the PC, log in anywhere, or send anything. Everything the model sees is redacted.
import Anthropic from "@anthropic-ai/sdk";
import { MODEL, GUIDE_TOOLS, CASE_STEPS, validateToolInput, requestParams } from "./guide-spec.mjs";

export { MODEL, GUIDE_TOOLS };
const MAX_TOOL_ROUNDS = 6;

// Network lock: a fetch that refuses every host but the allowed ones.
export function lockedFetch(allowedHosts, base = globalThis.fetch) {
  const allow = new Set(allowedHosts.map((h) => h.toLowerCase()));
  return (input, init) => {
    const u = new URL(typeof input === "string" ? input : input.url);
    if (u.protocol !== "https:" || !allow.has(u.host.toLowerCase())) {
      return Promise.reject(new Error(`network lock: ${u.protocol}//${u.host} is not allowed`));
    }
    return base(input, init);
  };
}

export function directTransport(apiKey, { fetchImpl } = {}) {
  const client = new Anthropic({ apiKey, fetch: fetchImpl || lockedFetch(["api.anthropic.com"]), maxRetries: 2 });
  return {
    kind: "direct",
    async turn(messages, onText) {
      const stream = client.beta.messages.stream(requestParams(messages));
      stream.on("text", onText);
      return stream.finalMessage();
    },
  };
}

// Gateway protocol: POST {messages} -> NDJSON lines {type:"text",delta} ... {type:"final",message}
// or {type:"error",status,message}. The gateway adds the prompt, tools and model itself.
export function gatewayTransport(baseUrl, getToken, { fetchImpl } = {}) {
  const url = new URL("/v1/guide/turn", baseUrl);
  const doFetch = fetchImpl || lockedFetch([url.host]);
  return {
    kind: "gateway",
    async turn(messages, onText) {
      const res = await doFetch(url.href, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${await getToken()}` },
        body: JSON.stringify({ messages }),
      });
      if (!res.ok || !res.body) throw Object.assign(new Error(`gateway ${res.status}`), { status: res.status });
      const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = "", final = null;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
          if (!line) continue;
          const ev = JSON.parse(line);
          if (ev.type === "text") onText(ev.delta);
          else if (ev.type === "final") final = ev.message;
          else if (ev.type === "error") throw Object.assign(new Error(ev.message || "gateway error"), { status: ev.status });
        }
      }
      if (!final) throw new Error("gateway ended without an answer");
      return final;
    },
  };
}

export class Guide {
  constructor({ transport, worker, brain = null, money = null, redactor, now = () => Date.now(), onUsage = null }) {
    this.transport = transport; this.worker = worker; this.brain = brain; this.money = money; this.redact = redactor; this.now = now; this.onUsage = onUsage;
    this.model = MODEL;
    this.messages = []; // append-only: assistant turns are stored exactly as returned
    this.busy = false;
  }
  get available() { return !!this.transport; }
  reset() { if (!this.busy) this.messages = []; }

  async #runTool(name, input, emit) {
    const w = this.worker;
    const scanView = () => {
      const s = w.latestScan;
      if (!s) return { scan: null };
      const ageMin = Math.round((this.now() - Date.parse(s.at)) / 60000);
      return { scan: { minutesAgo: ageMin, checked: s.checked, antivirus: s.defender, ranAsAdmin: s.admin, findings: s.findings || [] } };
    };
    if (name === "get_scan_results") {
      // A scan already under way (e.g. the automatic first look) is waited for, never
      // reported as "no scan yet" - that would be a false statement about the PC.
      const running = !w.latestScan && (w.jobs || []).find((j) => j.kind === "scan" && (j.state === "queued" || j.state === "running"));
      if (running) {
        emit({ type: "tool", name, status: "Waiting for the scan that's running..." });
        await Promise.race([running.done, new Promise((r) => setTimeout(r, 90_000))]);
      }
      return scanView();
    }
    if (name === "run_quick_scan") {
      emit({ type: "tool", name, status: "Running a quick scan..." });
      const job = await w.enqueue("scan").done;
      if (job.state !== "done") return { error: job.message || "the scan did not finish" };
      return scanView();
    }
    if (name === "start_deep_check") {
      emit({ type: "tool", name, status: input.with_admin ? "Deep check started - click Yes on the Windows prompt..." : "Deep check started (2-3 minutes)..." });
      const job = await w.enqueue(input.with_admin ? "hunt-admin" : "hunt").done;
      if (job.state !== "done") return { error: job.message || "the deep check did not finish" };
      return { deepCheck: w.latestHunt ? w.latestHunt.summary : null };
    }
    if (name === "get_deep_check_summary") {
      const h = w.latestHunt;
      return { deepCheck: h ? { minutesAgo: Math.round((this.now() - Date.parse(h.at)) / 60000), withAdmin: h.admin, ...h.summary } : null };
    }
    if (name === "get_case_file") {
      const cf = this.brain?.caseFile();
      return cf ? { caseFile: cf } : { caseFile: null, note: "Hideout's memory is unavailable on this PC right now." };
    }
    if (name === "update_case_step") {
      if (!this.brain?.available) return { error: "Hideout's memory is unavailable, so this wasn't saved." };
      emit({ type: "tool", name, status: `Case file: ${CASE_STEPS[input.step]} - ${input.status.replace("_", " ")}` });
      const ok = await this.brain.remember("step", { step: input.step, status: input.status });
      return ok ? { saved: true, caseFile: this.brain.caseFile() } : { error: "couldn't save to memory" };
    }
    const money = this.money;
    if (name === "get_money_summary") {
      if (!money) return { error: "The Money section isn't available." };
      return { money: money.guideView() };
    }
    if (name === "set_incident_date") {
      if (!money) return { error: "The Money section isn't available." };
      const r = await money.setIncident(input.date);
      if (!r.ok) return { error: r.error };
      emit({ type: "tool", name, status: `Money: things went wrong on ${input.date}` });
      return { saved: r.saved, sinceIncident: money.guideView().sinceIncident };
    }
    if (name === "mark_canceled") {
      if (!money) return { error: "The Money section isn't available." };
      const r = await money.markCanceled(input.merchant, input.canceled_on);
      if (!r.ok) return { error: r.error };
      emit({ type: "tool", name, status: `Money: cancelled on ${input.canceled_on} - Hideout will watch for any later charge` });
      return { saved: r.saved, company: money.guideView().repeating.find((x) => x.merchant === input.merchant) || null };
    }
    if (name === "show_cancel_steps") {
      const info = money?.cancelInfo(input.merchant);
      if (!info) return { error: "That company isn't in the repeating charges - read get_money_summary for the ids." };
      emit({ type: "card", card: { type: "cancel", ...info } });
      return { shown: true, ...info };
    }
    if (name === "offer_letter") {
      const info = input.merchant && money ? money.cancelInfo(input.merchant) : null;
      if (input.merchant && !info) return { error: "That company isn't in the repeating charges - read get_money_summary for the ids." };
      // Only the directory supplies an address, and only for a company that officially takes
      // cancellations by email. The model never picks where a letter goes.
      const to = input.kind === "cancel_by_email" && info?.cancelByEmail ? info.cancelByEmail : null;
      emit({ type: "card", card: { type: "letter", kind: input.kind, merchant: input.merchant || null, name: info?.name || null, to, subject: input.subject, body: input.body } });
      return { shown: true, to, note: "The person reviews and sends it themselves." };
    }
    return { error: "unknown tool" };
  }

  // One conversational turn. emit({type:'text'|'tool'|'pause'|'done'|'error', ...}) streams to the UI.
  async chat(userText, emit) {
    if (!this.transport) { emit({ type: "error", message: "The AI guide isn't connected on this PC." }); return; }
    if (this.busy) { emit({ type: "error", message: "The guide is still answering - one moment." }); return; }
    this.busy = true;
    const mark = this.messages.length;
    try {
      this.messages.push({ role: "user", content: this.redact.text(String(userText).slice(0, 4000)) });
      let jsonRetries = 0;
      for (let round = 0; round <= MAX_TOOL_ROUNDS; round++) {
        let msg;
        try {
          msg = await this.transport.turn(this.messages, (delta) => emit({ type: "text", delta }));
          jsonRetries = 0;
        } catch (err) {
          if (err instanceof Anthropic.APIError || err.status || jsonRetries++ >= 2) throw err;
          round--; continue; // a tool input that could not be parsed at all: re-issue the turn
        }
        // Token counts only (never content) - proves the prompt cache is actually hit.
        if (this.onUsage && msg.usage) this.onUsage({ model: msg.model, stop: msg.stop_reason, ...msg.usage });
        if (msg.stop_reason === "refusal") {
          this.messages.push({ role: "assistant", content: msg.content });
          emit({ type: "text", delta: "\n\nI can't help with that one. If you're dealing with an attack right now, disconnect from the internet and contact your bank or a trusted IT professional." });
          break;
        }
        const uses = msg.content.filter((b) => b.type === "tool_use");
        this.messages.push({ role: "assistant", content: msg.content });
        if (msg.stop_reason !== "tool_use" || !uses.length) break;
        if (round === MAX_TOOL_ROUNDS) { emit({ type: "text", delta: "\n\n(I've looked at a lot - let me stop here. Ask me to continue if you need more.)" }); break; }
        const results = [];
        for (const u of uses) {
          const bad = validateToolInput(u.name, u.input);
          if (bad) { results.push({ type: "tool_result", tool_use_id: u.id, is_error: true, content: bad }); continue; }
          let out;
          try { out = await this.#runTool(u.name, u.input, emit); } catch (e) { out = { error: String(e && e.message || e).slice(0, 200) }; }
          results.push({ type: "tool_result", tool_use_id: u.id, content: JSON.stringify(this.redact.deep(out)) });
        }
        this.messages.push({ role: "user", content: results });
        emit({ type: "pause" }); // text before and after a tool call are separate paragraphs
      }
      emit({ type: "done" });
    } catch (e) {
      // A failed turn is dropped whole (only the tail - earlier turns are never edited), so
      // the history never ends on an unanswered tool call or an unanswered question.
      this.messages.length = mark;
      const s = e.status;
      const msg = s === 429 ? "The guide is busy (or resting for today) - try again later."
        : s === 401 || s === 403 ? "The guide couldn't sign in."
        : e instanceof Anthropic.APIConnectionError || /network lock|fetch failed|ENOTFOUND|ECONN/.test(String(e.message)) ? "Couldn't reach the guide - check the internet connection."
        : s ? `The guide ran into a problem (${s}).`
        : "The guide ran into a problem.";
      emit({ type: "error", message: msg });
    } finally {
      this.busy = false;
    }
  }
}
