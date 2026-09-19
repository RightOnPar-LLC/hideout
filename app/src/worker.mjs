// worker.mjs — the background worker. Runs Hideout's engine as jobs, one at a time,
// while the person keeps talking to the guide. Every job is READ-ONLY: it only ever
// launches hideout.ps1 (scan) or hunt.ps1 (deep check); nothing here can delete, move,
// disable or quarantine.
//
// Jobs:  scan        quick check of everything set to start by itself (~20 s)
//        hunt        deep check, as the current user (~2-3 min)
//        hunt-admin  deep check with admin rights - Windows asks the person to click Yes
import fs from "node:fs";
import path from "node:path";
import { EventEmitter } from "node:events";
import { POWERSHELL, runProcess, psq, encodePs } from "./engine.mjs";

const KINDS = new Set(["scan", "hunt", "hunt-admin"]);
const now = () => new Date().toISOString();

export class Worker extends EventEmitter {
  constructor({ engine, dir, run = runProcess, powershell = POWERSHELL, brain = null }) {
    super();
    this.engine = engine; this.dir = dir; this.run = run; this.ps = powershell; this.brain = brain;
    this.jobs = []; this.queue = []; this.active = null; this.seq = 0;
    this.latestScan = null; this.latestHunt = null;
    fs.mkdirSync(path.join(dir, "hunts"), { recursive: true });
  }

  state() {
    return {
      busy: !!this.active,
      jobs: this.jobs.slice(-8).map(({ id, kind, state, started, finished, message, progress }) => ({ id, kind, state, started, finished, message, progress: progress.slice(-3) })),
      latestScan: this.latestScan,
      latestHunt: this.latestHunt ? { at: this.latestHunt.at, admin: this.latestHunt.admin, summary: this.latestHunt.summary } : null,
    };
  }

  // Same kind already waiting or running -> hand back that job instead of stacking a duplicate.
  enqueue(kind) {
    if (!KINDS.has(kind)) throw new Error(`unknown job kind: ${kind}`);
    const existing = this.jobs.find((j) => j.kind === kind && (j.state === "queued" || j.state === "running"));
    if (existing) return existing;
    const job = { id: ++this.seq, kind, state: "queued", started: null, finished: null, message: "", progress: [] };
    job.done = new Promise((res) => { job._resolve = res; });
    this.jobs.push(job); this.queue.push(job);
    this.emit("job", this.#public(job));
    this.#pump();
    return job;
  }

  #public(j) { return { id: j.id, kind: j.kind, state: j.state, message: j.message, progress: j.progress.slice(-1)[0] || "" }; }

  async #pump() {
    if (this.active || !this.queue.length) return;
    const job = this.active = this.queue.shift();
    job.state = "running"; job.started = now(); this.emit("job", this.#public(job));
    try {
      if (job.kind === "scan") await this.#scan(job);
      else await this.#hunt(job, job.kind === "hunt-admin");
      job.state = "done";
    } catch (e) {
      job.state = "failed"; job.message = String(e && e.message || e).slice(0, 300);
    }
    job.finished = now(); this.active = null;
    this.emit("job", this.#public(job)); this.emit("state");
    job._resolve(job);
    this.#pump();
  }

  async #scan(job) {
    job.progress.push("Checking everything set to start by itself...");
    this.emit("job", this.#public(job));
    const r = await this.run(this.ps, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", this.engine.hideout, "-Json"], { timeoutMs: 5 * 60_000 });
    if (r.code !== 0) throw new Error(`scan did not finish (${r.why || "exit " + r.code})`);
    let data;
    try { data = JSON.parse(r.stdout); } catch { throw new Error("scan output was not readable"); }
    this.latestScan = { at: now(), ...data };
    job.message = `${(data.findings || []).length} finding(s)`;
    // The case file remembers every scan (fail-soft: no brain, no memory, scan still counts).
    const f = data.findings || [];
    await this.brain?.remember("scan", {
      counts: { startItems: data.checked?.startItems || 0, threats: f.filter((x) => x.severity === "high").length, other: f.filter((x) => x.severity !== "high").length },
      threats: f.slice(0, 10).map((x) => ({ severity: x.severity, program: x.program, name: x.name, kind: x.kind, folder: x.folder, arrived: x.arrived, tags: (x.reasons || []).map((r) => r.tag) })),
    });
  }

  async #hunt(job, admin) {
    const out = path.join(this.dir, "hunts", `hunt-${now().replace(/[:.]/g, "-")}${admin ? "-admin" : ""}.json`);
    const onLine = (l) => { job.progress.push(l.trim().replace(/\s+/g, " ").slice(0, 120)); this.emit("job", this.#public(job)); };
    let r;
    if (!admin) {
      r = await this.run(this.ps, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", this.engine.hunt, "-Out", out], { timeoutMs: 15 * 60_000, onLine });
    } else {
      // Elevation hands the script admin rights: refuse a copy that differs from what shipped.
      if (!this.engine.verify("hunt.ps1") || !this.engine.verify("hideout.ps1")) throw new Error("the deep-check script on disk does not match the one Hideout shipped with - refusing to run it as admin");
      job.progress.push("Windows will ask for permission - click Yes to continue.");
      this.emit("job", this.#public(job));
      const inner = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", `"${this.engine.hunt}"`, "-Out", `"${out}"`];
      const script = `$ErrorActionPreference='Stop'; try { $p = Start-Process -FilePath ${psq(this.ps)} -Verb RunAs -Wait -PassThru -ArgumentList @(${inner.map(psq).join(",")}); exit $p.ExitCode } catch { exit 5 }`;
      r = await this.run(this.ps, ["-NoProfile", "-EncodedCommand", encodePs(script)], { timeoutMs: 20 * 60_000 });
      if (r.code === 5) throw new Error("admin permission wasn't given (the Windows prompt was declined or timed out)");
    }
    if (!fs.existsSync(out)) throw new Error(`deep check did not finish (${r.why || "exit " + r.code})`);
    const snapshot = JSON.parse(fs.readFileSync(out, "utf8"));
    this.latestHunt = { at: now(), admin: !!snapshot.admin, path: out, summary: summarizeHunt(snapshot) };
    const notable = {};
    for (const [k, v] of Object.entries(this.latestHunt.summary)) if (v && Array.isArray(v.notable) && v.notable.length) notable[k] = v.notable.length;
    await this.brain?.remember("deep", { admin: !!snapshot.admin, notable });
    job.message = `deep check done${snapshot.admin ? " (with admin)" : ""}`;
  }
}

// ---------------------------------------------------------------------------------
// A deep-check snapshot is ~700 KB. The guide gets the notable parts: anything a
// person could act on, plus counts so "nothing unusual" is a statement with a size.
const items = (s, name) => (s?.sections?.[name]?.items) || [];
const ok = (s, name) => s?.sections?.[name]?.ok !== false;
const pick = (o, keys) => Object.fromEntries(keys.filter((k) => o[k] !== undefined && o[k] !== null && o[k] !== "").map((k) => [k, o[k]]));
const BAD_FLAGS = new Set(["encoded-command", "download", "eval", "long-base64", "policy-bypass", "hidden-window"]);
const oddSig = (sig) => sig && sig !== "Valid";

export function summarizeHunt(s) {
  const sec = (name, notable, extra = {}) => ({ checked: items(s, name).length, collected: ok(s, name), notable, ...extra });
  const tasks = items(s, "scheduledTasks").filter((t) => !String(t.path || "").startsWith("\\Microsoft\\"));
  const oddTasks = tasks.filter((t) => (t.actions || []).some((a) => a.userFolder || (a.flags || []).some((f) => BAD_FLAGS.has(f)) || a.sig === "HashMismatch" || a.sig === "NotSigned") || t.hidden);
  const defender = items(s, "defender");
  const network = items(s, "network");
  return {
    computerIsAdminRun: !!s.admin,
    collectedAt: s.started,
    hideoutFindings: items(s, "hideout").map((f) => pick(f, ["severity", "kind", "name", "state", "program", "folder", "signer", "arrived", "reasons"])),
    scheduledTasks: sec("scheduledTasks", oddTasks.slice(0, 40).map((t) => ({ ...pick(t, ["name", "state", "author", "registered", "hidden", "runAs", "lastRun"]), actions: (t.actions || []).map((a) => pick(a, ["program", "sig", "signer", "userFolder", "flags", "urlHosts"])) })), { nonMicrosoft: tasks.length }),
    services: sec("services", items(s, "services").filter((x) => x.userFolder || (oddSig(x.sig) && x.sig !== "FileMissing") || oddSig(x.serviceDllSig)).slice(0, 30).map((x) => pick(x, ["name", "display", "state", "start", "program", "sig", "signer", "serviceDll", "serviceDllSig"]))),
    drivers: sec("drivers", items(s, "drivers").slice(0, 20)),
    registryAutoruns: sec("registryAutoruns", items(s, "registryAutoruns").slice(0, 60).map((x) => pick(x, ["where", "name", "program", "sig", "signer", "userFolder", "flags", "value", "urlHosts"]))),
    startupFolders: sec("startupFolders", items(s, "startupFolders").map((x) => pick(x, ["file", "created", "program", "sig", "signer", "flags"]))),
    wmiSubscriptions: sec("wmiSubscriptions", items(s, "wmiSubscriptions")),
    defender: sec("defender", defender.filter((d) => d.type !== "status"), { status: defender.find((d) => d.type === "status") || null }),
    rootCertificates: sec("rootCertificates", items(s, "rootCertificates").filter((c) => c.subject === c.issuer && Number(String(c.notBefore).slice(0, 4)) >= 2023)),
    network: sec("network", network.filter((n) => (n.state === "Established" && (oddSig(n.sig) || /\\(AppData|ProgramData|Temp)\\/i.test(n.path || ""))) || (n.state === "Listen" && /^(0\.0\.0\.0|::):/.test(n.local || "") && !/^(svchost|System|lsass|wininit|services|spoolsv)$/i.test(n.process || ""))).slice(0, 30)),
    processes: sec("processes", items(s, "processes").slice(0, 30).map((p) => pick(p, ["name", "path", "sig", "signer", "started", "parent", "flags"]))),
    recentFiles: sec("recentFiles", items(s, "recentFiles").filter((f) => f.kind === "program").sort((a, b) => String(b.created).localeCompare(String(a.created))).slice(0, 30).map((f) => pick(f, ["path", "created", "sig", "size"])), { scriptsOrShortcuts: items(s, "recentFiles").filter((f) => f.kind !== "program").length }),
    powershellProfiles: sec("powershellProfiles", items(s, "powershellProfiles").filter((p) => (p.flags || []).length)),
    browserExtensions: sec("browserExtensions", items(s, "browserExtensions").filter((e) => (e.riskyPermissions || []).length).map((e) => pick(e, ["browser", "name", "version", "updateUrl", "riskyPermissions"]))),
    hostsAndProxy: sec("hostsAndProxy", items(s, "hostsAndProxy")),
    accounts: sec("accounts", items(s, "accounts")),
  };
}
