import { Doors } from "./src/doors/doors.mjs";
import { runProcess } from "./src/engine.mjs";

const r = await runProcess("pwsh", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "../doors.ps1", "-Pass", "quick"], { timeoutMs: 20000 });
if (r.code !== 0) { console.log("engine run failed", r); process.exit(1); }
const raw = JSON.parse(r.stdout);
console.log("extraAccount section, raw from engine:", JSON.stringify(raw.sections.extraAccount));

const fakeWorker = {
  latestScan: null,
  latestDoors: { quick: { at: new Date().toISOString(), ...raw }, slow: null, speed: null },
  on() {},
};
const d = new Doors({ worker: fakeWorker });
const v = d.view();
console.log("extraAccount verdict (through the real PR2 Doors class):", JSON.stringify(v.doors.extraAccount));
console.log("headline:", v.summary.headline);
if (v.doors.extraAccount.verdict === "not_checked") {
  console.log("PASS: a thrown Section correctly surfaces as not_checked, never a guessed 'shut'");
  process.exit(0);
} else {
  console.log("FAIL: expected not_checked, got", v.doors.extraAccount.verdict);
  process.exit(1);
}
