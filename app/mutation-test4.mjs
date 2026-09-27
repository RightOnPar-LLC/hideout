import { runProcess } from "./src/engine.mjs";
import { Doors } from "./src/doors/doors.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const out = path.join(os.tmpdir(), "doors-mutation-test.json");
const r = await runProcess("C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "../doors.ps1", "-Pass", "quick", "-Out", out], { timeoutMs: 20000 });
console.log("exit code:", r.code, "out exists:", fs.existsSync(out));
const raw = JSON.parse(fs.readFileSync(out, "utf8"));
console.log("extraAccount section raw (ok/error):", raw.sections.extraAccount.ok, raw.sections.extraAccount.error);

const fakeWorker = { latestScan: null, latestDoors: { quick: { at: new Date().toISOString(), ...raw }, slow: null, speed: null }, on() {} };
const d = new Doors({ worker: fakeWorker });
const v = d.view();
console.log("extraAccount verdict (through the real PR2 Doors class):", JSON.stringify(v.doors.extraAccount));
console.log(v.doors.extraAccount.verdict === "not_checked" ? "PASS: thrown Section -> not_checked, never a guessed shut" : "FAIL: " + v.doors.extraAccount.verdict);
