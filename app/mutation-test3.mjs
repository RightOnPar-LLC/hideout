import { runProcess, POWERSHELL } from "./src/engine.mjs";

console.log("Using the exact executable worker.mjs uses:", POWERSHELL);
const r = await runProcess(POWERSHELL, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "../doors.ps1", "-Pass", "quick"], { timeoutMs: 20000 });
console.log("exit code:", r.code);
console.log("--- first 400 chars of stdout ---");
console.log(JSON.stringify(r.stdout.slice(0, 400)));
try {
  const data = JSON.parse(r.stdout);
  console.log("JSON.parse SUCCEEDED. pass field:", data.pass);
} catch (e) {
  console.log("JSON.parse FAILED (this is exactly worker.mjs's #doors catch path):", e.message);
}
