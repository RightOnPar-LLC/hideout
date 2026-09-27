import { runProcess } from "./src/engine.mjs";

// Exactly worker.mjs's #doors invocation: no -Out, relies on stdout being pure JSON.
const r = await runProcess("pwsh", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "../doors.ps1", "-Pass", "quick"], { timeoutMs: 20000 });
console.log("exit code:", r.code);
console.log("--- first 300 chars of stdout ---");
console.log(r.stdout.slice(0, 300));
console.log("--- attempting JSON.parse(r.stdout) ---");
try {
  const data = JSON.parse(r.stdout);
  console.log("JSON.parse SUCCEEDED. pass field:", data.pass);
} catch (e) {
  console.log("JSON.parse FAILED:", e.message);
}
