import { runProcess } from "./src/engine.mjs";
const r = await runProcess("C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "../doors.ps1", "-Pass", "quick", "-Out", "C:\Users\vipth\AppData\Local\Temp\doors-mutation-test.json"], { timeoutMs: 20000 });
console.log("code:", r.code, "why:", r.why, "stderr:", r.stderr.slice(0,500));
console.log("stdout:", r.stdout.slice(0,300));
