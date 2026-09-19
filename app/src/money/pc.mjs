// pc.mjs — which programs are installed on this PC (read-only), so Money can say "this is
// on your PC AND on your bill", and so remote-access tools a scammer may have left behind
// show up next to the money they may have moved. Reads the three Uninstall registry lists;
// changes nothing.
import { runProcess, POWERSHELL, encodePs } from "../engine.mjs";

export const INSTALLED_SCRIPT = [
  "$ErrorActionPreference='SilentlyContinue'",
  "$k='HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'",
  "@(Get-ItemProperty -Path $k | Where-Object { $_.DisplayName } | ForEach-Object { [pscustomobject]@{ n = [string]$_.DisplayName; p = [string]$_.Publisher; d = [string]$_.InstallDate } }) | ConvertTo-Json -Compress",
].join("; ");

// Remote-support tools that tech-support scammers commonly ask people to install. Being
// installed isn't proof of anything (IT departments use them too) - it's a question to ask.
export const REMOTE_TOOLS = ["AnyDesk", "TeamViewer", "ScreenConnect", "ConnectWise Control", "Zoho Assist", "LogMeIn", "GoTo Resolve", "UltraViewer", "RustDesk", "Splashtop", "Supremo", "AeroAdmin", "Ammyy", "RemotePC", "Chrome Remote Desktop", "Remote Utilities", "HopToDesk", "DWService", "SimpleHelp", "Atera"];

export function parseInstalled(stdout) {
  let v; try { v = JSON.parse(String(stdout || "").trim() || "[]"); } catch { return []; }
  const list = (Array.isArray(v) ? v : [v]).filter((x) => x && typeof x.n === "string");
  const seen = new Set();
  return list.map((x) => ({ name: x.n.slice(0, 120), publisher: String(x.p || "").slice(0, 80), installed: /^\d{8}$/.test(x.d || "") ? `${x.d.slice(0, 4)}-${x.d.slice(4, 6)}-${x.d.slice(6)}` : null }))
    .filter((x) => !seen.has(x.name) && seen.add(x.name));
}

export function remoteToolsIn(installed) {
  return installed.filter((p) => REMOTE_TOOLS.some((t) => p.name.toLowerCase().includes(t.toLowerCase())));
}

export async function listInstalled({ run = runProcess, powershell = POWERSHELL } = {}) {
  const r = await run(powershell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePs(INSTALLED_SCRIPT)], { timeoutMs: 60_000 });
  return r.code === 0 ? parseInstalled(r.stdout) : null;
}
