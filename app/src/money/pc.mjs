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
// Each entry also carries its RUNNING process name(s), for Doors & power's "running right
// now" reading (doors.ps1 emits process NAMES only, never CommandLine) - a product name and
// its process name(s) often differ (Zoho Assist runs as ZohoMeeting / ZA_Access, ConnectWise
// Control as ScreenConnect.ClientService, Chrome Remote Desktop as remoting_host, Remote
// Utilities as rutserv, GoTo Resolve without the space), so this is ONE table with two
// columns, not two separate matchers that could silently drift apart.
export const REMOTE_TOOLS = [
  { name: "AnyDesk", processes: ["AnyDesk"] },
  { name: "TeamViewer", processes: ["TeamViewer", "TeamViewer_Service"] },
  { name: "ScreenConnect", processes: ["ScreenConnect.ClientService", "ScreenConnect.WindowsClient"] },
  { name: "ConnectWise Control", processes: ["ScreenConnect.ClientService", "ScreenConnect.WindowsClient"] },
  { name: "Zoho Assist", processes: ["ZohoMeeting", "ZA_Access", "ZohoURSService"] },
  { name: "LogMeIn", processes: ["LogMeIn", "LMIGuardianSvc"] },
  { name: "GoTo Resolve", processes: ["GoToResolve"] },
  { name: "UltraViewer", processes: ["UltraViewer_Desktop", "UltraViewer_Service"] },
  { name: "RustDesk", processes: ["rustdesk"] },
  { name: "Splashtop", processes: ["SRServer", "SplashtopRemoteService", "SplashtopSOS"] },
  { name: "Supremo", processes: ["Supremo"] },
  { name: "AeroAdmin", processes: ["AeroAdmin"] },
  { name: "Ammyy", processes: ["AA_v3", "Ammyy_Admin"] },
  { name: "RemotePC", processes: ["RPCSuite", "RemotePCService"] },
  { name: "Chrome Remote Desktop", processes: ["remoting_host"] },
  { name: "Remote Utilities", processes: ["rutserv", "rfusclient"] },
  { name: "HopToDesk", processes: ["HopToDesk"] },
  { name: "DWService", processes: ["dwagent", "dwagsvc"] },
  { name: "SimpleHelp", processes: ["JWrapper-Remote Access", "SimpleHelp"] },
  { name: "Atera", processes: ["AteraAgent"] },
];

export function parseInstalled(stdout) {
  let v; try { v = JSON.parse(String(stdout || "").trim() || "[]"); } catch { return []; }
  const list = (Array.isArray(v) ? v : [v]).filter((x) => x && typeof x.n === "string");
  const seen = new Set();
  return list.map((x) => ({ name: x.n.slice(0, 120), publisher: String(x.p || "").slice(0, 80), installed: /^\d{8}$/.test(x.d || "") ? `${x.d.slice(0, 4)}-${x.d.slice(4, 6)}-${x.d.slice(6)}` : null }))
    .filter((x) => !seen.has(x.name) && seen.add(x.name));
}

export function remoteToolsIn(installed) {
  return installed.filter((p) => REMOTE_TOOLS.some((t) => p.name.toLowerCase().includes(t.name.toLowerCase())));
}

// Which of the REMOTE_TOOLS table are running RIGHT NOW, from a plain list of process names
// (doors.ps1's remoteSupportInstalled Section - Get-Process names only). Case-insensitive,
// exact process-name match (never substring - "AnyDesk" the product is a substring match on
// installed-program text, but its process name must match exactly, or "rustdesk" would also
// match an unrelated "rustdeskhelper.exe").
export function runningRemoteTools(processNames = []) {
  const seen = new Set((processNames || []).map((p) => String(p).toLowerCase()));
  return REMOTE_TOOLS.filter((t) => t.processes.some((p) => seen.has(p.toLowerCase())));
}

export async function listInstalled({ run = runProcess, powershell = POWERSHELL } = {}) {
  const r = await run(powershell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePs(INSTALLED_SCRIPT)], { timeoutMs: 60_000 });
  return r.code === 0 ? parseInstalled(r.stdout) : null;
}
