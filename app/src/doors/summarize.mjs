// summarize.mjs - every verdict for the Doors & power tab, computed here in JS from the
// RAW FACTS doors.ps1 collects (every Section over there returns {checked, control, facts};
// this file never touches PowerShell and never runs a command - it is pure functions over
// plain data, which is why its tests are JSON fixtures rather than a live machine).
//
// The one rule every function below obeys: "not checked" is never shown as clean, and a
// reading only counts when its own control observation proved the read actually answered.
// When two instruments disagree, the answer is "couldn't check", never a guess.
//
// This file does NOT decide which account names, task names or PC name reach the guide -
// that redaction step (turning a real name into "account 1") happens one layer up, in the
// Doors class (PR2), the same way worker.mjs's summarizeHunt does today.
import { decodeLastTaskResult, decodeBitLockerShellProperty } from "./decode.mjs";

const isManaged = (partOfDomain, entraJoined) => !!(partOfDomain || entraJoined);

// ------------------------------------------------------------------ doors.remoteDesktop
export function summarizeRemoteDesktop({
  fDeny = null,
  nlaOn = null,
  remoteSessions = [],
  partOfDomain = false,
  entraJoined = false,
  termServicePresent = null,
  firewallGroupPresent = null,
  firewall = null, // { checked: bool, enabledRuleCount: number|null }
} = {}) {
  const managed = isManaged(partOfDomain, entraJoined);
  if (fDeny === null || fDeny === undefined) {
    if (termServicePresent === false && firewallGroupPresent === false) {
      return { verdict: "not-available", doorOpen: false, managed };
    }
    return { verdict: "not_checked", doorOpen: false, managed };
  }
  if (managed) return { verdict: "set-by-your-organisation", doorOpen: false, managed };
  if (fDeny === 1) return { verdict: "shut", doorOpen: false, managed };
  // fDeny === 0: Remote Desktop is on. The inverted boolean is asserted both ways by the
  // fixtures below so a sign flip in doors.ps1 fails this suite, not a person's PC.
  const connected = (remoteSessions || []).length > 0;
  if (connected) return { verdict: "open-and-connected", doorOpen: true, managed, nlaOn: !!nlaOn };
  if (firewall && firewall.checked === false) {
    return { verdict: "open", doorOpen: true, managed, nlaOn: !!nlaOn, firewallDetail: "not_checked" };
  }
  if (firewall && firewall.enabledRuleCount === 0) {
    return { verdict: "open-but-blocked", doorOpen: true, managed, nlaOn: !!nlaOn };
  }
  return { verdict: "open", doorOpen: true, managed, nlaOn: !!nlaOn };
}

// ------------------------------------------------------------------ doors.extraAccount
const CLOUD_SOURCES = new Set(["MicrosoftAccount", "AzureAD"]);
export function summarizeExtraAccount({
  administrators = [], // enabled+disabled local accounts that are members of Administrators
  partOfDomain = false,
  entraJoined = false,
  builtinsPresent = null, // control: did the built-in accounts show up in the FULL user list
} = {}) {
  if (builtinsPresent === false) return { verdict: "not_checked" };
  const managed = isManaged(partOfDomain, entraJoined);
  if (managed) return { verdict: "set-by-your-organisation", managed };
  const judged = administrators.filter((a) => a.enabled && !CLOUD_SOURCES.has(a.principalSource));
  const noPassword = judged.filter((a) => a.passwordRequired === false && !a.passwordLastSet);
  if (noPassword.length) return { verdict: "open", accounts: noPassword.map((a) => a.name) };
  const maybeBlank = judged.filter((a) => a.passwordRequired === false && a.passwordLastSet);
  if (maybeBlank.length) return { verdict: "worth-a-look", reason: "maybe-blank", accounts: maybeBlank.map((a) => a.name) };
  if (judged.length >= 2) return { verdict: "worth-a-look", reason: "second-admin", accounts: judged.map((a) => a.name) };
  return { verdict: "shut" };
}

// ------------------------------------------------------------------ doors.diskEncryption
// The admin (hunt.ps1 'bitlocker' Section) reading, when present, overrides the quick Shell
// property read - it is authoritative and never carries a recovery key (hunt.ps1 selects
// only MountPoint/VolumeStatus/ProtectionStatus/EncryptionPercentage/KeyProtectorType).
export function mapAdminBitlockerVolume({ volumeStatus = "", protectionStatus = "" } = {}) {
  const vs = String(volumeStatus || "").toLowerCase();
  const ps = String(protectionStatus || "").toLowerCase();
  if (!vs) return null;
  if (vs.includes("fullyencrypted")) return ps === "off" ? "paused" : "on";
  if (vs.includes("fullydecrypted")) return "off";
  if (vs.includes("encryptioninprogress")) return "turning-on";
  if (vs.includes("decryptioninprogress")) return "turning-off";
  if (vs.includes("locked")) return "locked";
  return null;
}

export function summarizeDiskEncryption({ shellProperty = null, admin = null } = {}) {
  if (admin && admin.verdict) return { verdict: admin.verdict, confidence: "admin" };
  return { verdict: decodeBitLockerShellProperty(shellProperty), confidence: "quick" };
}

// ------------------------------------------------------------------ doors.remoteSupport
// The name-to-process matching table (pc.mjs REMOTE_TOOLS gaining a `processes` column) is
// PR2's job - this function stays a pure verdict over already-matched lists so it does not
// need to change again when that table grows.
export function summarizeRemoteSupport({ installedMatches = [], runningMatches = [], knownProcessSeen = null } = {}) {
  if (knownProcessSeen === false) return { verdict: "not_checked" };
  if (runningMatches.length) return { verdict: "running-now", tools: [...runningMatches] };
  if (installedMatches.length) return { verdict: "installed", tools: [...installedMatches] };
  return { verdict: "none" };
}

// ------------------------------------------------------------------ doors.antivirus
export function summarizeAntivirus(
  { amRunningMode = null, realTimeProtectionEnabled = null, signatureAgeDays = null, fullScanEndTime = "" } = {},
  { leftoversCount = 0 } = {}
) {
  if (!amRunningMode) return { verdict: "not_checked" };
  const mode = String(amRunningMode).toLowerCase();
  if (mode === "passive" || mode === "sxs") return { verdict: "other-antivirus" };
  let verdict = "fine";
  if (realTimeProtectionEnabled === false) verdict = "open";
  else if (signatureAgeDays != null && signatureAgeDays > 7) verdict = "stale-signatures";
  const suggestions = [];
  const neverFullScan = !fullScanEndTime;
  if (neverFullScan) {
    suggestions.push("full-scan-never");
    // A full scan having never run counts toward "doors open" only when something else
    // already flagged it (leftovers) or real-time protection is off - it is normal on most
    // home PCs and counting it there would make an ordinary PC read broken.
    if (verdict === "fine" && leftoversCount > 0) verdict = "full-scan-never";
  }
  return { verdict, suggestions, realTimeProtectionEnabled: !!realTimeProtectionEnabled };
}

// ------------------------------------------------------------------ doors.leftovers (no new
// engine code - reads the existing scan/defender/case-file data; see engineChecks id
// "doors.leftovers"). A custom folder scan leaves no end time Get-MpComputerStatus exposes,
// so "by your word" is the honest label for that path.
export function summarizeLeftovers({
  findingsCount = 0,
  newestFindingArrivedAt = null,
  quickScanEndTime = "",
  fullScanEndTime = "",
  folderScanStepDone = false,
} = {}) {
  if (findingsCount === 0) return { verdict: "none", deleteAllowed: false };
  const scanEnds = [quickScanEndTime, fullScanEndTime].filter(Boolean).sort();
  const latestScanEnd = scanEnds.length ? scanEnds[scanEnds.length - 1] : null;
  const evidenceUnlocks = !!(latestScanEnd && newestFindingArrivedAt && latestScanEnd > newestFindingArrivedAt);
  if (evidenceUnlocks) return { verdict: "clear-to-delete-by-evidence", deleteAllowed: true, unlockedBy: "evidence" };
  if (folderScanStepDone) return { verdict: "clear-to-delete-by-your-word", deleteAllowed: true, unlockedBy: "your-word" };
  if (!quickScanEndTime && !fullScanEndTime) return { verdict: "not_checked", deleteAllowed: false };
  return { verdict: "flagged", deleteAllowed: false, findingsCount };
}

// ------------------------------------------------------------------ power.suddenShutdowns
// Cross-references doors.batteryAndCharger's KP105/524 facts to exclude a shutdown that was
// really the battery running flat, not a fault - a laptop that ran flat in a bag isn't one.
export function markRanFlat(kp41 = [], kp524 = [], windowMs = 5 * 60 * 1000) {
  const t = (s) => Date.parse(s) || 0;
  const kp524Times = kp524.map((e) => t(e.timeCreated)).filter(Boolean).sort((a, b) => a - b);
  return kp41.map((e) => {
    const at = t(e.timeCreated);
    const ranFlat = kp524Times.some((flatAt) => flatAt <= at && at - flatAt < windowMs);
    return { ...e, ranFlat };
  });
}

function classifyShutdown(e, { count1001, minidumps, memoryDmp, crashDumpEnabled }) {
  const btn = Number(e.powerButtonTimestamp);
  if (Number.isFinite(btn) && btn !== 0) return "held-power-button";
  const bugcheck = Number(e.bugcheckCode) || 0;
  const hasDumpEvidence = bugcheck !== 0 || count1001 > 0 || minidumps.length > 0 || memoryDmp;
  if (hasDumpEvidence) return "crash";
  if (Number(crashDumpEnabled) === 0) return "cant-tell";
  return "power-loss";
}

export function summarizeSuddenShutdowns({
  kp41 = [], // pre-marked by markRanFlat: [{ timeCreated, bugcheckCode, powerButtonTimestamp, ranFlat }]
  count1001 = 0,
  minidumps = [],
  memoryDmp = false,
  crashDumpEnabled = null,
  controlSampleCount = null, // the same System-log query WITHOUT the Id filter; null = log unreadable
} = {}) {
  if (controlSampleCount === null || controlSampleCount === undefined) return { verdict: "not_checked" };
  const ranFlatCount = kp41.filter((e) => e.ranFlat).length;
  const real = kp41.filter((e) => !e.ranFlat);
  const n = real.length;
  let band = "quiet";
  if (n >= 10) band = "fix-now";
  else if (n >= 3) band = "soon";
  else if (n >= 1) band = "note";
  const classes = real.map((e) => classifyShutdown(e, { count1001, minidumps, memoryDmp, crashDumpEnabled }));
  return { verdict: band, count: n, ranFlatCount, classes };
}

// ------------------------------------------------------------------ power.batteryAndCharger
// AC/DC reversals within 60s are one episode; a docked commuter's dock/undock cycle logs
// several KP105 within seconds, so total count is never the headline - distinct DAYS with an
// episode are.
export function clusterEpisodes(kp105 = []) {
  const times = kp105.map((e) => Date.parse(e.timeCreated)).filter(Number.isFinite).sort((a, b) => a - b);
  const clusters = [];
  let clusterStart = null;
  for (const t of times) {
    if (clusterStart === null || t - clusterStart > 60_000) {
      clusterStart = t;
      clusters.push({ day: new Date(t).toISOString().slice(0, 10) });
    }
  }
  return clusters;
}

export function summarizeBatteryAndCharger({
  hasBattery = null,
  kp105 = [],
  designedCapacity = null,
  fullChargedCapacity = null,
  ranFlatCount = 0,
  diedPluggedInCount = 0,
  diedOnBatteryCount = 0,
} = {}) {
  if (hasBattery === false) return { verdict: "no-battery" };
  if (hasBattery === null) return { verdict: "not_checked" };
  const episodes = clusterEpisodes(kp105);
  const chargerEpisodeDays = new Set(episodes.map((e) => e.day)).size;
  const health = designedCapacity && fullChargedCapacity && designedCapacity > 0
    ? Math.round((fullChargedCapacity / designedCapacity) * 100)
    : null;
  let verdict = "fine";
  if (diedPluggedInCount >= 2 || (health != null && health < 60)) verdict = "fix-now";
  else if (chargerEpisodeDays >= 5 || diedOnBatteryCount >= 3 || (health != null && health < 70)) verdict = "soon";
  return { verdict, health, chargerEpisodeDays, ranFlatCount, diedPluggedInCount, diedOnBatteryCount };
}

// ------------------------------------------------------------------ power.sleepTimers
// On a Modern Standby PC, STANDBYIDLE=0 does not mean "never sleeps" - VIDEOIDLE and the
// hidden VIDEOCONLOCK are what put the box into S0 low-power idle (this session's corrected
// root cause). The effective "sleeps after N minutes alone" reading is whichever of the two
// is actually driving it.
export function summarizeSleepTimers(
  { standbyIdleAc = null, videoIdleAc = null, videoConLockAc = null, modelListed = null, registryOk = true, qhAgrees = null } = {},
  { pcMustStayOn = false } = {}
) {
  if (!registryOk) return { verdict: "not_checked" };
  if (qhAgrees === false) return { verdict: "not_checked", note: "registry and powercfg disagree" };
  const neverSleeps = standbyIdleAc === 0 && videoIdleAc === 0;
  if (neverSleeps) return { verdict: "never-sleeps" };
  const effectiveIdleSeconds = standbyIdleAc && standbyIdleAc > 0 ? standbyIdleAc : videoIdleAc;
  if (effectiveIdleSeconds == null && videoConLockAc == null) return { verdict: "not_checked" };
  const standbyMinutes = effectiveIdleSeconds != null ? Math.round(effectiveIdleSeconds / 60) : null;
  const verdict = pcMustStayOn ? "soon" : "info";
  return { verdict, standbyMinutes, videoConLockSeconds: videoConLockAc ?? null, modelKnown: !!modelListed };
}

// ------------------------------------------------------------------ power.restartWaiting
export function summarizeRestartWaiting({ rebootRequired = false, cbsRebootPending = false, pendingFileRename = false, uxKeyReadable = true } = {}) {
  if (!uxKeyReadable) return { verdict: "not_checked" };
  if (rebootRequired || cbsRebootPending) return { verdict: "restart-waiting" };
  if (pendingFileRename) return { verdict: "possibly" };
  return { verdict: "none" };
}

// ------------------------------------------------------------------ power.startupHealth
// Counts only reach the guide (task names stay in the window) - see redact.mjs and the
// "account n" note in guide-spec.mjs's plan; this function itself never drops a name because
// it doesn't receive one - callers pass tasks flagged by the quick scan only.
export function summarizeStartupHealth({ tasks = [], microsoftTaskSeen = true, vbsLogReadable = true, vbsDeprecationCount = 0, vbsStartupEntries = [] } = {}) {
  if (!microsoftTaskSeen) return { verdict: "not_checked" };
  let neverFairChance = 0, failed = 0;
  for (const t of tasks) {
    const label = decodeLastTaskResult(t.lastTaskResult);
    if (label === "refused-by-condition" || label === "killed-at-signout") neverFairChance++;
    else if (label === "failed") failed++;
  }
  return {
    total: tasks.length,
    neverFairChance,
    failed,
    vbsCount: vbsLogReadable ? vbsDeprecationCount : null,
    vbsStartupCount: vbsStartupEntries.length,
  };
}

// ------------------------------------------------------------------ power.diskSpace
// Percent AND absolute, always together - 12% of a 2TB drive is 240GB free, never a red
// headline on its own.
export function summarizeDiskSpace(drives = []) {
  return drives.map((d) => {
    if (d.sizeBytes == null || d.freeBytes == null || d.sizeBytes === 0) return { drive: d.drive, verdict: "not_checked" };
    const percentFree = (d.freeBytes / d.sizeBytes) * 100;
    const freeGb = d.freeBytes / 1024 ** 3;
    let verdict = "fine";
    if (percentFree < 12 && freeGb < 15) verdict = "fix-now";
    else if (percentFree < 20 && freeGb < 50) verdict = "soon";
    return { drive: d.drive, verdict, percentFree: Math.round(percentFree * 10) / 10, freeGb: Math.round(freeGb) };
  });
}

export function summarizeDiskSpaceGroup(drives = [], { systemDrivePresent = true } = {}) {
  if (!systemDrivePresent) return { verdict: "not_checked", drives: [] };
  return { verdict: "ok", drives: summarizeDiskSpace(drives) };
}

// ------------------------------------------------------------------ power.speedCap
// Never a static clock-speed property (box-audit's founding gotcha) - only the
// Processor Information counters doors.ps1 samples with an in-process load running.
export function summarizeSpeedCap({ perf = [], util = [], counterOk = true } = {}) {
  if (!counterOk || perf.length === 0) return { verdict: "not_checked" };
  const maxUtil = Math.max(0, ...util);
  if (maxUtil < 60) return { verdict: "unclear" };
  const maxPerf = Math.max(0, ...perf);
  if (maxPerf >= 90) return { verdict: "full-speed" };
  if (maxPerf < 60) return { verdict: "capped" };
  return { verdict: "unclear" };
}
