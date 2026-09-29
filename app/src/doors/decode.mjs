// decode.mjs - small, tested lookup tables for the numeric codes doors.ps1 hands back as
// raw facts. Policy-sized text (labels, click paths) belongs in the cached system prompt
// (guide-spec.mjs), not here: this file is code-matched numeric-to-meaning tables only, so
// a new value gets a test, not a prompt edit. Nothing here judges good or bad on its own -
// verdicts live in summarize.mjs, which reads these tables.

// Get-ScheduledTaskInfo's LastTaskResult, decoded against Microsoft's own documented values.
// 0x800710E0 and 0xC000013A are NOT failures: Windows refused to run the task under a start
// condition (commonly "only on AC power") or killed it at sign-out/shutdown. Treating either
// as broken sends a person chasing a bug that is a setting, not code - see
// power.startupHealth's falsePositiveGuards.
export const LAST_TASK_RESULT = {
  0: "ran",
  267009: "running",
  267011: "never-ran",
  [0x800710e0]: "refused-by-condition",
  [0xc000013a]: "killed-at-signout",
};

export function decodeLastTaskResult(code) {
  if (code === null || code === undefined || code === "") return "not_checked";
  const n = typeof code === "string" ? Number(code) : code;
  if (!Number.isFinite(n)) return "not_checked";
  const label = LAST_TASK_RESULT[n];
  return label || "failed";
}

// Kernel-Power event ids doors.ps1 reads. Id 125 is deliberately never decoded to anything
// but "ignore" here - it is per-boot ACPI enumeration, not a heat alarm (box-audit's
// founding gotcha, measured this session); doors.ps1 never even queries it.
export const KERNEL_POWER_IDS = {
  41: "unexpected-shutdown",
  105: "ac-source-change",
  524: "critical-battery",
  125: "ignore-acpi-enumeration",
};

// Explorer's System.Volume.BitLockerProtection property (read without admin). Measured this
// session, non-admin, Windows PowerShell 5.1: it answered in 0.3s while the CIM class threw
// Access denied. 0 is deliberately mapped to not_checked, never "off" - this session's own
// probe could not tell "the property answered and said off" apart from "unprotected meaning
// nothing was ever set up here", and the spec that documents this property does not resolve
// that ambiguity either, so Hideout never guesses a door shut that might just be unset.
export const BITLOCKER_SHELL_PROPERTY = {
  1: "on",
  2: "off",
  3: "turning-on",
  4: "turning-off",
  5: "paused",
  6: "locked",
};

export function decodeBitLockerShellProperty(value) {
  if (value === null || value === undefined || value === "") return "not_checked";
  const n = typeof value === "string" ? Number(value) : value;
  if (!Number.isFinite(n)) return "not_checked";
  return BITLOCKER_SHELL_PROPERTY[n] || "not_checked";
}
