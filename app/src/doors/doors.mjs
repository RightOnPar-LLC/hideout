// doors.mjs — the Doors class: turns the worker's latest doors-quick / doors-slow /
// doors-speed raw-fact runs into the verdicts the window and the guide see. Every verdict
// RULE lives in summarize.mjs / decode.mjs (PR1) - this file's only job is wiring: which raw
// fact from doors.ps1's Sections feeds which summarize* function, the "account n" name
// treatment (mirrors worker.mjs's summarizeHunt), and deleteAllowed's reason.
//
// Mirrors money.mjs's shape: a class that holds no state of its own beyond references
// (worker, brain, money) and computes view()/guideView() fresh each time, exactly like
// Money.view()/guideView() do - so there is never a second, cacheable copy of a verdict to
// go stale relative to the raw facts underneath it.
//
// "Not checked is never shown as clean": every summarize* function already treats a missing
// or false control as not_checked, but several of them ALSO default an unpassed control flag
// to true or null in a way that's safe for a unit-test fixture (a fixture that omits a field
// means "not part of THIS test") but would be UNSAFE here (an app that has never run a pass
// at all must never look confirmed-clean). So every control-shaped input below is computed
// explicitly with `!!` - coercing "no run yet" / "section threw" to `false`, never left to a
// summarize* function's own JS default parameter.
import {
  summarizeRemoteDesktop, summarizeExtraAccount, summarizeDiskEncryption,
  summarizeRemoteSupport, summarizeAntivirus, summarizeLeftovers, markRanFlat, summarizeSuddenShutdowns,
  summarizeBatteryAndCharger, summarizeSleepTimers, summarizeRestartWaiting,
  summarizeStartupHealth, summarizeDiskSpaceGroup, summarizeSpeedCap,
} from "./summarize.mjs";
import { decodeLastTaskResult } from "./decode.mjs";
import { remoteToolsIn, runningRemoteTools } from "../money/pc.mjs";
import { anonymizeAccounts } from "../worker.mjs";

export { anonymizeAccounts };
const now = () => new Date().toISOString();
export const minutesAgo = (iso, ref = Date.now()) => (iso ? Math.max(0, Math.round((ref - Date.parse(iso)) / 60000)) : null);

// Best-effort cross-check between the registry read (primary) and `powercfg /qh`'s text
// (secondary). Returns true/false only when BOTH the setting's own text block and its
// "Current AC Power Setting Index" line are found; null ("couldn't tell from the text") on
// any other shape, which the caller treats as "trust the registry" - never as a disagreement
// that was not actually observed. GUID is the setting's own GUID (STANDBYIDLE, VIDEOIDLE),
// never the subgroup GUID, so the two settings sharing one Sleep/Video block don't collide.
export function qhAgreesWithRegistry(qhText, settingGuid, registryAcSeconds) {
  if (!qhText || registryAcSeconds == null) return null;
  const guidRe = new RegExp(String(settingGuid).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
  const m = guidRe.exec(qhText);
  if (!m) return null;
  const tail = qhText.slice(m.index, m.index + 2000);
  const idx = /Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)/.exec(tail);
  if (!idx) return null;
  const parsed = parseInt(idx[1], 16);
  if (!Number.isFinite(parsed)) return null;
  return parsed === registryAcSeconds;
}

// The AC/DC state at the moment of a shutdown: the most recent KP105 (ac-source-change)
// event at or before it. null when no KP105 precedes it at all (unknown, never guessed).
export function acOnlineStateAt(kp105, atMs) {
  const events = (kp105 || [])
    .map((e) => ({ t: Date.parse(e.timeCreated), ac: e.acOnline === true || e.acOnline === "true" || e.acOnline === "1" || e.acOnline === 1 }))
    .filter((e) => Number.isFinite(e.t))
    .sort((a, b) => a.t - b.t);
  let state = null;
  for (const e of events) { if (e.t > atMs) break; state = e.ac; }
  return state;
}

// doors.ps1's own Section() wrapper (repo root, not this file) shapes every entry in
// `sections` as { ok, items: [ {checked, control, facts} ], seconds } - items is an array
// because PowerShell's `@(& $body)` always wraps a scriptblock's return value, even a single
// object, in an array. `ok: false` (the WHOLE Section body threw, never caught inside it) and
// a missing/empty items array both collapse to "no reading at all" here, the same as a
// Section that ran but whose OWN inner `checked` came back false - see the file-header note
// on why every caller below still asks for `checked` explicitly rather than trusting `ok`.
const section = (sections, name) => {
  const sec = sections && sections[name];
  if (!sec || sec.ok === false) return null;
  return (sec.items && sec.items[0]) || null;
};
const facts = (sections, name) => section(sections, name)?.facts || {};
const control = (sections, name) => section(sections, name)?.control || {};
const sectionChecked = (sections, name) => !!section(sections, name)?.checked;

// Which verdicts count as "this door is standing open" for the radar dot / headline count.
// A verdict that is merely a QUESTION ("installed" - the person may have put it there
// themselves) or a judgement call that fell short of "open" ("worth-a-look") never counts -
// see doors.remoteSupport's and doors.extraAccount's own falsePositiveGuards.
const DOOR_OPEN = {
  remoteDesktop: (r) => r.doorOpen === true,
  extraAccount: (r) => r.verdict === "open",
  diskEncryption: (r) => r.verdict === "off" || r.verdict === "paused",
  remoteSupport: (r) => r.verdict === "running-now",
  antivirus: (r) => r.verdict === "open" || r.verdict === "full-scan-never" || r.verdict === "stale-signatures",
  leftovers: (r) => r.verdict === "flagged",
};
const NOT_CHECKED = new Set(["not_checked", "not-available"]);

export class Doors {
  constructor({ worker, brain = null, money = null, log = () => {} }) {
    this.worker = worker; this.brain = brain; this.money = money; this.log = log;
    this.onChange = null;
    if (this.worker && typeof this.worker.on === "function") {
      this.worker.on("job", (j) => {
        if (j && j.state === "done" && String(j.kind || "").startsWith("doors-")) {
          this.#remember().catch((e) => this.log(`doors remember failed: ${e.message}`));
          try { this.onChange?.(); } catch {}
        }
      });
    }
  }

  #caseSteps() { return this.brain?.caseFile()?.steps || []; }
  #stepDone(id) { return (this.#caseSteps().find((s) => s.id === id) || {}).status === "done"; }

  // ---------------------------------------------------------------------------- doors rows
  #remoteDesktop(q, s) {
    const rd = facts(q, "remoteDesktopRegistry");
    const fw = section(s, "remoteDesktopFirewall");
    return summarizeRemoteDesktop({
      fDeny: rd.fDenyTSConnections ?? null,
      nlaOn: rd.userAuthenticationNLA ?? null,
      remoteSessions: rd.remoteSessions || [],
      partOfDomain: !!rd.partOfDomain,
      entraJoined: !!rd.entraJoined,
      termServicePresent: q ? !!control(q, "remoteDesktopRegistry").termServicePresent : null,
      firewallGroupPresent: s ? !!control(s, "remoteDesktopFirewall").groupPresent : null,
      firewall: fw ? { checked: !!fw.checked, enabledRuleCount: fw.checked ? (fw.facts.enabledRuleCount ?? null) : null } : { checked: false, enabledRuleCount: null },
    });
  }

  #extraAccount(q) {
    const ea = facts(q, "extraAccount");
    const users = ea.users || [];
    const administrators = (ea.administrators || []).map((a) => {
      const u = users.find((x) => x.name === a.name) || {};
      return { name: a.name, enabled: u.enabled !== false, passwordRequired: u.passwordRequired ?? null, passwordLastSet: u.passwordLastSet || "", principalSource: u.principalSource || a.source || "" };
    });
    return summarizeExtraAccount({
      administrators,
      partOfDomain: !!ea.partOfDomain,
      entraJoined: !!ea.entraJoined,
      builtinsPresent: !!control(q, "extraAccount").builtinsPresent,
    });
  }

  #diskEncryption(q) {
    const de = facts(q, "diskEncryption");
    const sysDrive = process.env.SystemDrive || "C:";
    const drive = (de.drives || []).find((d) => d.drive === sysDrive) || (de.drives || [])[0] || null;
    // The admin (hunt.ps1 "bitlocker" Section) reading is wired once a future PR runs the
    // doors quick sections elevated inside hunt-admin (buildPlan PR6) - until then this stays
    // "quick" confidence, which is honest, never "off" when it is merely unconfirmed.
    return summarizeDiskEncryption({ shellProperty: drive ? drive.shellProperty ?? null : null, admin: null });
  }

  #remoteSupport(q) {
    const rs = facts(q, "remoteSupportInstalled");
    const installed = this.money?.installed || [];
    return summarizeRemoteSupport({
      installedMatches: remoteToolsIn(installed).map((p) => p.name),
      runningMatches: runningRemoteTools(rs.processNames || []).map((t) => t.name),
      knownProcessSeen: !!control(q, "remoteSupportInstalled").knownProcessSeen,
    });
  }

  #antivirus(s) {
    const av = facts(s, "antivirus");
    const leftoversCount = (this.worker?.latestScan?.findings || []).length;
    return summarizeAntivirus(av, { leftoversCount });
  }

  #leftovers(s) {
    const av = facts(s, "antivirus");
    const findings = this.worker?.latestScan?.findings || [];
    const newestFindingArrivedAt = findings.map((f) => f.arrived).filter(Boolean).sort().at(-1) || null;
    return summarizeLeftovers({
      findingsCount: findings.length,
      newestFindingArrivedAt,
      quickScanEndTime: av.quickScanEndTime || "",
      fullScanEndTime: av.fullScanEndTime || "",
      folderScanStepDone: this.#stepDone("windows_security_folder_scan"),
    });
  }

  // ---------------------------------------------------------------------------- power rows
  #suddenShutdowns(s) {
    const ss = facts(s, "suddenShutdowns");
    const marked = markRanFlat(ss.kp41 || [], (facts(s, "batteryAndCharger").kp524) || []);
    return summarizeSuddenShutdowns({
      kp41: marked,
      count1001: ss.count1001 ?? 0,
      minidumps: ss.minidumps || [],
      memoryDmp: !!ss.memoryDmp,
      crashDumpEnabled: ss.crashDumpEnabled ?? null,
      controlSampleCount: s ? (control(s, "suddenShutdowns").sampleCountWithoutIdFilter ?? null) : null,
    });
  }

  #batteryAndCharger(q, s) {
    const b = facts(q, "battery");
    const bc = facts(s, "batteryAndCharger");
    const ss = facts(s, "suddenShutdowns");
    const marked = markRanFlat(ss.kp41 || [], bc.kp524 || []);
    const ranFlatCount = marked.filter((e) => e.ranFlat).length;
    // For each real (not-ran-flat) sudden shutdown, the AC/DC state at that moment is the
    // most recent KP105 at or before it - "died while plugged in" vs "died on battery".
    let diedPluggedInCount = 0, diedOnBatteryCount = 0;
    for (const e of marked) {
      if (e.ranFlat) continue;
      const t = Date.parse(e.timeCreated);
      if (!Number.isFinite(t)) continue;
      const ac = acOnlineStateAt(bc.kp105 || [], t);
      if (ac === true) diedPluggedInCount++;
      else if (ac === false) diedOnBatteryCount++;
    }
    return summarizeBatteryAndCharger({
      hasBattery: q ? (b.hasBattery ?? null) : null,
      kp105: bc.kp105 || [],
      designedCapacity: b.designedCapacity ?? null,
      fullChargedCapacity: b.fullChargedCapacity ?? null,
      ranFlatCount, diedPluggedInCount, diedOnBatteryCount,
    });
  }

  #sleepTimers(q) {
    const st = facts(q, "sleepTimers");
    const standbyIdleAc = st.standbyIdle ? st.standbyIdle.ac ?? null : null;
    const videoIdleAc = st.videoIdle ? st.videoIdle.ac ?? null : null;
    const videoConLockAc = st.videoConLock ? st.videoConLock.ac ?? null : null;
    const STANDBYIDLE_GUID = "29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA";
    const qhAgrees = qhAgreesWithRegistry(st.qhText, STANDBYIDLE_GUID, standbyIdleAc);
    return summarizeSleepTimers(
      { standbyIdleAc, videoIdleAc, videoConLockAc, modelListed: q ? !!control(q, "sleepTimers").modelListed : false, registryOk: q ? sectionChecked(q, "sleepTimers") : false, qhAgrees },
      { pcMustStayOn: this.#stepDone("pc_must_stay_on") }
    );
  }

  #restartWaiting(q) {
    const rw = facts(q, "restartWaiting");
    return summarizeRestartWaiting({
      rebootRequired: !!rw.rebootRequired, cbsRebootPending: !!rw.cbsRebootPending, pendingFileRename: !!rw.pendingFileRename,
      uxKeyReadable: q ? sectionChecked(q, "restartWaiting") : false,
    });
  }

  #startupHealth(s) {
    const sh = facts(s, "startupHealth");
    return {
      ...summarizeStartupHealth({
        tasks: sh.tasks || [],
        microsoftTaskSeen: s ? !!control(s, "startupHealth").microsoftTaskSeen : false,
        vbsLogReadable: s ? !!control(s, "startupHealth").vbsLogReadable : false,
        vbsDeprecationCount: sh.vbsDeprecationCount ?? 0,
        vbsStartupEntries: sh.vbsStartupEntries || [],
      }),
      // Window-only detail (a "details toggle"): the raw non-Microsoft task rows this pass
      // looked at. Names never reach the guide - see guideView(), which drops this key.
      tasks: (sh.tasks || []).map((t) => ({ name: t.name, path: t.path, state: t.state, result: decodeLastTaskResult(t.lastTaskResult) })),
    };
  }

  #diskSpace(q) {
    const ds = facts(q, "diskSpace");
    return summarizeDiskSpaceGroup(ds.drives || [], { systemDrivePresent: q ? !!control(q, "diskSpace").systemDrivePresent : false });
  }

  #speedCap() {
    const speedRun = this.worker?.latestDoors?.speed || null;
    const sp = facts(speedRun?.sections || null, "speedCap");
    return summarizeSpeedCap({
      perf: sp.perf || [], util: sp.util || [],
      counterOk: speedRun ? !!control(speedRun.sections, "speedCap").counterReadable : false,
    });
  }

  // ---------------------------------------------------------------------------- assembly
  #rows() {
    const latest = this.worker?.latestDoors || {};
    const q = latest.quick?.sections || null;
    const s = latest.slow?.sections || null;
    const managed = !!(q && (facts(q, "remoteDesktopRegistry").partOfDomain || facts(q, "remoteDesktopRegistry").entraJoined));
    const doors = {
      remoteDesktop: this.#remoteDesktop(q, s),
      extraAccount: this.#extraAccount(q),
      diskEncryption: this.#diskEncryption(q),
      remoteSupport: this.#remoteSupport(q),
      antivirus: this.#antivirus(s),
      leftovers: this.#leftovers(s),
    };
    const power = {
      suddenShutdowns: this.#suddenShutdowns(s),
      batteryAndCharger: this.#batteryAndCharger(q, s),
      sleepTimers: this.#sleepTimers(q),
      restartWaiting: this.#restartWaiting(q),
      startupHealth: this.#startupHealth(s),
      diskSpace: this.#diskSpace(q),
      speedCap: this.#speedCap(),
    };
    return { doors, power, managed, checkedAt: { quick: latest.quick?.at || null, slow: latest.slow?.at || null, speed: latest.speed?.at || null } };
  }

  #summarize(rows) {
    const doorEntries = Object.entries(rows.doors);
    const openIds = doorEntries.filter(([id, r]) => DOOR_OPEN[id]?.(r)).map(([id]) => id);
    const doorsNotCheckedIds = doorEntries.filter(([, r]) => NOT_CHECKED.has(r.verdict)).map(([id]) => id);
    const powerNotCheckedIds = Object.entries(rows.power).filter(([, r]) => NOT_CHECKED.has(r.verdict)).map(([id]) => id);
    const notCheckedIds = [...doorsNotCheckedIds, ...powerNotCheckedIds];
    const shutCount = doorEntries.length - openIds.length - doorsNotCheckedIds.length;
    let headline;
    if (openIds.length) headline = `${openIds.length} door${openIds.length === 1 ? "" : "s"} open`;
    else if (notCheckedIds.length) headline = `Couldn't check ${notCheckedIds.length} thing${notCheckedIds.length === 1 ? "" : "s"}`;
    else headline = "Every door we could check is shut";
    return { openCount: openIds.length, openIds, shutCount, doorsNotCheckedCount: doorsNotCheckedIds.length, notCheckedCount: notCheckedIds.length, notCheckedIds, headline };
  }

  /** Everything the window shows (local only) - raw enough for a details toggle, never a password or a recovery key. */
  view() {
    const rows = this.#rows();
    const summary = this.#summarize(rows);
    return { ...rows, summary, minutesAgo: { quick: minutesAgo(rows.checkedAt.quick), slow: minutesAgo(rows.checkedAt.slow), speed: minutesAgo(rows.checkedAt.speed) } };
  }

  /** What the guide sees: the same verdicts, with every name replaced - the redactor runs on top of this too. */
  guideView() {
    const v = this.view();
    const extraAccount = { ...v.doors.extraAccount, accounts: anonymizeAccounts(v.doors.extraAccount.accounts) };
    const { tasks, ...startupHealthCounts } = v.power.startupHealth; // task names never reach the guide - counts only
    return {
      summary: v.summary, managed: v.managed, minutesAgo: v.minutesAgo,
      doors: { ...v.doors, extraAccount },
      power: { ...v.power, startupHealth: startupHealthCounts },
    };
  }

  async #remember() {
    if (!this.brain) return;
    const v = this.view();
    await this.brain.remember("doors", { at: now(), open: v.summary.openCount, shut: v.summary.shutCount, notChecked: v.summary.doorsNotCheckedCount, openIds: v.summary.openIds });
  }
}
