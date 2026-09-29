# Doors & power — where it came from

- **Source:** the estate's own private box-audit workflow (`box-audit` skill and its
  `workflow.js`) - a read-only diagnosis tool for the estate's own machines, covering crash
  vs. power classification, battery and charger health, sleep timers, disk and task-scheduler
  health, and a break-in sweep (extra admin accounts, Remote Desktop, disk encryption,
  remote-support tools, antivirus). That tool stays private and estate-only; this is a
  rewrite of its consumer-relevant half, not a copy of any of its code or output.
- **What came across:** the six lenses a person recovering from an incident needs -
  Remote Desktop, an account that may have no password, disk encryption, remote-support
  programs, antivirus, and leftovers not yet scanned (the "doors") - and why the PC keeps
  losing power: sudden shutdowns classed power-loss / crash / can't-tell, battery health and
  charger flicker counted as episodes, the sleep timers (including the hidden lock-screen
  timer), a restart waiting, disk space, and an opt-in speed check (the "power" half).
- **What did NOT come across, on purpose:** the ssh / remote-exec lens; the estate's own
  fleet peer-tracking lenses; its wider governance tooling and its own task-name filters;
  vendor-specific BIOS/thermal reads; the recursive disk walk; a `.vbs` file's contents (only
  its presence in Startup is read, never opened); and every fact measured from any one
  machine during that tool's own use. A security app that reads another machine's file
  contents, or that filters by names only the estate would recognise, looks exactly like the
  malware Hideout hunts.
- **Edits on fold:** rewritten rather than copied, and corrected against a live, read-only
  probe rather than assumed from documentation: raw facts only (`doors.ps1`), every verdict in
  JS (`summarize.mjs` / `decode.mjs`), a two-pass split (quick / slow) instead of one always-on
  check, disk encryption read without admin through the same property Windows Explorer uses
  for its own padlock icon, and an admin snapshot Section that is shaped (`Select-Object`) so
  a BitLocker recovery key can never land in it. `pc.mjs`'s remote-tool table gained a
  `processes` column, because a product's name and the name of the process it runs as often
  differ.
- **The one rule that carries over unchanged, from OUTFLOW-into-Money before it:** help,
  never take over. Hideout only ever looks - it shows the exact step and the undo, and the
  person clicks, at their own keyboard, approving their own Windows prompt.
- **Tests:** `app/tests/doors.selftest.mjs` (its own suite; it gates the build).
