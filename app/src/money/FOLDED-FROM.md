# Money — where it came from

- **Source:** an internal, private money-out scanner (merchant directory, descriptor
  matcher, statement header handling, and a cancellation runbook format: steps, traps named
  in advance, and "done only when the evidence says so"), folded in at its commit `f10e3fd`
  on 2026-09-19. That product is retired; this is the only copy that ships.
- **What came across:** the statement lane only - the merchant directory (the developer
  services, carried as `category: "developer"`), descriptor matching, the cancel-runbook
  shape, and the product rules: show where the money goes, flag anything still charging
  after a cancellation, give honest refund odds, offer drafts and never send them.
- **What did NOT come across, on purpose:** credential discovery and provider API probes.
  A security app that searches a PC for API keys looks exactly like the malware it hunts.
- **Edits on fold:** rewritten rather than copied. The statement reader became a real
  bank-CSV reader (quoted fields, header or no header, split Debit/Credit columns, per-file
  sign detection, digit masking); matching became word-boundary with longest-pattern-wins;
  a consumer directory of 46 companies was added, each entry citing the vendor pages it came
  from (checked 2026-09-19).
- **Tests:** `app/tests/money.selftest.mjs` (its own suite; it gates the build).
