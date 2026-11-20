# TODO — open tasks, in order

### Next

- [~] **F23** (follow-up, critical) Developer Mode only when it's needed (user 2026-11-19): Apple requires it for apps signed with a development profile (get-task-allow true), not for Ad Hoc or Enterprise. SideDrop signs with an Ad Hoc profile now, so: read the served profile's kind (ProvisionedDevices + get-task-allow false = Ad Hoc; ProvisionsAllDevices = Enterprise; get-task-allow true = Development) and show the Developer Mode parts (the first-install sheet's Developer Mode step, Help's 'Turn on Developer Mode', iFizBox's 'It needs Developer Mode, like every app here' footer, docs) only for a Development profile. Stolen Device Protection: SideDrop can't detect it; keep its help, but in the first-install sheet show it as 'if Register iPhone fails' rather than a step everyone must do (read the current text first). Fix the docstring at app_entitlements that says a wildcard can 'demand Developer Mode' only if it's still accurate. Tests: the page with an Ad Hoc profile has no Developer Mode step; with a development profile it does. Note in the journal that the Ad Hoc rule is Apple's documented behaviour and the user's hand check (an iPhone with Developer Mode off installing a SideDrop app) confirms it (iFizBox R task). | files: app.py, test_app.py, static/**, README.md, docs/**, journal/** | after: F22 BLOCKED: HOLD: the user's iPhone 18 Pro (iOS 27) asked for Developer Mode opening SideDrop's iFizBox, which is Ad Hoc with get-task-allow false in every binary (checked 2026-11-19). So 'Ad Hoc needs no Developer Mode' may not hold on iOS 27: don't remove the step until iFizBox's R40 settles it.

### Follow-ups

- [ ] **B3** (follow-up, low) Dark themes: an armed green INSTALL (.get.go) has grey text, because '.dark .get{color:var(--getc);border-color:...}' (app.py ~1041) comes after '.get.go{color:#fff;border-color:#2f7a17}' with the same specificity. Give .dark .get.go white text and the green border (F25 did it only for Home's iFizBox card, .dark .ifzr .get.go). | files: app.py, test_app.py

### Parked
