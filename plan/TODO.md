# TODO — open tasks, in order

### Next

- [ ] **F23** (follow-up, critical) Developer Mode only when it's needed (user 2026-11-19): Apple requires it for apps signed with a development profile (get-task-allow true), not for Ad Hoc or Enterprise. SideDrop signs with an Ad Hoc profile now, so: read the served profile's kind (ProvisionedDevices + get-task-allow false = Ad Hoc; ProvisionsAllDevices = Enterprise; get-task-allow true = Development) and show the Developer Mode parts (the first-install sheet's Developer Mode step, Help's 'Turn on Developer Mode', iFizBox's 'It needs Developer Mode, like every app here' footer, docs) only for a Development profile. Stolen Device Protection: SideDrop can't detect it; keep its help, but in the first-install sheet show it as 'if Register iPhone fails' rather than a step everyone must do (read the current text first). Fix the docstring at app_entitlements that says a wildcard can 'demand Developer Mode' only if it's still accurate. Tests: the page with an Ad Hoc profile has no Developer Mode step; with a development profile it does. Note in the journal that the Ad Hoc rule is Apple's documented behaviour and the user's hand check (an iPhone with Developer Mode off installing a SideDrop app) confirms it (iFizBox R task). | files: app.py, test_app.py, static/**, README.md, docs/**, journal/** | after: F22 — the user's test answered it: keep the step, explain it

### Follow-ups

- [ ] **B3** (follow-up, low) Dark themes: an armed green INSTALL (.get.go) has grey text, because '.dark .get{color:var(--getc);border-color:...}' (app.py ~1041) comes after '.get.go{color:#fff;border-color:#2f7a17}' with the same specificity. Give .dark .get.go white text and the green border (F25 did it only for Home's iFizBox card, .dark .ifzr .get.go). | files: app.py, test_app.py
- [ ] **B4** (follow-up, low) Main page's pageshow handler calls themeMarks(), which only exists after Settings > Theme was pushed (THEME_JS): every main-page load logs 'themeMarks is not defined' (seen in F26's headless check). Guard it (window.themeMarks&&themeMarks()) or define a main-page one. | files: app.py

### Parked
- [ ] **F28** (follow-up, later) F26 follow-up: the concept says Stolen Device Protection is 'only under Register iPhone Didn't Work now'. F26 took it out of the first-install sheet and Settings, but the Apps tab's unregistered setup still has it as step 1 ('Set up this iPhone: 2 steps', #sdp, sdpDone). Ask the user whether that step goes too (then setup is just Register). | files: app.py, test_app.py
