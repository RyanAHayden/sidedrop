# TODO — open tasks, in order

### Next

### Follow-ups

- [ ] **B3** (follow-up, low) Dark themes: an armed green INSTALL (.get.go) has grey text, because '.dark .get{color:var(--getc);border-color:...}' (app.py ~1041) comes after '.get.go{color:#fff;border-color:#2f7a17}' with the same specificity. Give .dark .get.go white text and the green border (F25 did it only for Home's iFizBox card, .dark .ifzr .get.go). | files: app.py, test_app.py
- [ ] **B4** (follow-up, low) Main page's pageshow handler calls themeMarks(), which only exists after Settings > Theme was pushed (THEME_JS): every main-page load logs 'themeMarks is not defined' (seen in F26's headless check). Guard it (window.themeMarks&&themeMarks()) or define a main-page one. | files: app.py

### Parked
- [ ] **F28** (follow-up, later) F26 follow-up: the concept says Stolen Device Protection is 'only under Register iPhone Didn't Work now'. F26 took it out of the first-install sheet and Settings, but the Apps tab's unregistered setup still has it as step 1 ('Set up this iPhone: 2 steps', #sdp, sdpDone). Ask the user whether that step goes too (then setup is just Register). | files: app.py, test_app.py
