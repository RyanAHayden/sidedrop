# TODO — open tasks, in order

### Next

### Follow-ups

- [ ] **T1** (follow-up, normal) docs/readme_shots.py breaks after C2: it writes A.INSTALLED (gone), scrolls to '#t-apps .row.up' (gone) and captions apps.png 'your apps and their updates'; drop the installed seed, the update scroll and the pushAsked init script, recaption, and regenerate docs/img/apps.png (still shows an UPDATE row and badge) | files: docs/readme_shots.py, docs/img/apps.png, docs/img/** | after: C2
- [~] **F32** (follow-up, low) Register step screenshots: capture Settings' Profile Downloaded row (under the name) and the Install Profile sheet with Install top-right, on a current-iOS iPhone, as static/reg1.jpg/reg2.jpg, and show them under the register steps and Help's Register iPhone Didn't Work like sdp1-3 (R1 changed the wording only) | files: app.py, static/**, test_app.py BLOCKED: shelved: BLOCKED: send two screenshots from your iOS 26/27 iPhone — Settings with the Profile Downloaded row under your name, and the Install Profile sheet (Install top-right) — and drop them in static/ as reg1.png/reg2.png; then crop, circle and wire them in like sdp1-3 (journal/2026-11-20-f32-register-shots)
### Parked
- [ ] **F28** (follow-up, later) F26 follow-up: the concept says Stolen Device Protection is 'only under Register iPhone Didn't Work now'. F26 took it out of the first-install sheet and Settings, but the Apps tab's unregistered setup still has it as step 1 ('Set up this iPhone: 2 steps', #sdp, sdpDone). Ask the user whether that step goes too (then setup is just Register). | files: app.py, test_app.py
