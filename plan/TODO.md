# TODO — open tasks, in order

### Next

- [ ] **B18** Apps row 'Mark as Installed' hold sheet (mkItems, ~app.py:1449, F27 /installed route ~1574) doesn't look like the iFizBox action sheet, and on choosing it vanishes at once instead of sliding down. Match iFizBox's sheet look (use the same UIKit-art action sheet styling iFizBox uses) and run the slide-away animation before removing it. Check: test_app.py covers the markup/class; screenshot open and dismiss on a 375px iPhone. | files: app.py, test_app.py
### Follow-ups

- [~] **F34** (follow-up, normal) Control session 4 asked the person: "Want me to add that to the run's queue?" Carry on from their answer (the session, closed while it waited: https://claude.ai/code/session_012iEtdP3dUvBtpKQviukSVv) BLOCKED: DECIDE: Want me to add that to the run's queue? https://claude.ai/code/session_012iEtdP3dUvBtpKQviukSVv (asked 2026-11-20 14:37)
- [~] **F32** (follow-up, low) Register step screenshots: capture Settings' Profile Downloaded row (under the name) and the Install Profile sheet with Install top-right, on a current-iOS iPhone, as static/reg1.jpg/reg2.jpg, and show them under the register steps and Help's Register iPhone Didn't Work like sdp1-3 (R1 changed the wording only) | files: app.py, static/**, test_app.py BLOCKED: shelved: BLOCKED: send two screenshots from your iOS 26/27 iPhone — Settings with the Profile Downloaded row under your name, and the Install Profile sheet (Install top-right) — and drop them in static/ as reg1.png/reg2.png; then crop, circle and wire them in like sdp1-3 (journal/2026-11-20-f32-register-shots)
### Parked
- [ ] **F28** (follow-up, later) F26 follow-up: the concept says Stolen Device Protection is 'only under Register iPhone Didn't Work now'. F26 took it out of the first-install sheet and Settings, but the Apps tab's unregistered setup still has it as step 1 ('Set up this iPhone: 2 steps', #sdp, sdpDone). Ask the user whether that step goes too (then setup is just Register). | files: app.py, test_app.py
