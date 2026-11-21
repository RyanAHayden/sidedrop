# TODO — open tasks, in order

### Next

### Follow-ups

- [~] **F36** (follow-up, normal) Control session 2 asked the person: "Want me to queue the `/sync` fix as a task?" Carry on from their answer (the session, closed while it waited: https://claude.ai/code/session_012iEtdNSwuoDgUtMGEBjyja) BLOCKED: DECIDE: Want me to queue the `/sync` fix as a task? https://claude.ai/code/session_012iEtdNSwuoDgUtMGEBjyja (asked 2026-11-20 20:07)
- [ ] **R2** (follow-up, normal) Check B23's group fix on apps.hayde.in after the merge: deploy.sh's cron redeployed main (ssh truenas_admin@truenas-scale; docker exec into the sidedrop container: /app/native/groupfix/sidedrop-groupfix.dylib exists), and a signed IPA there for an app with original app groups (e.g. RyukGram) holds Payload/*.app/sidedrop-groupfix.dylib and sidedrop-groupfix.plist with keychain-access-groups [TEAM.<its bundle ID>, TEAM.com.ryha.sideload]. If the App ID's capabilities changed, regenerate the profile via docker exec. | files: journal/** | after: B23
- [~] **F32** (follow-up, low) Register step screenshots: capture Settings' Profile Downloaded row (under the name) and the Install Profile sheet with Install top-right, on a current-iOS iPhone, as static/reg1.jpg/reg2.jpg, and show them under the register steps and Help's Register iPhone Didn't Work like sdp1-3 (R1 changed the wording only) | files: app.py, static/**, test_app.py BLOCKED: shelved: BLOCKED: send two screenshots from your iOS 26/27 iPhone — Settings with the Profile Downloaded row under your name, and the Install Profile sheet (Install top-right) — and drop them in static/ as reg1.png/reg2.png; then crop, circle and wire them in like sdp1-3 (journal/2026-11-20-f32-register-shots)
### Parked
- [ ] **F28** (follow-up, later) F26 follow-up: the concept says Stolen Device Protection is 'only under Register iPhone Didn't Work now'. F26 took it out of the first-install sheet and Settings, but the Apps tab's unregistered setup still has it as step 1 ('Set up this iPhone: 2 steps', #sdp, sdpDone). Ask the user whether that step goes too (then setup is just Register). | files: app.py, test_app.py
