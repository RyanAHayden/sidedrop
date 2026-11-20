# TODO — open tasks, in order

### Next

- [ ] **B10** One of the invite links has no link-preview embed when pasted in a chat (the other does). Compare what a preview crawler (no cookies, e.g. Discordbot/facebookexternalhit/iMessage UA) gets from /join/<tok> and /invite/<tok>, including the redirect target and error pages, and make both serve the og: tags (base page meta around app.py:711) without signing the crawler in or using up the invite. Check: test_app.py fetches both links with a crawler UA and finds og:title/og:image. | files: app.py, test_app.py
### Follow-ups

- [~] **F32** (follow-up, low) Register step screenshots: capture Settings' Profile Downloaded row (under the name) and the Install Profile sheet with Install top-right, on a current-iOS iPhone, as static/reg1.jpg/reg2.jpg, and show them under the register steps and Help's Register iPhone Didn't Work like sdp1-3 (R1 changed the wording only) | files: app.py, static/**, test_app.py BLOCKED: shelved: BLOCKED: send two screenshots from your iOS 26/27 iPhone — Settings with the Profile Downloaded row under your name, and the Install Profile sheet (Install top-right) — and drop them in static/ as reg1.png/reg2.png; then crop, circle and wire them in like sdp1-3 (journal/2026-11-20-f32-register-shots)
- [ ] **B14** (follow-up, low) A Home Screen app added before the iPhone registered through a one-iPhone invite has no device cookie in its jar: once that invite is revoked (or replaced) it is stuck on 'This invite link doesn't work any more' with no way to identify the iPhone; offer Install Profile there (like B7's INVITE_AGAIN) so the UDID finds the invite that holds it | files: app.py, test_app.py
### Parked
- [ ] **F28** (follow-up, later) F26 follow-up: the concept says Stolen Device Protection is 'only under Register iPhone Didn't Work now'. F26 took it out of the first-install sheet and Settings, but the Apps tab's unregistered setup still has it as step 1 ('Set up this iPhone: 2 steps', #sdp, sdpDone). Ask the user whether that step goes too (then setup is just Register). | files: app.py, test_app.py
