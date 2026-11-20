# TODO — open tasks, in order

### Next

- [ ] **F31** A user invited with a link must not have to set or type a password: the link is their access. Opening an invite link signs them in (and keeps them signed in) with no password step. Keep the admin login as is. Check: open a fresh invite link in a clean session; you get in and through setup without any password prompt; an invalid/used-up link still refuses.
- [ ] **F30** Any setup/invite link a user is given should open straight into setting up their device, not the homepage. Check: open each kind of setup link in a fresh browser session; it lands on the device setup flow's first step.
- [ ] **F29** Settings layout fixes: (1) under the Manage row, bring back the Share page row, admins only; (2) remove the hint text there; (3) the section title that says This iPhone makes no sense: the admin section gets a group title like Admin Settings instead; (4) Theme and the other personal options go in their own group with a fitting title; (5) the page can be scrolled/overscrolled too far above its top, stop that. Check: as admin, Settings shows Admin Settings with Manage then Share; as a user no Share row; theme in its own group; no gap above the top when dragging down.
- [ ] **B5** Buttons like Copy Link (and the other plain action buttons) have no pressed look while held. Give them iFizBox's depressed hold state (its *Pressed art/styles), in light and dark themes. Check: hold each button on the phone or in the browser with :active; it darkens/insets like iFizBox's.
### Follow-ups

- [ ] **F32** (follow-up, low) Register step screenshots: capture Settings' Profile Downloaded row (under the name) and the Install Profile sheet with Install top-right, on a current-iOS iPhone, as static/reg1.jpg/reg2.jpg, and show them under the register steps and Help's Register iPhone Didn't Work like sdp1-3 (R1 changed the wording only) | files: app.py, static/**, test_app.py
### Parked
- [ ] **F28** (follow-up, later) F26 follow-up: the concept says Stolen Device Protection is 'only under Register iPhone Didn't Work now'. F26 took it out of the first-install sheet and Settings, but the Apps tab's unregistered setup still has it as step 1 ('Set up this iPhone: 2 steps', #sdp, sdpDone). Ask the user whether that step goes too (then setup is just Register). | files: app.py, test_app.py
