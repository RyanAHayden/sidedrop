# F26: Settings rewrite to the user's concept

## What changed (app.py)

**Settings tab**: grouped iOS 6 rows, each with its 29pt icon and a footer under its group (`.sg`, the detail `.val` on the right):

1. **This iPhone** (`#sThis`): Status (Registered / Not registered; when not registered the row is a link that runs `nudge()` on Apps),
   Apps Work Until (the profile's expiry, when there is one). Footer "Every app on the Apps tab can install on this iPhone." (unregistered:
   "Register this iPhone on the Apps tab, then every app there can install on it."). "iPhones used" is gone (Manage > iPhones has it).
2. **Manage** (`#sManage`, only when `is_admin()`): orange person icon (`ROW_ICONS["manage"]`, the old tile's glyph), detail "N iPhones"
   (`manage_iphone_count()`: the saved device list, else the profile; the same count Manage used). Footer "Only you see this: you run this
   SideDrop." Replaces the Manage/Register tile pair.
3. **Theme** (detail: the theme showing now, `#themeV`, kept current by a small `themeVal()` on load, popstate, pageshow and the phone's
   appearance change; the server draws "Classic") and **Update Alerts** with its switch; footer as before.
4. **Add to Home Screen** pushes `/home-screen` (its steps). Footer "Open SideDrop from your Home Screen like an app."
5. **Help** pushes `/help`.
6. **Sign Out** (capitalised as the concept), then the version line.

No iFizBox row, no About: the About alert, the nav bar's About button (the slot is an empty `<span>`), and the About tiles on Settings
and on the Apps header are gone. The Apps header's Help tile now spans its row (`.hw:has(>:only-child)`) and calls `helpOpen()`. The
version line stays at the bottom of Apps and Settings, and I added it to the sign-in page (it was only in About there; a test checks it).

**Help page** (`/help`, back "Settings"): Problems: Register iPhone Didn't Work (the three steps from the brief, then the SDP screenshots),
An App Won't Install (my wording: check Registered, register again, delete a stuck grey icon, Developer Mode below), Turn on Developer Mode
(today's steps for everyone, since F23 is on hold), then the old Help footer. Getting Started: Add to Home Screen, Notifications in Apps,
More Apps with iFizBox (the old "for your own IPAs… use iFizBox" line moved here). Every item is a `<details>`. `helpOpen(id)` pushes Help
from anywhere (Settings tab, then push over any open layer) and opens that item; the Developer Mode alert's **Show Me** uses it. On its
own (a reload of `/help#dev`), a small script opens the item named in the hash. `HELP_CSS` copies `.num/.shot/.warn` for that standalone case.

The step snippets (`sdp_steps`, `dev_steps`, and a new `a2hs_steps`) moved from `{% set %}` blocks in the home template to Python
constants (`SDP_STEPS`, …) registered as Jinja globals, so the Help page shares them.

**First-install sheet**: Stolen Device Protection is out; it's only Developer Mode now ("One setting, once per iPhone…").

**Manage** (`/admin`): banner on top: green `cw ok` "Signing works: <cert kind>, App ID <BUNDLE_ID> with Push" when there are no problems
(" with Push" only when the profile has `aps-environment`), else today's warning banner. Groups: Friends (iPhones "N of 100", Invite
Friends, Passwords), Signing (Certificate: subtitle kind + holder/team, detail expiry; Profile: "Ad Hoc · Push · N capabilities", detail
"N iPhones", from `profile_info()`; both open `/admin/signing`), Apps (App Sources, Files for Friends, iFizBox with the version served,
`ifizbox_served()`, else "Not yet"), each with the brief's footer. Routes unchanged. "Capabilities" counts the profile's entitlements
besides application-identifier, team-identifier, keychain-access-groups, get-task-allow and beta-reports-active: my reading of "N capabilities".

docs/configuration.md: Manage's banner and groups.

## Tests (test_app.py)

New: Settings' groups in order (`sThis, sTheme, sHome, sHelp`; the admin's with `sManage` second), each label and footer in order up to
Sign Out and the version line; no iFizBox/About/iPhones used/SDP/tiles in Settings; Manage row only for the admin (friend: absent);
`/help` and `/home-screen` route (back Settings; 302 signed out), Help's groups and six items in order, SDP only under Register iPhone
Didn't Work; Manage's groups, rows, counts ("1 of 100", "1 iPhone"), footers; the green banner with and without Push in the profile.
Updated old asserts that encoded About, the old Settings order, the version line counted 3 times, SDP in the first-install sheet, and
Manage's old flat menu (7 icons → 8, the bare iPhones count). Gate passes.

## Checked in a browser

`shots.py` (readme_shots' demo data, headless Chromium, 375pt) wrote `after/`: Settings (admin, friend), Help, Add to Home Screen, Manage
in Classic and OLED Black, a pushed Help, Show Me, the Apps header. Its checks printed: Theme detail Classic / OLED Black; Help pushed
with back "Settings", back pops to 0 layers; Show Me → Settings tab, Help, `#dev` open; after picking Sepia in Theme > Light and going
back twice the row says Sepia; the Apps header's Help tile pushes Help; a friend has no Manage row.

It also showed `themeMarks is not defined` on every main-page load: F20's pageshow handler, already there before F26. Filed as **B4** (low).

## Tried and failed

Nothing major. The first test run tripped on my own CSS comment containing "About" (the page must have none); reworded.

## Follow-ups filed

- **B4** (low): the themeMarks pageshow error above.
- **F28** (later): the brief says SDP is "only under Register iPhone Didn't Work now". I took it out of the first-install sheet and
  Settings but left the Apps tab's unregistered setup step 1 (SDP, then Register), since that's the Apps tab, not Settings, and dropping
  it changes the setup flow. F28 asks the user.

## Not verified

- **A real iPhone / Safari**: headless Chromium only, no phone in this unattended run (push slide, edge-swipe back over Help, the
  Help tile from the Home Screen app).
- **Manage's green banner with "with Push" on screen**: the demo profile has no entitlements, so the shot shows it without Push and
  "0 capabilities"; the Push wording is covered by the gate's assert, not a screenshot.
- **The unregistered Settings** (Status as a link to the setup) was not shot; the template and `nudge()` are unchanged otherwise.
- **Widths other than 375pt** were not shot (e.g. the Certificate subtitle ellipsis at 320pt).
