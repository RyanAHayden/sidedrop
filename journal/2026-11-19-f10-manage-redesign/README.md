# F10: Manage redesign

I couldn't open the approved mockup (no Artifact tool in this run), so this follows the task text.

## What I did

- **Manage menu** (`/admin`, `manage_menu`): two grouped tables of rows with iFizBox's 29pt row icons.
  - iPhones (device): a count.
  - Signing (syncCert): the expiry date.
  - Passwords (signInKey).
  - Files for Friends (fromFile): a count.
  - App Sources (sources): a count.
  - iFizBox (general).

  The menu makes no Apple call:
  - The iPhone count comes from the saved device list. Before the first fetch it comes from the profile.
  - The expiry is read from cert.p12.
  - The banner comes from `cert_status_cached()`. That returns cert_status's last answer at any age, or only the local checks before the first answer. A stale or missing answer is refreshed in a background thread (`cert_bg["t"]`).

  The banner shows the first problem (errors first) and "And N more on Signing.", and links to Signing. Each row is `data-push`.
- **Row icons**: `ROW_ICONS` / `tile_svg` / `row_icon` are a Python copy of `~/repos/iFizBox/web/app/icons/rowicons.js`'s tileSvg, colours and glyph paths for these six icons, with gear() ported. They are inlined as data: URIs, so nothing is loaded from iFizBox.
- **Nested pushes** (home page JS):
  - Before this change, a pushed page couldn't push another (`if(L)return`). Pushed pages are now a stack (`LS`, with `L` the top one), so Settings → Manage → iPhones → an iPhone slides like UIKit.
  - Each new page's back button carries the title of the page under it.
  - popstate pops down to the page that matches the history entry.
  - `fill()` re-creates `<script>`s in a pushed page so they run. The iPhones page needs this for its refresh.
- **iPhones** (`/admin/iphones`):
  - It shows the saved list (`DATA/devices.json`, Apple's last `/devices` answer) at once, under a "Loading from Apple…" row.
  - Its script fetches `/admin/devices.json`. That endpoint asks Apple, saves the answer, and returns `{ok, error, devices, html}`. The returned HTML replaces the list. If Apple fails, the answer is the saved list plus a "didn't answer" note.
  - Each iPhone has an ON/OFF switch. It posts `/admin/device` with `json=1`, after a confirm when turning one off. There is no Delete.
  - `/admin/device` now does only the PATCH while the request waits. It then updates the saved list and runs `resign_all` (new profile and re-sign) in a background thread. Before, it held the request for the whole re-sign.
  - Turned-off iPhones are in a "Disabled" group. The footer reads "N of 100 slots used. Disabled iPhones still count until your membership renews."
- **iPhone details** (`/admin/iphone/<id>`): model, added, last used, status and UDID, all from the saved list. Rename sends PATCH `/v1/devices/<id>` with `name` (1–50 characters, whitespace collapsed) and updates the saved list.
- **Signing** (`/admin/signing`, GET added beside the existing POST):
  - All problems.
  - Certificate group (type, expiry, team, App ID, read from cert.p12), with Make New Certificate and the revoke picker under it.
  - API Key group: file `AuthKey_<KeyID>.p8` and role. Role shows "Admin" once the key has made a certificate (`make_certificate` sets `asc_role`), "Not Admin" after Apple's Admin-role 403, and "Not checked yet" otherwise. A newly uploaded key clears it. Below the group is the Choose API Key form.
  - Manual → "Upload cert.p12 Instead" (a `<details>`) holds today's manual form. It opens by itself when an upload fails.
- **Passwords** (`/admin/passwords`): change the friends' password, the admin password, or both. Rules: at least 8 characters, not the default, not equal to each other or to the other current password. They are saved hashed in setup.json. A password set in .env isn't shown, and when both are set there the page says so.
- **Files / App Sources / iFizBox** (`/admin/files`, `/admin/sources`, `/admin/ifizbox`): today's forms. The config POST redirects back to the page the file belongs to and shows its errors there.
- Redirects moved from `/admin?done=…` to each page's own URL.
- `test_app.py`:
  - The menu returns in under 1s with ASC hanging (a stub blocked on an Event) or raising. It has six row icons and the six push links.
  - The iPhones page with nothing saved shows only the loading row.
  - The JSON refresh with Apple down, then up. The list is saved, and the next page shows it at once with Apple down. The menu count comes from the saved list.
  - Details page.
  - The JSON switch: Disabled group, saved status, background re-sign, the no-JS redirect, and a 502 with the status left unchanged when Apple fails.
  - Rename: the exact PATCH body, the validation, and Apple failing.
  - Every Manage page redirects a non-admin, and the JSON answers 403.
  - Banner: local checks at once, Apple's after the background check, errors first.
  - Signing shows the certificate fields, key file and role.
  - Passwords: all the rules, changing one or both, hashed storage, and the `.env` case.
  - Earlier tests were moved to the new URLs.
- Screenshots: `1-manage` … `9-ifizbox`, light and dark, 390pt at 2x in headless Chromium (`/usr/bin/chromium`). The script is `shots.py`. Flask's test client answered Chromium's requests, with ASC stubbed. The app was driven by clicks from Settings, so they show the nested pushes. `2-iphones-loading` was taken while the JSON request was held, and `3-iphones` after Apple's answer, which brought a disabled iPhone. The script checks the stack reaches 3 layers and pops back to 1.

## Tried that failed

- `opacity="{{ … i * .07 }}"`: Jinja doesn't accept `.07`, so it's `0.07` now.
- The first menu put every certificate problem in the banner (three long red paragraphs on top). It now shows the first problem and a count.
- The first screenshot run let the app's background source sync reach the real sources on the internet. It was read-only, but the script now stops it, as test_app.py does.

## Not verified

- **On an iPhone**: no device in this unattended run. Not checked in iOS Safari or the Home Screen app:
  - the nested push slide, and the edge swipe across two levels
  - `confirm()`/`alert()` inside a pushed page
  - the switch look
- **Dragging the iPhones switches**: the drag code in PAGE binds `.sw` only at DOMContentLoaded. Switches that arrive in a pushed page or through the JSON refresh toggle by tap but don't follow a drag. I didn't change PAGE's switch code.
- **Against Apple**: these are from Apple's API docs, not observed:
  - PATCH `/v1/devices/{id}` with `name`
  - Apple's name length limit (I used 50)
  - how long `/devices` takes on a big account
- **Admin sessions after an admin password change** stay signed in, as friends' sessions do after a friends' password change. Nothing revokes them.
- The switch CSS is repeated in `MANAGE_CSS`, so Manage's pages also work when opened on their own (a reload). The Settings tab's copy is untouched.
- The pressed highlight on an iPhone row's name area: `PRESS` matches `.g a.row`, and the device rows are a `div` holding a link and a switch, so they get no held-blue.
