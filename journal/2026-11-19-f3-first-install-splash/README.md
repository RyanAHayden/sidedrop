# F3 First-install splash: Stolen Device Protection and Developer Mode, once per iPhone

## What I did
- `app.py`: a full-screen sheet (`#firstRun`, class `.fl`), "Before You Install", that slides up like the install page. It has
  step 1, turn off Stolen Device Protection (the existing `sdp_steps`), and step 2, turn on Developer Mode. The Developer Mode
  screenshots moved into a `dev_steps` block that Settings → Help now uses too, so there is one copy.
- A capture-phase click listener catches the first tap on any install trigger (`a[href^="itms-services:"]` or iFizBox's `#ifzb`)
  while the sheet is due. It holds the tap and shows the sheet. **Install** / **Got It, Install** posts `/first-run`, then replays
  the held tap (an unarmed GET is armed first, so the replay installs instead of only turning green). **Cancel** keeps the sheet
  for the next tap.
- Per device, on the server: `first_run.json` `{udid: time}`, keyed on the device cookie's UDID. The sheet is rendered only for a
  registered phone that isn't in that file, so Safari and the Home Screen app (each with its own storage) show it once between them.
  Rendered without a cookie or for an unregistered phone: no sheet (those phones can't install anyway).
- Going through the sheet also sets `localStorage.devTold`, so the existing "Developer Mode Required" alert doesn't repeat after
  the install. The notifications ask still follows as before.
- `test_app.py`: the first page has the sheet (hidden, due, with the sdp and dev screenshots, and the listener covers every install link).
  `/first-run` is 403 without login or cookie. After it, the page has no sheet, keeps the Help copy and still has the itms links.
  A second browser for the same phone (`fresh`) doesn't get it either.

## Decisions (unattended)
- Splash on the first **GET** tap, not on the second (armed INSTALL) tap: GET is where the user first "taps an app to install".
  Continuing goes straight to iOS's prompt, so a second tap isn't needed.
- Remembered on the server, not in localStorage: "per device" means across Safari and the Home Screen app too.
- Updates started with Changes → Update (n) (`upgradeGo`, which sets location.href) skip the sheet. Those apps are already installed.

## Checked
- Gate passes.
- The page's rendered scripts pass `node --check`.
- Headless Chromium screenshot of the sheet (390 px wide): both cards, screenshots and the green button lay out as intended.
- Headless Chromium click probe on the rendered page: tap 1 shows the sheet and doesn't arm; Install hides it, clears due, posts
  `/first-run` and fires one itms-services navigation; tap 2 just arms as before.

## Not verified
- On a real iPhone: that Safari accepts the replayed `a.click()` on an itms-services link from the sheet's button tap as a user
  gesture and shows the install prompt. The test phone wasn't used: unattended run, and no deployed build with this change.
- Dark mode look of the sheet: only light mode was screenshotted.
