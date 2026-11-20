# C2 SideDrop stops tracking installs and offering updates

## What I did
- **Server (`app.py`).** Removed `INSTALLED`/`installed()` (data/installed.json), the `/installed` beacon route, the F27 hold sheet's
  `/installed/mark` route and its `mark_csrf`. Also removed web push, which only existed for Update Alerts: `PUSH`, `VAPID`,
  `vapid_public`, `pending`, `signed_versions`, `notify_upgrades`, `/push`, `/sw.js`, and the `pywebpush` import plus its line in
  `requirements.txt` (the `ec` import went too; nothing else used it). `resign_and_notify` is now `resign_logged` (it only signs).
  `/check` and the hourly `sync_loop` still sync and sign. They just don't notify. The lock that guarded installed.json also covered
  seen.json and first_run.json, so it's now `seen_lock`, used only for those two.
- **Apps page.** Every row's button is GET (arming to a green INSTALL, a second tap installs, as before). A row with files has a
  GET button that unfolds its steps. The iFizBox card is always the green INSTALL. Removed: the `mine`/`vkey`/`updates` template
  data, INSTALLED/UPDATE/REINSTALL labels, `.done`/`.upd` button styles, the `.row.up` red icon badge and "Update available" note,
  the Apps tab's count badge (`.badge`, `.badge.busy` spinner and `navR`), the hold sheet's markup, CSS (`.mks`/`.mkp`/`.mkd`, `.held`,
  `.mkc` in the B5 `:where`) and JS (`mkState`, `mkItems`, `mkOpen`, `mkClose`, `mkDo` and the pointer handlers), and `mark()`.
  Nothing else used the action-sheet CSS, so it's all gone. An install tap still brings the one-time Developer Mode alert through a
  small `tapped()`. The page-load `checkNow()` still runs; it no longer spins a badge.
- **Settings/Help.** Removed the Update Alerts switch and its footer, the "Get Notified of Updates?" alert and all `push*` JS. Removed
  the Help sentence and the Add to Home Screen footer clause about Update Alerts. The Theme preview's sample buttons show DOWNLOAD
  (the blue file button) instead of UPDATE, and its badge is gone.
- **README.** The Apps bullet no longer promises update rows, a badge or alerts. The screenshot's alt text changed with it. The image
  `docs/img/apps.png` itself is not regenerated.
- **Tests (`test_app.py`).** Removed the F22/F24 update-row tests, the F27/B18 hold-sheet tests (routes, CSRF, node checks of
  `mkItems`/`mkClose`), the iFizBox card's INSTALLED/mark checks and the web push test. Added a C2 block. The old routes are 404
  (`/installed`, `/installed/mark`, `/push`, `/sw.js`), and the removed names are gone from the module. Rows show GET
  (link and steps button), and none of UPDATE/INSTALLED/badge/sheet/push strings are on the page. The Apps tab has no count. A node
  check shows GET arming to INSTALL and installing on the second tap. The Settings test now checks that Update Alerts is absent.
- **Decision (no one to ask):** "Every Apps row just offers Install" I read as one uniform state, keeping the App Store GET → INSTALL
  arm that rows had before (B17's test still expects `data-arm=GET`), not as relabelling GET to INSTALL.
- **Kept on purpose:** iFizBox's own copy ("Recommended: get update alerts…", "Updates in one tap") describes the iFizBox app, which
  does its own updates on the phone; it is not SideDrop tracking anything. The install page's `INSTALLS`/`/install/<t>` progress
  poll stays: it follows one iFizBox install in progress and records nothing about the phone.
- **Screenshots** (`shots.py`, Chromium 375×667): `apps-light.png`, `apps-dark.png` (iFizBox INSTALL, three GET rows, no badge),
  `apps-armed.png` (one GET tapped → INSTALL), `apps-after-press.png` (after a 1 s press on a row: no dialog, no held row). There were no
  page errors.

## Tried and failed
- My first `git worktree add … main`, to compare the gate's stderr with main, failed because main is checked out in the main
  checkout. `--detach` worked, and I removed the worktree afterwards. On main the gate prints the same 3 `KeyError: 'Entitlements'`
  tracebacks as on this branch, so they come from existing tests and C2 didn't add them.

## Not verified
- On an iPhone: that an install tap still opens iOS's prompt and the Developer Mode alert after the button changes. No iPhone could be
  reached from this unattended run. Chromium shows the arming, and the node test covers `arm()`.
- Existing deployments keep stale `installed.json`, `push.json` and `vapid.pem` in their data folder. Nothing reads them any more. I
  left them alone: deleting user data on start wasn't asked for. Home Screen apps that subscribed to push keep a registered
  service worker whose `/sw.js` now 404s. Browsers keep the old copy until an update check fails, and no pushes are sent. Nothing
  here could check this on a real device.
- `docs/img/apps.png` in the README still shows the old UPDATE row and badge. Regenerating it needs the docs shot setup, which is
  outside this task's files.
