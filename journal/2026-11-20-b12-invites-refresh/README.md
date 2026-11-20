# B12: Invite Friends refreshes on its own

When an iPhone registered through a One-iPhone invite, Manage → Invite Friends kept showing 'Not used' until the admin opened the
page again. Pushed pages never got refreshed: B8's Reload (`reloadData` → `refreshIn`) swaps only the tab lists from `/`.

## What changed (app.py)
- The one-iPhone rows moved out of `INVITES_PAGE` into `INVITE_ROWS`, unchanged. The page puts them in
  `<div data-invites data-sig=…>` (no change to how the page looks).
- `GET /admin/invites.json` (admin only, 403 for everyone else) answers `{sig, states, html}`: the rows drawn now, and
  `invite_rows_sig()`, a hash of each row's token, name, state and status.
- The page's own script gives the box a `live()` that fetches that JSON and redraws the rows only when `sig` changes, so a COPIED
  label or a name half-typed in the form above is left alone. `live()` runs:
  - every 4 s while the page is visible and on screen,
  - when the app comes back to the screen (`visibilitychange`),
  - with Reload/pull-down: `refreshIn` now calls `live()` on any `[data-invites]` box after it swaps the tab lists (one line).
  The polling stops by itself once the page is closed (the box leaves the document).
- I chose a page-level poll as well as the Reload hook because the bug is about the page updating "on its own" while the admin
  looks at it. Reload alone would still need a tap, and `/check` (the visibility check) never fires while the page stays on screen.
  It's one small admin-only JSON request every 4 s, and only while the page is showing.

## Checks
- test_app.py (F16 block): the JSON is 403 to a guest and to a signed-out client. Before registering, it says `unused`/'Not used',
  the page carries the same rows and sig, and asking again gives the same sig. After the invite's first UDID registers, it says
  `used`, the sig changed, the html has 'Used by Sam x iPhone14,2 on' and no COPY link, and REVOKE is still there.
- Gate: `uv run … python test_app.py` passes (`ok`).
- Manual run: the real app on 127.0.0.1 with a scratch data folder, fake Apple calls, and an unused invite. Headless Chromium over
  CDP signed in as admin and pushed Invite Friends over Settings with the app's own `push()`, as tapping the row does. The row read
  'Not used' with its COPY/SHARE buttons. 10 s after start the server registered an iPhone through the invite (`register(…, invite=)`).
  3.5 s later the open page read 'Used by Sam iPhone14,2 on Nov 20, 2026', with no COPY buttons. After Back closed the page,
  the server log shows no more `/admin/invites.json` requests (1 in all). Scripts: scratchpad `b12/serve.py` and `b12/drive.mjs` (not kept).

## Tried / notes
- Stopping the manual run by the pids I'd kept (`$!`) killed only the `uv`/`chromium` wrappers. The python server and the
  Chrome process kept listening. I found their pids by listening port (`ss -ltnp`) and killed those pids.
- A first gate run wrote its log to `/home/ryha/runs/sidedrop/tmp-b12-gate.log`, outside the worktree. It's harmless and I left it
  there (the rules say not to delete outside the worktree).

## Not verified
- On a real iPhone (the Home Screen app): no phone was used in this unattended run. Headless Chromium ran the same page code.
- The Reload/pull-down path calling `live()`: I didn't run it in the browser (the manual run covered the poll). It's one line
  after `navR()` in `refreshIn`'s success path, and the page's script (gate run) parsed fine in Chromium.
- The visibility trigger (app sent to the background and brought back): headless Chromium can't really hide the page.
