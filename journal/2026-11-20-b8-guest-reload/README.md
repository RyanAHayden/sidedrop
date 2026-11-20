# B8: Reload for an invite guest, and a Reload that never fails silently

## What I found
I could not reproduce a guest-only failure. Locally, a one-iPhone invite guest (session `pv ['g', tok, sid]`) gets
`POST /refresh` → 204 and `GET /` → the full page with `#t-apps`, `#t-ifizbox` and `#stamp`. That holds both with the
device cookie and without it, in the session that registered. In headless Chromium, Reload showed the bar and swapped
in an app added after the page loaded. `guest_ok` doesn't fail for either session, so it isn't what breaks Reload.

The old code had these silent paths, and any of them could be what Rhys sees on apps.hayde.in:
- **No connection, or no answer**: `refreshIn`'s `.catch(()=>{})` swallowed it, so the bar went down and nothing changed.
  A `/refresh` that never returned left `html.reloading` set for good, and `reloadData()` ignores taps while that class
  is set, so every later tap did nothing.
- **A cached "/"**: `fetch("/")` used the default cache mode, so a proxy or the iOS web-app cache could return the same
  page again. "Nothing happens" would look exactly like that.
- **A non-OK "/"**: a 500 page that happens to contain the sections would be swapped in, or a throw would be swallowed.
- **A 403 from /refresh**: this was already OK, because the "/" fetched next has no `#t-apps` and the page reloads.
  Now a 403 reloads the page directly.
- **A throw during the swap**: `i.oninput()` on an `input[name=name]` without a handler threw. It runs after the lists are
  swapped, so the visible effect was small, but it was swallowed.

## What changed (app.py, the Reload script)
- `reloadData()`: `/refresh` returns 403 (signed out, or a stale guest) → `location.reload()`, which lands on what the
  server shows that session now (the invite's message, `invite_back`'s sign-in again, or the password form). Any other
  answer, or a network failure → `refreshIn(1)`. An AbortController gives up on `/refresh` after 2 minutes, so a hung
  request can't leave Reload dead.
- `refreshIn(loud)`: fetches "/" with `cache:"no-store"`, and a non-OK response counts as a failure. With `loud` (a tapped
  Reload): a network failure shows **Couldn't Reach SideDrop** in the reload bar for 2 s without the spinner
  (`reloadFail()`, `#rbar.fail`), and any other failure (bad page, a throw in the swap) does `location.reload()`.
  Without `loud` (checkNow's background refresh, mkDo) it stays quiet, as before, so a background check can't yank the page.
- `i.oninput&&i.oninput()` in the swap.
- No server change.

## Checked
- Test gate passes. New asserts in test_app.py, in the F16/F31 invite block:
  - the guest session, the device-cookie client, and the "lost" (signed back in) client all get a non-403 `/refresh` and
    a "/" with the three sections;
  - a stale guest session (wrong sid, no cookie) gets `/refresh` 403 and a "/" with no lists;
  - the page has the new JS (403 → reload, the timeout, no-store, the loud catch, the bar message, the oninput guard).
- Headless Chromium (`guest_reload.py` here; from the repo root:
  `uv run -q --no-project --with-requirements requirements.txt --with playwright python journal/2026-11-20-b8-guest-reload/guest_reload.py [nodevice] [offline] [revoke] [nameinput]`),
  with a named invite "Rhys" and `/refresh` slowed by 0.6 s, both with and without the device cookie:
  - Tap Reload: the class went `[True, False]`, so the bar showed and then hid. Trailhead, added on the server after the
    page loaded, was in the list. The page was swapped in place (no reload), and there were no page errors.
  - Offline (every request aborted): the bar read "Couldn't Reach SideDrop" with `.fail` on it, then went down, and the
    text went back to "Reloading Data". On the old code (HEAD exported to the scratchpad), the same run showed nothing.
  - Invite revoked while the page was open (the signed-out case): Reload reloaded the page to "This invite link doesn't
    work any more… Sign in with a password instead".

## Tried and dropped
- Probing with buttons on a pushed page (Help, This iPhone): the pushed layer covers the header's Reload button, so it
  can't be tapped there. That isn't specific to guests and isn't this bug.
- `Cache-Control: no-store` on "/" itself: not added. Safari keeps no-store pages out of its back/forward cache, which
  could change how `goBack()`'s `history.back()` restores pages. The client's `cache:"no-store"` covers Reload.

## Not verified
- **The real cause on apps.hayde.in.** I have no access to that server, its proxy, Rhys's session or his iPhone, and
  the guest path works locally. The fix makes every failure visible or reloads the page, so the next report should say
  which case it is. To confirm: Rhys taps Reload on the deployed build. Either the lists update, or he sees "Couldn't
  Reach SideDrop", or the page reloads.
- iOS Safari and the Home Screen app: tested only in headless Chromium. `AbortController` needs iOS 12.2+ and falls back
  to no timeout when missing.
- Pull-to-refresh (touch) goes through the same `reloadData()`, but I did not test it by touch.
