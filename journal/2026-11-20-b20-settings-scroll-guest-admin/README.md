# B20 Settings scrolls again; Admin Login for invite guests too

## What I did
- **Scroll.** Looked for what stops the Settings tab scrolling. B18's action sheet (`.mks`) is `display:none` while hidden and
  `pointer-events:none` while leaving, and no script sets `overflow` or a height on `#scr`/`<body>`; the touch handlers are all
  passive except the scroll indicator's and the switches' own. The one scroll rule that applies only to Settings was F29's
  `#scr:has(>#t-settings:not([hidden])){overscroll-behavior-y:none}`. F29's journal lists it under "Not verified" on an iPhone.
  It is the only way Settings scrolls differently from the other tabs, which do scroll, so I removed it (`app.py`, the CSS
  by `#t-settings{min-height:0}`, which stays: a Settings page shorter than the screen still doesn't move). Settings now
  bounces at its top like the other tabs, which is also how iOS 6 Settings behaves.
- **Guests.** The Settings row (`id=sAdmin`) now shows for every non-admin, invite guests included (`not guest` dropped).
  `guests_stay_out` no longer 403s `/admin` itself, only `/admin/…`, so a guest gets the password prompt, and a right password
  turns the session into an admin's (`pv` `["a", ver]`, so `is_guest()` is false from then on), the same as a normal login.
  `admin_fails` rate-limits it as before.
- **`admin_on` kept.** Without an admin password `/admin` is a 404, so a row there would lead nowhere. Setup always asks for an
  admin password (or takes `ADMIN_PASSWORD`), so in practice the row is only missing before setup is done.
- **Tests (`test_app.py`).** The F29 CSS check is replaced: no `overscroll-behavior-y:none` and no `:has(>#t-settings` on the page,
  `#scr` keeps `overflow-y:auto`, and no CSS rule for `#scr`/`#t-settings` sets overflow:hidden, a (max-)height,
  overscroll-behavior:none or touch-action:none. A guest's page has the Admin Login row. A guest's `/admin` is a 200 with the
  prompt (and no Manage menu). A second guest of the same invite who gives the right admin password gets `/admin` → `/admin`,
  the Manage menu, `/admin/invites`, Admin Settings on Settings, no login row, and Sign Out. `/admin/…` stays 403 to a guest.
  The password user's row checks from B19 stay.
- **Screenshots** (`shots.py`, Chromium at 375×667, scrolled with real touch drags through CDP `Input.dispatchTouchEvent`):
  `user-settings-bottom.png` and `guest-settings-bottom.png` show Settings scrolled to the bottom (the user's with Admin Login
  and Sign Out; the guest's with Admin Login and no Sign Out, per F31). `*-admin-login.png` is the pushed prompt.
  `*-admin-after.png` is Manage after the right password.

## Tried and failed
- `Input.synthesizeScrollGesture` (touch) scrolled nothing, not even a plain test scroller, so it couldn't tell me anything.
  Raw `Input.dispatchTouchEvent` drags work, and I used them.
- I couldn't reproduce the "doesn't scroll" bug in Chromium: before the fix, touch drags and the wheel both scrolled Settings
  (138px for a password user). Removing the overscroll rule in Chromium changed nothing either. So the bug is WebKit-only, and
  I found the cause by reading the CSS, not by watching it fail.

## Not verified
- On a real iPhone (Safari or the Home Screen app), that Settings scrolls now. Before the fix, Chromium already scrolled, so the
  shots only show nothing else blocks it. No iPhone was reachable from this unattended run (the iPhone 7 test phone is on another
  machine, and on iOS 15 it doesn't support overscroll-behavior, so it couldn't show this bug anyway). If an iPhone still won't
  scroll Settings, the next thing to look at is the `#t-settings{min-height:0}` that stays.
