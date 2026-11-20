# B7: invite guest no longer lands on the password form after installing the profile

## Cause
iOS opens `/?enrolled=<device token>` after the profile install, often in a Safari without the session. `home()` sent a
signed-out load to `invite_back()`, which (like `guest_ok()` and `invite_link()`) only read the `device` cookie. That cookie
is set by `home()` only on a signed-in load, so the guest got the password form.

## What I did (app.py)
- `device_tok()`: the valid signed token from `?enrolled=`, else the device cookie, else "".
- `guest_ok()`, `invite_link()`, `invite_back()` use it instead of the cookie alone.
- `invite_back()`: when the UDID came from `?enrolled=` and matches a used invite, it signs that guest in and returns None;
  `home()` re-checks `logged_in()` and renders the guest's page in the same response (so the welcome alert still shows,
  since the cookie isn't set yet on that request). The cookie-only case still redirects, as before (F31 tests).
- `home()` sets the device cookie on `?enrolled=` for a guest as well as for a UDID in the profile (it is still re-checked
  against the invite on every load).
- A used invite opened in a fresh cookie jar (Home Screen app) now shows `INVITE_AGAIN`: the used message plus an
  **Install Profile** button. `/invite/<tok>/profile` redirects to a signed registration profile through the invite
  (`/udid/<name>/g/<tok>/again`); `udid_guest()` accepts only the UDID the invite registered and 301s to `?enrolled=`, which
  signs that guest in. Another iPhone's post is refused as before (301 to the invite page). Still 403, like the other
  invite refusals, so existing tests and `/refresh` logic are unchanged.

Decision (unattended): the re-install page needs no session, since the profile only works for the iPhone the invite
already registered; that is the same trust the device cookie already relies on (the profile POST's CMS signature is not
verified, see `embedded_plist`).

## Tests (test_app.py, after the B8 block)
- `/?enrolled=<GUEST-1 token>` with no session and no cookie: 200, the guest's page, no password form, `Set-Cookie: device=…`,
  session `pv` is that invite's guest, next plain `/` stays signed in.
- Unregistered iPhone's token and a forged token still get the password form.
- Fresh jar `/invite/<used tok>`: Install Profile button, no password field; the profile link's GUEST-1 post lands on
  `?enrolled=`, GUEST-2's is refused; unknown invite's `/profile` goes back to `/invite/nope`.

## Tried and failed
nothing

## Not verified
- On a real iPhone (apps.hayde.in, Rhys's invite): no phone or deploy access from this unattended run; the flow is tested
  only through Flask's test client with a fake profile.
- That iOS installs a second registration profile for an already-registered UDID and follows the 301 again: assumed from
  the first install working the same way; not checked on a device.
