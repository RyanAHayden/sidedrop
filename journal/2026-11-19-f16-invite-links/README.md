# F16: invite links on Manage

## What I did

- Manage menu: a new **Invite Friends** row (iFizBox's `share` row icon, copied into `ROW_ICONS` from rowicons.js's
  glyph and its `C.blue`), opening `/admin/invites`.
- **Anyone with the link**: `/join/<token>`, where the token is an HMAC (SECRET) of the friends' `password_ver` and a
  `join_gen` counter in `setup.json`. The password itself is never in it. Opening it makes the same session a
  friend's login makes (`pv = ["f", ver]`). Sign Out Everyone bumps `password_ver`, which kills the link (and, as
  before, those sessions). **Make New Link** bumps `join_gen`. That kills the link but not the sessions already made
  with it. I decided against killing them too: rotating is about who can still join, and Sign Out Everyone already
  exists for kicking people out.
- **One iPhone**: each **New One-iPhone Link** saves `{name, made, exp}` under a random `token_urlsafe(16)` in
  `invites.json` in the data folder. `/invite/<token>` signs the browser in as a guest: `pv = ["g", token, sid]`,
  where sid is a random id for that session. `logged_in()` sends guest sessions to `guest_ok()`:
  - Unused invite: it must be unexpired.
  - Used invite: either the device cookie is the UDID it registered, or the session's sid is the one that downloaded
    the registering profile.
  - Revoked: the invite is deleted, so the guest is out.
- Safari vs the Home Screen app: iOS copies Safari's cookies into the web app when it is added, which is how friends'
  Home Screen apps are signed in today. A guest's Home Screen app gets either:
  - the device cookie (added after registering), or
  - the guest session with the registering sid (added before registering, even though only Safari got the
    `?enrolled=` device cookie).

  Both get in. Someone else who opened the same shared link before it was used has a different sid and no matching
  device cookie, so they're signed out once the link is used.
- Registering: a guest's `/enroll` points the profile at `/udid/<name>/g/<token>/<sid>` (signed like the friends'
  URL). `register(udid, name, invite=(token, sid))` checks the invite under the registration lock (`invite_check`).
  A second UDID raises `InviteRefused(INVITE_USED)`, and expired or revoked invites raise too. The invite is marked
  used only after Apple and the profile succeed (`invite_use`), so a failed Apple call doesn't burn it. The route
  answers a refusal with a 301 to `/invite/<token>`, which shows why in Safari (403 page).
- Guests get 403 on `/admin` and `/admin/*` from a `before_request` hook (`guests_stay_out`). It also covers the
  admin password form, so a guest who knows the admin password has to sign out first.
- A friend or the admin opening a join or invite link stays who they are (a redirect to `/`), so the admin can try
  links without losing Manage.
- The page:
  - The anyone link in a read-only field, with Copy Link and Share.
  - The one-iPhone form (optional name). The new link shows at the top after making it.
  - The list of invites: name, made date, and Not used / Used by <device name> on <date> / Expired.
  - Each unused invite has COPY/SHARE. Every invite has REVOKE, with a confirm.
- Copy uses `navigator.clipboard.writeText` inside the tap. Without it, or if it's refused, it selects the link's text
  (the field, or a temporary hidden textarea for list rows) and tries `execCommand('copy')`. Share is hidden where
  `navigator.share` doesn't exist.
- test_app.py, new F16 section on a fresh boot:
  - The anyone link signs in; Make New Link and Sign Out Everyone kill it.
  - The one-iPhone link registers GUEST-1, refuses GUEST-2 (route and `register()` directly), and allows GUEST-1 again.
  - After use: the registering session stays in, another early session is out, and the link opens again only with
    GUEST-1's device cookie.
  - Expired and revoked links refuse, and their sessions are out. Revoking the used one leaves GUEST-1 in the profile.
  - A guest gets 403 on `/admin` and `/admin/*` (GET and POST).
  - Changed tests: the register stub takes `**kw`, and the Manage menu now has 7 row icons.
- README: a Manage bullet.

## Tried and failed

- First gate run failed only on the Manage menu's row-icon count (6, now 7). Fixed the test.

## Not verified

- I didn't try it on an iPhone. These were checked only in the Flask test client, not in iOS Safari or a Home Screen
  app: clipboard, share sheet, the `execCommand` fallback, and how the page looks. No phone is attached to this
  unattended run.
- Cookie copying into a Home Screen app is iOS behaviour I relied on, not something I tested. The test stands in for
  it with a client holding only the device cookie, and with the registering session.
- Guests aren't tied to the friends' password: Sign Out Everyone doesn't sign guests out (Revoke does). The spec didn't
  ask for that, so it's a choice, not a check.
