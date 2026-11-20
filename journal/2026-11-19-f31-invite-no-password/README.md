# F31: invite links never ask for a password

## What I found

F16 already signs people in from an invite link with no password step. `/join/<token>` makes a friend session, and
`/invite/<token>` makes a guest session. Registering needs no password either. A named invite skips even the name
field. A user who came in by a link could still end up on the password form in three ways, with no password to type:

- **They tapped Sign Out.** `session.clear()` dropped the guest session. That person might still open a one-iPhone
  link that was already used, which works only with that iPhone's device cookie, but a Home Screen app has no way to
  open a link at all.
- **A session without the guest cookie.** For example, a Home Screen app whose cookies were copied before the invite
  was opened, or a session that was lost. It has the device cookie but no session.
- **A guest session the invite no longer lets in.** For example, someone else who opened a shared link before it was
  used. They got the bare password form with "The friend who sent you the link has the password".

## What I did

- `invite_back()`, in `app.py` after `invite_link`. It runs from `/` whenever someone is not signed in:
  - If the device cookie is the UDID a one-iPhone invite registered, and that invite hasn't been revoked, it signs the
    browser in again as that invite's guest (new sid) and redirects to the same URL. This applies the access rule
    F16 already uses for `/invite/<token>`, now without the link in hand.
  - If the session is a guest session the invite refuses (used by another iPhone, expired or revoked), it shows the
    reason, the same text as `/invite/<token>` (403). There is no password form, but there is a small "Sign in with a
    password instead" link (`/logout`, then the form) for someone who does have one.
  - Otherwise it returns None, and the password form shows as before.
- Settings hides **Sign Out** for guests: with no password, signing out only locks them out, and their device cookie
  would sign them straight back in anyway. Friends (including people who joined with the "Anyone with the link"
  link) and the admin keep Sign Out.
- The password form's footer adds one line: "If they sent you an invite link, open it again: it signs you in with no
  password." The existing sentence stays as it was.
- Admin login is unchanged: no admin code path was touched.
- Tests (test_app.py, F16 section):
  - A guest's page has no `type=password`, no login form and no Sign Out. A friend and the admin still have Sign Out.
  - A client with only GUEST-1's device cookie is signed back in with no password.
  - The stale `early` session gets a 403 with INVITE_USED, no password field, and a way out to the form.
  - A device cookie no invite registered still gets the password form.
  - Once the invite is revoked, GUEST-1's device cookie signs nobody in.
  - The existing tests for invalid, expired, used and revoked links still pass, so a bad link still refuses.
  - `signed_in()` in the tests now also needs a 200, because the stale-guest page has no login form but isn't
    signed in.

## Choices

- "Anyone with the link" friends keep Sign Out. Their link still signs them in again, and it is a friend session, not
  a guest one. The new footer line points them back to the link.
- I didn't let an expired unused invite keep its session. Expiry is how a shared link stops filling the account, and
  F16's tests assert it. The guest now sees "This invite has expired. Ask for a new one." instead of a password form.
- F30 (invite links land on device setup) is separate and not done here. I left `invite_link`'s redirect alone.

## Tried and failed

- The first draft of the "friends keep Sign Out" test used the `anyone` client, which an earlier Sign Out Everyone
  had signed out, so the check was empty. It now uses a fresh client from the current join link.

## Not verified

- I didn't try it on an iPhone (unattended run, no phone attached). Two things are covered only by Flask test-client
  checks, not in Safari or a Home Screen app:
  - Signing back in from the device cookie in a real Home Screen app.
  - Safari following the 302.
- I didn't check by eye how the stale-guest page and the hidden Sign Out look.
