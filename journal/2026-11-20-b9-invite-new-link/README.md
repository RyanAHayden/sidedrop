# B9: a new invite link "doesn't work" / "expired" after the admin revoked the old one

## What I did

Read both invite paths (`/join/<tok>` with Make New Link, `/invite/<tok>` with REVOKE) and walked each sequence in the test client:
make, revoke/rotate, make again, open as a fresh client, after a cookieless crawler fetch, and after a restart (a second `boot()` on the
same data folder, which is also what a second worker would see).

- **Anyone with the Link**: the token is an HMAC of the persisted `SECRET` (env or `data/secret.key`), the friends' password version
  and `join_gen` in setup.json. Make New Link bumps `join_gen`; nothing a crawler or a fresh client does changes it, and a restart
  computes the same token. The existing test (old link 403, new link works) already covers it. No bug found there.
- **One iPhone**: a fresh client, a crawler, or a restart all leave a new unused invite working. The failing sequence is the realistic
  one: the friend's iPhone **was registered through the first link**, the admin revoked it (which signs the guest out) and made a new
  one. The friend opens the new link in Safari: the iPhone is already in the profile, so nothing ever registers through the new
  link and it stays *unused*. Then:
  - the Home Screen app (its own cookie jar: the revoked link's guest session plus the device cookie) finds no invite holding its
    UDID and shows "This invite link doesn't work any more. Ask for a new one." — the friend can't open the link inside it;
  - 7 days later (INVITE_TTL) Safari's guest session on the still-unused link shows "This invite has expired".

## Fix

`invite_registered()` in app.py, called from `/invite/<tok>` when it signs a guest in: if the invite is unused and the browser's device
token names an iPhone already in the profile that no other invite holds, that iPhone uses the invite right away (as `register()` would
have done for an already-registered UDID: `invite_use`, device name = invite name + saved PRODUCT). The device cookie then signs every
cookie jar of that iPhone in as the new guest (`invite_back`), and the session no longer depends on the 7-day expiry.

Choices: only an iPhone **in the profile** (one the admin turned off still registers through the link normally), and only when **no
other invite already holds its UDID** (a friend with a working invite who opens a second link doesn't burn it; behaviour there is
unchanged). A cookieless crawler has no device token, so it uses nothing up.

## Test

test_app.py, after the F16/F31 revoke checks: GUEST-1's revoked-link session and device cookie in two jars (Safari, Home Screen app),
a new invite, a crawler fetch (still "Not used"), Safari opens it (now "Used by Sam iPhone14,2"), the Home Screen app gets in, both
stay in past the expiry, a restarted instance signs the device cookie in and refuses other iPhones; plus an unregistered client's
make/revoke/make sequence (old 403, new works, stays unused). Before the fix it failed at the "Used by" assertion (and the Home Screen
jar got the 403 page); after it the gate passes.

## Tried and dropped

Looked at the client-side push navigation (`cache[id]` of pushed pages, `f.submit()` fallback re-posting) for a stale link shown to
the admin: a re-post of Make New Link bumps twice but the page then shows the newest link, which works; no stale-link path found.

## Not verified

- On a real iPhone (Messages preview, Safari + Home Screen app jars): no device in this unattended run; the cookie-jar behaviour is
  modelled with separate test clients as the B7/F31 tests do.
- Which link the friend actually used is still unknown (the report didn't say); the `/join` path showed no failure in any sequence I
  could build, so if the report was about `/join`, its cause is not found here.
- A Home Screen app added *before* the iPhone was registered (no device cookie in its jar) still can't get back in after the first
  link is revoked; it was not part of the reported sequence and needs a way to identify the iPhone there (not built).
