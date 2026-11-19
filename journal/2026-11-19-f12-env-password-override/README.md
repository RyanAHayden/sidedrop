# F12: Passwords page can change a password that .env sets

## What I did

- `app.py`:
  - `password_ok()` now checks `setup.json`'s `password_override` / `admin_password_override` first when `.env` sets that
    password. With no override it uses `.env`, and with no `.env` value it uses the saved hash. Hash checking moved into
    `hash_ok()`.
  - `drop_stale_overrides()` runs at startup, after `apply_setup()`. An override is stored with `password_env`, a pbkdf2
    hash of the `.env` value it replaced. If `.env` now holds a different value, or none, the override and that hash are
    removed, so `.env` wins again. The check runs only at startup because `.env` is only read then. That keeps
    `password_ok()` to one pbkdf2 per sign-in.
  - Session password versions: `setup.json` holds `password_ver` and `admin_password_ver`. Every sign-in stores
    `session["pv"] = [kind, version]`. The kind is `"f"` for the friends' password and `"a"` for the admin password (the
    login link, or unlocking on `/admin`).
    - `logged_in()` requires the session's version to equal the current version for its kind, so `is_admin()` checks it
      too.
    - Sessions from before F12 have no `pv`. They count as version 0, of kind `"a"` if they have `admin`, else `"f"`. So
      nobody is signed out by the upgrade.
  - `/admin/passwords`:
    - Both fields always show. A field whose password comes from `.env` says **Set in .env**, or **Changed here, over the
      one in .env** once it has an override.
    - When a `.env` field has text, Save opens an in-page iOS 6 alert (`.scrim .alert`, the same markup as the home
      page's alerts) with the brief's wording. **Replace** sets the hidden `replace_env=1` and calls `requestSubmit()`, so
      the pushed-page submit handler still posts it.
    - The server refuses a change to a `.env` password without `replace_env=1` ("Confirm replacing…"), so skipping the
      JS changes nothing.
    - **Use .env Password** is a separate small form for each overridden password, behind its own alert. It drops the
      override and bumps that password's version.
    - Every change bumps the version, including changes to passwords that are not in `.env`. When the admin password
      changes, the current session's `pv` is moved to the new version, so the admin making the change stays signed in.
      The small text now says that a change signs out the iPhones that used the old password.
  - `DONE["env"]` holds the message shown after Use .env Password.
- `test_app.py`: the old assertion ("set in .env" plus "Type a new password") now expects "Set in .env" and the confirm
  refusal. A new F12 block at the end boots a fresh data folder with PASSWORD and ADMIN_PASSWORD in env and checks:
  - Without confirm, nothing changes.
  - After changing the friends' password, the old one is refused (form and `?password=` link), the new one works, the
    old friend session is out, and the admin stays in.
  - After changing the admin password, the other admin session is out and this one stays.
  - A restart with the same env keeps both overrides.
  - Use .env Password restores `.env`'s value and signs out the override's sessions.
  - A restart with a different `ADMIN_PASSWORD` gives `.env` the win and drops the override from `setup.json`.
- README: a Manage bullet for Passwords.

## Checked by hand

`ui.py` (here) runs the app with both passwords in env, then drives headless Chromium (`/usr/bin/chromium` through
Playwright). It goes Settings → Manage → Passwords as a pushed page, types a friends' password and taps Save. The alert
appears and nothing is saved yet. Replace saves the override and "Saved." shows in the pushed page. Use .env Password →
its alert → Use .env brings `.env`'s password back, and the admin stays on the page. Screenshots: `alert.png`,
`overridden.png`.

## Tried that failed

- Playwright's own WebKit build wasn't installed for the Playwright version uv fetched (webkit-2388 missing). I used the
  system Chromium instead of downloading browsers.
- The first test run failed because the fresh `f12` data folder didn't exist (`save_json` doesn't create it). Real
  deployments always have the data folder, so the test now creates it.

## Decisions

- When `.env` changes and an override is dropped at startup, password versions are **not** bumped. Editing `.env` never
  signed anyone out before, so sessions made with the dropped override stay signed in until they sign out.
- Use .env Password does bump, as the brief's "a change signs out the sessions made with the old password" asks.
- An admin who signed in with the friends' password and then unlocked `/admin` with the admin password is treated as an
  admin session (kind `"a"`). Changing the friends' password doesn't sign them out.

## Not verified

- On a real iPhone (iOS Safari): only headless Chromium was used. iOS has had `requestSubmit` since 16. Without it the
  code falls back to `form.submit()`, a full-page POST that still works but leaves the pushed page. Not tried on an older
  iOS.
- WebKit rendering of the alert inside a pushed layer: Playwright's WebKit wasn't available (see above).
