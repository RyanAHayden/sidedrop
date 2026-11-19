# F2: admin through the login link, and a Manage page that runs the server

## What I did

- `login()` (the form and the `?password=` link): the friends' password signs in as before (and drops an admin flag left in
  that browser); otherwise the admin password (`.env` or the setup's hash) signs in with `session["admin"]` and a CSRF token,
  the same state the old `/admin` unlock form sets. Not while setup is pending, so it can't skip the splash.
- The **Manage** tile in Settings now shows only to an admin session (`is_admin()`), not to every registered iPhone. A friend
  who types `/admin` still gets the old unlock form, which still works.
- `/admin` is now one Manage page: iPhones (as before; Apple not answering is now an inline error instead of the whole page,
  so the rest still works), **Files for friends** (upload, delete), **Apps and iFizBox** (one textarea per editable file:
  `mirror-sources.txt`, `third-party-sources.txt`, `ifizbox-sources.txt`, and a new `ifizbox-settings.json`), and **Signing**
  (Choose Signing Files, P12 password, Key ID, Issuer ID, App ID; `.env`-set fields hidden, as on the setup screen).
- Config overrides: `conf(f)` returns `DATA/config/f` if it exists, else the repo's `HERE/f`; `read_urls`/`read_sources` and
  iFizBox's re-sign dependencies go through it. Saving rebuilds `SOURCES` and starts a background `sync_if_stale(0)`;
  **Use Default** deletes the override. iFizBox sources/settings changes delete the signed iFizBox (when its IPA is in `apps/`)
  so the next page load signs it again with them inside (the mtime rule can't see a revert to the older repo file).
- `ifizbox_transfer()` puts `ifizbox_settings()` (the JSON object, `{}` if none or bad) in the payload's `settings`.
- Signing: the setup's file handling moved into `take_signing_files(form, uploads, s)`, used by `/setup` and
  `/admin/signing`. One change for both: with `P12_PASSWORD` in `.env` a new `.p12` must open with it (before, setup would save a
  guessed password that `.env` then overrode). After a good save, `resign_all()` runs in a thread: a new profile for the new
  certificate (`regen_profile`) and `resign(force=True)`, only if a profile exists already.
- Files: the old Files page (git `9e64376^`: `DATA/files`, signed `/f/<path>` links) is back as `DATA/files/` (flat, no
  subfolders), listed under **Files** on the Apps tab for everyone signed in, links signed like `/af/` (7 days, no login,
  resumable). Upload names are stripped of paths and leading dots; delete takes only a name that's in the listing.
- Tests: admin via `?password=<admin>` sees Manage; edits mirror sources (saved in `DATA/config`, repo file untouched,
  `SOURCES` updated), iFizBox sources and settings (checked inside the transfer link), bad JSON refused, unknown file names 400,
  Use Default; uploads a file (path/dotfile names cleaned); a friend sees the file and no Manage, downloads it without login
  via the signed link, gets 403 on every Manage POST, and a wrong CSRF gets 403 too; signing upload with a wrong then right p12
  password, re-sign started; on the first-run (no `.env`) app: admin link, bad App ID refused, App ID change saved with the
  password hashes kept.
- README: how the admin signs in and what Manage does.

## Tried / failed

- First test run: the bad-App-ID check was a no-op in the main test env because `BUNDLE_ID` comes from `.env` there (the
  field is hidden and ignored); moved it to the first-run app, which has no `.env` App ID.
- I edited one block of `app.py` with a Python heredoc (cutting the old device-list body out of `admin()`) before
  remembering the rule about using the edit tool; the result was checked by the test run and the diff.

## Decisions

- Admin login lands on `/` (Apps), not `/admin`: the admin is also a friend installing apps; Manage is one tap in Settings.
- Removing a source doesn't delete the apps it already put in `apps/`; that was already true for repo edits.
- "iFizBox settings" is free-form JSON: I don't know which keys iFizBox's import reads beyond `settings` being an object.

## Not verified

- On an iPhone: the Manage page layout and file pickers in Safari. Checked only as a 390px headless Chromium screenshot.
- Replacing the certificate against Apple for real (`regen_profile` with a new cert, `cert_id()` finding it): Apple is stubbed
  in tests and there is no developer account here.
- That iFizBox applies the `settings` object from the transfer link: needs iFizBox on a phone.
- Very large uploads through the production proxy (body size limits there); Flask itself has no `MAX_CONTENT_LENGTH` set.
