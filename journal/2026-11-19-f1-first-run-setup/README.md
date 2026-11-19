# F1: first-run setup splash

## What I did

- `app.py`: `PASSWORD` and `SECRET_KEY` are optional now. With no `PASSWORD` in `.env` and no saved setup, signing in with
  `DEFAULT_PASSWORD` (`sidedrop`) sets only `session["setup"]` (never `ok`) and redirects to `/setup`; every other page
  stays locked for that session. The login page shows the default password while setup is pending (it is public in the README anyway).
- `/setup` takes the friends' password, the admin password, signing files (`sort_signing_files`, a port of iFizBox's
  `certfiles.js`: zips or loose files, `__MACOSX` skipped, `.p12`/`.p8` by extension, p12 password guessed from text files with
  the same `password_guesses` rules, plus "" last), the P12 password, Key ID (guessed from `AuthKey_<ID>.p8`), Issuer ID
  (guessed from a UUID in a text file) and `BUNDLE_ID`. Fields `.env` set are hidden and left alone.
- Valid files and IDs are saved even if the form has another error, so a retry doesn't need the files again; the passwords
  (pbkdf2-sha256, 200k rounds) only go into `setup.json` when everything is complete, which ends setup. The default
  password then is just a wrong password, and `/setup` redirects home.
- `apply_setup()` fills `P12_PASSWORD`, `BUNDLE_ID` and the `ASC_*` environment variables (which `asc()` reads) from
  `setup.json` where `.env` left them empty, at import and after saving.
- Admin checks go through `admin_enabled()` / `password_ok(..., admin=True)` so a setup-made admin password works.
- Empty `SECRET_KEY`: one random key is made and kept in `DATA/secret.key`, so a fresh container needs only `PUBLIC_URL`.
- Tests: `boot()` re-imports `app.py` as a new module on a new data folder with chosen env, to cover fresh start → default
  password → splash errors (short password, missing App ID, same passwords, wrong p12 password) → setup → new passwords
  and admin password work, default refused, hashes not plaintext; the same after a restart; `.env` `BUNDLE_ID` wins over the
  saved one; a `.env`-configured start skips the splash.
- README Setup and `.env.example` describe the phone setup as the default.

## Decisions

- No CSRF token on `/setup`: the session cookie is SameSite=Lax, so a cross-site POST carries no session.
- `PUBLIC_URL` stays required: it's used for signed links and the cookie's Secure flag at import.
- The splash requires the signing files and IDs (or existing ones on disk / in `.env`): there is no other UI to add them later.
- Anyone who reaches a fresh server before its owner can set it up; that is inherent to "default password + setup on the phone".

## Tried that failed

Nothing notable; the gate passed on the first full run.

## Not verified

- How the splash looks on an iPhone (no browser/phone check in this unattended run); it reuses the page's `.c` form, label,
  `.vh` file-input and `.ftr` styles, plus one small `<style>` for stacked labels.
- iOS Safari's multi-file picker with a `.zip` from Files: only the server side was tested with the Flask test client.
- A real Apple certificate/API key: tests use a self-made EC cert in a p12 and a generated EC key.
- Docker compose's handling of the now-empty `.env.example` values with trailing comments (the file already relied on it for `ADMIN_PASSWORD`).
