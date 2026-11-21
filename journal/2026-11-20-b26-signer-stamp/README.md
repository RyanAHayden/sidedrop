# B26 Signed copies are signed again when signing itself changes

## What I did

- `app.py`: `SIGNER_VERSION` (bumped by hand when what `sign_ipa` puts in a signed copy changes) and `signer_stamp()`
  (`"<SIGNER_VERSION> <sha256 of GROUPFIX_DYLIB>"`, `none` for the hash when the dylib is missing).
- `resign()` keeps one stamp per signed copy, `signed/.<name>.signer`, beside it. A copy is signed again when its stamp
  is missing or differs, on top of the old checks (missing, older than the IPA/profile, `force`). The stamp is removed
  before signing and written only after `sign_ipa` succeeds, so a failed sign is tried again on the next resign while the
  old copy stays served.
- Per-copy rather than one stamp for the whole folder: with one stamp, a single app that keeps failing would make every
  resign (one runs on Apps page loads) sign every app again.
- Dotfiles are hidden from `SIGNED.glob("*.ipa")`, which is how every reader lists signed apps, so Apps, `signing_now()`
  and the ETag/mtime readers don't see them.
- On deploy: no live copy has a stamp yet, so the first resign after B26 lands (the next Apps page load) signs every
  app again, which brings the group fix and the new keychain-access-groups from B23 to the copies signed before it.
  That is what the task asked for; it means one slow page load (every app signed under `lock`).
- `test_app.py`: a B26 section on its own data folder: first sign writes the stamp; no change → no sign; a copy without
  a stamp (from before B26) is signed again; a `SIGNER_VERSION` bump and another group fix dylib each sign again, once;
  a failing zsign leaves no stamp and the old copy, and the next resign signs it.

## What failed

Nothing.

## Not verified

- The live server (apps.hayde.in): not deployed from a task branch; the runner merges and publishes. The re-sign of the
  live copies after deploy is R3's recheck to see (R3 is already filed to recheck B23's group fix live).
