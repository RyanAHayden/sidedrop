# F4: certificate warnings and errors, the checks iFizBox makes

## What I did

- `cert_problems(blob, pw)`: checks a .p12 locally, no network, and returns `[(level, text)]`:
  - wrong password
  - no certificate
  - no private key (a cert-only .p12 loads the cert among the extras)
  - a key that pairs with none of the certificates, or a key and cert whose public keys differ
  - common name not `Apple Distribution:`/`iPhone Distribution:`, with "a development certificate" when it's
    `Apple Development`/`iPhone Developer`
  - expired (error)
  - expiring within `CERT_WARN_DAYS` = 30 (warning). iFizBox warns at 7 by default; the brief says 30.
- `cert_account_problems()`: the checks that need Apple.
  - Revoked: OCSP to the cert's AIA responder. The issuer comes from the .p12's extras or the AIA caIssuers URL. A failed
    OCSP call is only printed, never shown as a problem.
  - The ad hoc profile's `DeveloperCertificates` don't include this certificate.
  - The certificate's serial isn't in ASC `/certificates` (left out when it's already reported as revoked).
  - `BUNDLE_ID` isn't an exact match in `/bundleIds`.
  - An explicit App ID without the `PUSH_NOTIFICATIONS` capability (warning: signing still works).
  - ASC not answering gives one warning.
- `cert_status()` runs both and caches Apple's answers for an hour, keyed on the p12 mtime, password and BUNDLE_ID, so a new
  upload is checked again at once. It skips the Apple checks when the p12 doesn't open or has no key.
- Setup and Manage uploads: `take_signing_files` refuses a .p12 that has any `cert_problems` error. The saved one stays,
  because a certificate that can't sign would break every app at the next re-sign. A warning, such as expiring soon, doesn't
  block the upload.
- Manage: the problems appear as a banner at the top of the page, red for errors and amber for warnings.
- Startup: the local problems are printed at import. The Apple checks run in a background thread and print with a
  `certificate error:`/`certificate warning:` prefix. Only when a p12 exists and setup is done.
- README: a Manage bullet and a line about what the upload refuses.
- Tests: the suite's p12s now use a self-made `Apple Distribution: …` cert. The old one was the `x.test` TLS cert, which is now
  rightly refused. New tests:
  - `cert_problems` for each case
  - Manage uploads of a wrong-password, an expired and a non-distribution p12, each with its message and the saved p12
    untouched
  - the Manage banner showing expiring-in-10-days, not-in-account and missing App ID
  - explicit App ID with and without Push
  - profile for another cert
  - revoked through a stubbed OCSP responder, with a real cryptography-built OCSP response from a fake CA and the issuer
    fetched via AIA
  - ASC down
  - the startup log line format

## Tried, failed

- A test p12 whose key doesn't match its cert: cryptography refuses to build one ("public key and provided private key do not
  match"). That branch is untested.
- I ran a live OCSP check against `revoked.badssl.com` to test the revoked path. Its cert is Let's Encrypt, which no longer has
  OCSP, so it can't show the revoked path. `www.apple.com`'s cert, from an Apple CA that uses the same ocsp.apple.com family
  as the WWDR certs, went through `ocsp_revoked`'s exact steps: issuer from AIA, POST, SUCCESSFUL, GOOD.

## Not verified

- I didn't run OCSP against a real Apple Distribution certificate, revoked or not: there's no Apple developer cert on this
  machine. The flow was checked against Apple's TLS OCSP responder (GOOD) and a stubbed revoked answer.
- I didn't call the real App Store Connect `/certificates`, `/bundleIds` or `/bundleIds/{id}/bundleIdCapabilities`: there's
  no API key here. The field names (`serialNumber`, `identifier`, `capabilityType` = `PUSH_NOTIFICATIONS`) come from Apple's
  API docs and from how `cert_id`/`regen_profile` already use them.
- I didn't look at the Manage banner in a browser. The test checks its text only.
- The setup screen runs only the local checks. Apple's checks need the API key the same form is saving, and the Manage banner
  shows them right after.
