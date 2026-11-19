# F9: setup with just the API key

## What I did

- `app.py`, new block before `/setup` ("setup with just the API key"):
  - `ensure_app_id(bid)`: GET `/bundleIds` (exact match, since the filter is a prefix match); if the App ID is missing,
    POST `/bundleIds` (name `sidedrop`, platform IOS). An explicit one then gets POST `/bundleIdCapabilities` for
    PUSH_NOTIFICATIONS (a failure here is an error), APP_GROUPS and ASSOCIATED_DOMAINS (failures only printed). These
    are the same three the docs told people to tick. A wildcard gets none.
  - `make_certificate(s, revoke)`: an RSA 2048 key and a CSR (CN `sidedrop`; Apple sets its own subject), then POST
    `/certificates` with `certificateType: DISTRIBUTION` and the PEM CSR. The answer's DER cert and our key are saved as
    `cert.p12` (mode 600). It uses 3DES/SHA1 PKCS#12, like `openssl -legacy`, so every iOS version opens it (iFizBox
    carries it to phones; I checked with `openssl pkcs12 -info`). The password is `secrets.token_urlsafe(18)`, kept as
    `p12_password` in `setup.json`, or `P12_PASSWORD` from `.env` when that is set.
    - 403 means the key role is wrong: the error says it needs an Admin key.
    - 401 means bad Key ID or Issuer ID.
    - 409 with distribution certificates present means the account is full: it returns the picker list.
    - `revoke` is deleted only if it's in the freshly listed distribution certificates. Nothing is revoked without it.
  - `dist_certs()`: GET `/certificates` filtered to DISTRIBUTION and IOS_DISTRIBUTION. Each entry has name, kind, made
    (the certificate's notBefore, since Apple's API gives no creation date), expires, and whether it's sidedrop's
    current cert.p12.
  - `api_signing(s, revoke)`: makes the App ID first, then the certificate. A retry after a failed certificate finds
    the App ID already there.
  - `CERT_PICKER` / `REVOKE_CONFIRM`: radio rows inside the signing form, plus a JS `confirm()` before submitting with
    one checked.
- `/setup`: the main path is passwords, **Choose API Key**, Key ID, Issuer ID and App ID. If no cert.p12 was uploaded
  or saved, `api_signing` runs after every local check passes and before the passwords are saved. **Manual setup** is
  a `<details>` that holds today's **Choose Signing Files** (a second `files` input) and P12 Password, plus a link to
  `docs/developer-account.md#manual-setup`. It opens by itself once a cert.p12 is saved. The manual path calls Apple
  for nothing, as before.
- Manage → Signing has the same layout: API key first, then **Save** and **Make New Certificate**, and Manual setup
  under them. Make New Certificate (or a revoke pick, or no cert.p12) runs `api_signing`. When it works, the
  certificate check cache is cleared and `resign_all` runs. The picker shows its error inside the signing form, because
  the top banner is far away. When Manage saves a changed App ID, `ensure_app_id` runs too. A failure there doesn't
  stop the save: it's printed, and the existing banner reports the missing App ID.
- Key role research: Apple's roles table (developer.apple.com/help/account/access/roles/, fetched today) gives
  "Create and revoke distribution certificates" to Account Holder and Admin. App Manager gets it only with "Access to
  Certificates, Identifiers & Profiles". In App Store Connect that is an option for people, and I found nothing that
  offers it for team API keys. So the docs and the 403 error say **Admin**, and App Manager stays enough for the
  manual path.
- Docs:
  - developer-account.md is rewritten. The main path is: join, one Admin API key, upload it, what sidedrop makes, and
    the certificate-limit picker. Then iPhones/profile and switching from a wildcard. The old certificate, App ID and
    server steps are now under `## Manual setup` (M1–M3).
  - become-a-distributor.md: step 1 is now just the program and an API key (`apikey.zip` with an issuer.txt). Step 4
    covers Choose API Key, the picker, and the yearly Make New Certificate. Troubleshooting covers the Admin role.
  - README: the setup steps, the data folder table, the Manage bullet, and the BUNDLE_ID line.
- Tests (`test_app.py`, at the end, against a `FakeApple` ASC stub that signs the CSR it is sent):
  - The setup page shows Choose API Key, Manual setup and the docs link.
  - An App Manager-like 403 gives "Admin role", no cert.p12, setup not done. The App ID is still made, with exactly
    Push, App Groups and Associated Domains.
  - On retry: setup is done, the cert.p12 passes `cert_problems` with a random password of 20+ characters saved in
    setup.json, the App ID is not made twice, and nothing is deleted.
  - A wildcard is made without capabilities, and not made twice.
  - Manage Make New Certificate with 3 certificates: the limit text, 3 radios with names, made and expires dates, one
    marked as sidedrop's, and no DELETE. An unknown revoke id is refused with no DELETE. Revoking "Old Mac" DELETEs
    exactly that one, makes a new certificate, changes cert.p12 and keeps the App ID.
  - Manual upload on Manage still works, with only GET calls to Apple.
  - Manage saving a new App ID makes it.
  - The earlier manual setup tests (zip with cert.p12 + password.txt) pass unchanged.
- Screenshots (headless Chromium, 390pt wide, rendered from the real templates with `api_signing` stubbed):
  `setup.png`, `setup-revoke-picker.png`.

## Tried that failed

- The first picker render inherited the page's `input{width:100%;padding…}`, so each radio was a stretched text box
  with the labels crushed into a 10px column. I gave the radio inline `flex:none;width:22px…` and the text
  `flex:1;min-width:0`.
- The test's CSR-signing stub used the suite's `n` as the issuer name. Something later in the suite reassigns `n`, so
  `issuer_name` got a non-Name. The stub now uses its own name.

## Not verified

- **Against Apple itself.** No real App Store Connect account or key is available to an unattended run. These are
  from Apple's API docs and fastlane-style usage, not observed:
  - that `csrContent` takes the PEM text (headers included)
  - that a full account answers 409 (rather than another 4xx) on POST `/certificates`
  - that an App Manager team key gets 403 there
  - that `name: "sidedrop"` is accepted for `/bundleIds`
  - that APP_GROUPS and ASSOCIATED_DOMAINS can be added by `capabilityType` alone

  If Apple answers a full account with something other than 409, the admin sees "Apple didn't make the certificate: …"
  with Apple's text instead of the picker. That's safe (nothing is revoked) but less helpful.
- **Apple's exact certificate limit** isn't hard-coded. The picker appears on Apple's refusal, so the number doesn't
  matter.
- **On an iPhone.** The setup and Manage pages were only checked in desktop headless Chromium, not in iOS Safari
  (radio look, `<details>` disclosure, the confirm dialog). Manage's signing section had no screenshot.
- **A generated cert.p12 imported by iFizBox on a phone.** It's checked only as being in the same 3DES format as
  `openssl -legacy`.
