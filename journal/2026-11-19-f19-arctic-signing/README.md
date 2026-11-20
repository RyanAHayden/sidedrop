# F19: Arctic-style signing (explicit App ID with Push, apps keep their IDs)

## What changed

- `APP_ID_CAPS`: the 25 capabilities App Store Connect's API accepted for an App ID in a real probe on the team
  (2026-11-19), with the settings three of them need (ICLOUD: ICLOUD_VERSION/XCODE_6, APPLE_ID_AUTH:
  APPLE_ID_AUTH_APP_CONSENT/PRIMARY_APP_CONSENT, DATA_PROTECTION: DATA_PROTECTION_PERMISSION_LEVEL/COMPLETE_PROTECTION).
  Not in the API: time-sensitive and communication notifications, WeatherKit, App Attest, fonts, memory limits,
  multitasking camera.
- `ensure_app_id`: also adds the missing capabilities to an App ID that already exists. Push must succeed; any other
  capability Apple refuses is logged and skipped (and tried again next start). Returns True when it changed anything,
  because a profile keeps the capabilities it was made with. `GET /bundleIds/{id}/bundleIdCapabilities` is called
  without `limit`: Apple answers a limit there with a 400.
- `heal_signing` (a background thread at start): ensure_app_id, then `profile_stale()` (profile made for another
  certificate, or its application-identifier isn't `TEAM.<BUNDLE_ID>`). Either one makes the profile again and signs
  every app again (`resign_all`). So changing `cert.p12`/`P12_PASSWORD`/`BUNDLE_ID` on the server and redeploying is
  enough; nobody has to touch Manage.
- `app_entitlements`: for an explicit App ID the keychain group is now narrowed to `TEAM.<App ID>` (it used to stay as
  the profile's `TEAM.*` + `com.apple.token`). application-identifier stays the profile's, get-task-allow false.
- `sign_ipa`: zsign gets `--rm_watch` (zsign 1.1.2 has it). App extensions are kept: zsign gives every executable in
  the bundle the same `-e` entitlements (archo.cpp: `IsExecute() ? m_strEntitleData`) and embeds the profile in each
  appex. Extensions keep their Info.plist IDs, which are prefixed by the app's own ID, as installd requires
  (`AppexBundleIDNotPrefixed`, iFizBox's R25). Notification Service extensions matter for rich and encrypted pushes.

## Decisions

- **App ID: `com.ryha.sideload`** (reused). It already exists with Push, App Groups, Associated Domains and In-App
  Purchase, and the hand-made RSideload profile is on it with the new certificate. Nothing in SideDrop conflicts:
  SideDrop deletes and makes only profiles named `sidedrop adhoc` (PROFILE_NAME), so RSideload is never deleted.
  Adding capabilities to the App ID makes Apple mark the RSideload profile Invalid on the portal. Apps already
  installed with it keep working, but downloading it again needs a regenerate on developer.apple.com.
- **iFizBox's own IPA keeps `com.ryha.ifizbox`** in Info.plist, like every other app; only the entitlements carry
  `TEAM.com.ryha.sideload`. That is what the coordinator decided: iFizBox will get its own APNs pushes, and their
  topic is the Info.plist bundle ID (team S8NFX3A2LT owns com.ryha.ifizbox). A copy renamed to the App ID couldn't
  receive them. Push delivery depends on the kept Info.plist ID plus aps-environment in the profile, not on which
  team signed. It also fits iFizBox's own rule: its IPA goes the old way only when the installed copy has another ID,
  and friends' installed copy is already `com.ryha.ifizbox` (it fitted the `com.ryha.*` wildcard). Its bundled
  `ifizbox-identity.plist` now carries the Push profile, so iFizBox's on-phone signing (Keep Bundle IDs on) gets Push
  too.

## Risks not verified on a phone

- An app installed under the old wildcard with an ID inside `com.ryha.*` (in practice iFizBox) keeps its Info.plist ID,
  but its application-identifier changes from `TEAM.com.ryha.ifizbox` to `TEAM.com.ryha.sideload`. installd has a
  `MismatchedApplicationIdentifierEntitlement` check ("Upgrade's application-identifier entitlement string ... does not
  match installed application's"), so the update may be refused. Then delete the old copy and install again.
- Apps that used to be renamed into `com.ryha.*` (YouTube as com.ryha.youtube, ...) now install as separate apps
  under their real IDs. The old copies keep opening until the old certificate expires (2027-10-29; never revoke it).
- Extensions signed under the main app's application-identifier: R25 says that should work, but nobody has tried it
  on a phone.

## Finding: the new cert.p12 doesn't open in zsign

`~/sync/default/signing/rsideload/cert.p12` (a Keychain export) encrypts its certificate bag with
pbeWithSHA1And40BitRC2-CBC. The static musl zsign 1.1.2 in the image can't load OpenSSL's legacy provider and fails:
"Can't load p12 or private key file". Python's cryptography opens the file, so SideDrop's upload checks accept it.
For the deploy, the same key and certificate were repacked, with the same password, as 3DES/SHA1 PKCS#12 (what
`make_certificate` writes, and what every iOS opens). Follow-up queued: repack such uploads automatically.

Local check with the real zsign 1.1.2 binary, the repacked p12 and the RSideload profile: PartyBoard signed with
CFBundleIdentifier `com.mariopartyrd.partyboard`, application-identifier `S8NFX3A2LT.com.ryha.sideload`, keychain
group narrowed, aps-environment production, get-task-allow false.
