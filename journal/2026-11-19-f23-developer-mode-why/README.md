# F23 Developer Mode: keep the step, say why

The task as first written (show Developer Mode only for a Development profile, read from the profile's kind) was
rewritten by the user's test on 2026-11-19: on an iPhone 18 Pro (iOS 27), Ad Hoc apps from SideDrop (iFizBox and
another app, get-task-allow false in every binary, Developer Mode off) **did** ask for Developer Mode. Apple documents
Developer Mode only for development-signed apps (get-task-allow true), so the documented Ad Hoc rule does not hold
on iOS 27, and the user's hand check is what settles it. So the step stays for every profile kind, and no profile-kind
or iOS-version detection was added (Safari's user agent freezes the iOS version).

## What I did

- `DEV_WHY` (app.py, a Jinja global next to F26's step globals): "iOS 27 asks for Developer Mode once for apps
  installed outside the App Store. Turn it on, restart, then the app opens." Shown, the same words, in:
  - the first-install sheet's lead (was "One setting, once per iPhone: apps from here open only with Developer Mode on.");
  - the Developer Mode Required alert (its second line now "Opening the app after it installs takes you there.");
  - Help > Turn on Developer Mode, above the screenshots.
- iFizBox card footer: "It needs Developer Mode, like every app here." → "iOS 27 asks for Developer Mode once to open
  it, as for every app here."
- Stolen Device Protection: F26 already took it out of the first-install sheet; it is only in Help > Register iPhone
  Didn't Work (and the Apps tab's register setup, where it belongs, since it blocks installing the profile). Nothing
  to change; the existing F26 test already asserts the sheet has no SDP.
- `app_entitlements` docstring: the wildcard → development-profile match may still be true, but it read as if
  narrowing avoids Developer Mode. Added that iOS 27 asks for it for these Ad Hoc apps anyway.
- README Limits: Developer Mode bullet said only App Store, TestFlight and enterprise apps are exempt; now says Apple
  documents it for development-signed apps only, iOS 27 asks for Ad Hoc too, so the page always shows it.
- Tests: the sheet, the alert and Help carry `DEV_WHY`; the old wording is gone.

## Tried and dropped

- Nothing failed. The profile-kind detection from the original brief was not built: the user's test made it wrong.

## Not verified

- On a phone: the new text was not looked at on an iPhone (no phone attached to this unattended run); it is plain
  text in existing elements, so layout should be unchanged.
- That iOS 27 asks "once" per phone: taken from the user's report, not checked here.
- docs/developer-account.md and docs/become-a-distributor.md already say to turn on Developer Mode when iOS asks;
  left as they are.
