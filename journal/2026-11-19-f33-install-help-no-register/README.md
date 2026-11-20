# F33: An App Won't Install drops its registration steps

## What I did
- Help › Problems › **An App Won't Install** (`HELP` in app.py) now has two steps: delete a half-installed
  grey icon and tap GET again; installed but won't open → Developer Mode below.
- Dropped step 1 ("Settings should say this iPhone is Registered…") as the task asks, and also step 2
  ("Registered before but the apps are locked? Register again"). Why: same premise — locked apps have no
  Install button, so someone reading "an app won't install" after tapping Install is registered. That
  re-register hint still sits on the Register card itself (app.py, under the enroll form), where a
  locked user actually lands, so nothing is lost.
- test_app.py: the Install section has exactly those two steps and no "register" wording.

## Tried and failed
none

## Not verified
- Not looked at on a phone: text-only change in an existing `<ol>`; the gate checks the rendered HTML.
