# F7: Apps page header like iFizBox's Home

## What I did
- `app.py`: replaced the Apps tab's `.splash` markup with `.hd` (57px icon 16px in, radius 12, shadow 0 1px 3px; "Welcome to sidedrop" 21/26px over
  "by Ryan Hayden (Fizlo)" 17px, the name one bold #586c90 link with a white emboss; the word block centred in the space to the right of the icon,
  its lines flush left) and `.hx` tiles (43px, 10px between rows, #999 1px edges, 8px corners, 29px glyphs, bold 17px labels, grey chevron):
  - row 1: an outlined pair with no fill: GitHub (#333, `</>`) | iFizBox (#1a82fb, `go('ifizbox')`).
  - registered: Changes (red clock, `go('changes')`) + Sign IPA (purple pen: Settings tab, then scrolls to `#sign`); green `Registered` tile
    (#eefff0) with "until <date>" from `stats[1]` (left out when the profile has no ExpirationDate), opening Settings.
  - not registered: Help (grey ?, Settings tab scrolled to its Help section, which got `id=help`) + Sign IPA; yellow `Set up this iPhone` tile
    (#fff8e1, edge #c9a74a, orange phone) with "2 steps, then every app unlocks". It toggles `<div id=setup hidden>`, which wraps the existing
    SDP + Register steps unchanged (the old "First, set up this iPhone" heading went: the tile says it). `nudge()` (the 🔒 buttons) now unfolds
    it first via the new `setupOpen()`; the chevron turns down while open (`aria-expanded`).
  - dark mode: every tile takes the existing dark tile gradient and #0d0e10 edges; row 1 stays unfilled.
  - tiles reuse `.tile`, so the existing press highlight (blue) works; `.hx` rules override its sizes.
- Kept the `.splash` CSS: the iFizBox tab's header still uses it (the brief said replace it, but deleting it would break that tab).
- `test_app.py`: the not-registered check looks for "Set up this iPhone"; new asserts for the header, both tile sets, and the fold.

## Screenshots (390 px wide, 2x, headless Chromium, empty app list)
`reg-light.png`, `reg-dark.png`, `unreg-light.png`, `unreg-dark.png`, here. Made with a scratch server that stubs login, enrolment and a
profile expiring Nov 18, 2027 (dark via `--force-dark-mode`, which the page's prefers-color-scheme fallback follows).

## Tried and failed
- The first scratch server stubbed `threading.Thread.start` (as test_app.py does) and Flask's threaded dev server then answered nothing;
  restoring it after `import app` fixed it.

## Not verified
- Taps: headless screenshots can't click, so the setup tile's unfold, `nudge()` unfolding it, and the Help/Sign IPA scroll targets were not
  exercised in a browser (only read, and the markup asserted in test_app.py).
- On a real iPhone (Safari / Home Screen): not checked, no device session in this unattended run. `:has()` (detail spacing) needs iOS 15.4+;
  the page already relies on it for the switches.
- The Apps tab with apps in the list and with iFizBox present: the screenshot data had none; the list markup is unchanged.
