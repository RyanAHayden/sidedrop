# B18: the Apps row's hold sheet as iFizBox's action sheet, sliding away

## What changed
- **Look** (app.py, the `.mks`/`.mkp` CSS after F27's comment): replaced the guessed sheet (two-stop glosses, a blue-grey panel with a
  white top line) with iFizBox's values, copied from `~/repos/iFizBox/web/app/packages.css` `.action-sheet` (sampled there from the 4S's
  UIAlertSheet* art; no file shared, per the projects-stay-independent rule): the panel's 1pt #3f4347 edge + half-point white +
  #acb1b9→#5c626d at 84%, 21px padding and 11px gaps, 44pt buttons with the ten-stop UIAlertSheetDefaultButton gloss and the inward-fading
  edge shadow, the blue …ButtonPressed, the dark Cancel after a wider gap (11+3 = iFizBox's 14px margin) and its pressed look, 13px title.
  Dark themes get iFizBox's Black style (UIAlertSheetBlack* panel, button and Cancel). Pressed states use sidedrop's `.is-pressed` (the
  gate forbids `:active`).
- **Motion**: rise .35s on iOS 6's `ease` curve (iFizBox's SHEET_IN), with the dim on its own layer (`.mkd`) so it fades by opacity only,
  as iFizBox's `.action-dim`. `mkClose()` now adds `.out` (sheet slides down .25s, dim fades .25s, as iFizBox's close) and hides the sheet
  250 ms later by a timer (not `animationend`: under prefers-reduced-motion the page turns animations off and no event would come). The
  held row lets go at once. A second close during the slide is a no-op; `mkOpen` clears a pending hide. A tap on the dim (`.mkd`) closes,
  replacing the old `event.target==this` check on the scrim.
- **test_app.py**: the new markup (`.mkd`), the panel/button gradients, the `.out` animations and the dark panel; and a node test of
  `mkClose`: `.out` at once and not hidden, the row released, one 250 ms timer, a second call adds nothing, hidden and `.out` cleared
  after the timer.

## Checks
- Gate passes. First run failed: I had copied iFizBox's `:active` selectors, which sidedrop's test bans (iOS keeps `:active` on a control
  after a touch turns into a scroll); removed them.
- `shots.py` (Chromium, 375×667 @2x, touch, a registered fake iPhone with one signed app): hold the row 700 ms → sheet open
  (`light-open.png`, `dark-open.png`); tap Mark as Installed → sampled every ~60 ms: panel top 498 → 548 → 648 → 665 px with the dim at
  1 → .94 → .57 → .21, then hidden (`light-closing.png` mid-slide, `light-closed.png` after; the row now says INSTALLED). No page errors.

## Not verified
- On a real iPhone: no phone reachable from this unattended run (the iPhone 7 is a person's device). Chromium's mobile emulation stands
  in; WebKit timing and the 84% panel over the tab bar on iOS Safari are not seen.
- Pixel comparison against iFizBox's own sheet on a phone: not done; the values are iFizBox's CSS copied as written, and the screenshots
  were checked by eye only.
- Dark theme dismiss: only the open state was shot in dark; the slide-away CSS is theme-independent.
- Escape to close (iFizBox has it): not added, not asked for.
