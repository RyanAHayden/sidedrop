# B5: pressed look on plain action buttons

## What was wrong
- Plain blue buttons outside a `<form>` (Copy Link on Invites, both copies) had no held rule: the blue pressed look was only
  `form button:not(.grey):not(.act).is-pressed`.
- In dark themes grey buttons (Share, Make New Link, any `button.grey`/`a.b.grey`) never changed while held: `.dark button.grey` (0,2,1)
  comes after `button.grey.is-pressed` (0,2,1) and won.
- Pressed looks came only from `touchstart`, so holding the mouse in a desktop browser showed nothing.

## What I did (app.py PAGE css + press script, test_app.py)
- `:where(button:not(.grey,.act,.gbtn,.get,.tile,.bar,.ok,.mkc,.confin)).is-pressed` gets the form buttons' blue press
  (PurchaseButtonBluePressed). `:where` keeps it at one class of weight, so `.seg`, `.alert .abtns`, `.mkp`, `.nav .bar`, etc. still win.
  Blue buttons look the same in dark themes, so this one rule covers both.
- `.dark a.b.grey/.dark label.b.grey/.dark button.grey.is-pressed`: iFizBox's dark button press, `--dk-btn-pressed`, which is each dark
  palette's `--barpress` here (identical values), border `--barpe`, a slight inset shadow.
- Mouse: `pointerdown`/`pointerup`/`pointermove` for `pointerType=="mouse"` set and clear `.is-pressed`, the same class the touch path uses.
  Not `:active`: the existing test forbids it (iOS keeps `:active` stuck after a touch turns into a scroll), and touch pointer events are
  ignored so the touch path is unchanged.
- Tests assert the three pieces.

## Checked
- Gate passes.
- Headless Chromium (system /usr/bin/chromium via Playwright; the cached Playwright WebKit build didn't match the installed version) with the
  page's real CSS and press script: holding the mouse on Copy Link, Share and a segment in Classic, Gunmetal and Midnight adds
  `is-pressed` and darkens each; the segment keeps its own `--segp` press (not overridden by the new rule).

## Not verified
- On the iPhone itself: no phone access from this unattended run. The touch path is untouched and uses the same class, so the CSS
  above should apply there too.
- Not every dark palette (checked Gunmetal and Midnight; the others use the same variables).
