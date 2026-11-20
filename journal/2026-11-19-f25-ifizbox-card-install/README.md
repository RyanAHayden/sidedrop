# F25: iFizBox's card on Home installs in one tap

app.py, the Home (`#t-apps`) iFizBox card:

- **No footer**: the `<p class=ftr>Installs apps right on your iPhone. Why iFizBox</p>` under the card is gone (the iFizBox tile at the
  top and the tab bar still lead to the page).
- **Green INSTALL**: the button is `class="get go"`, the iOS 6 App Store's armed green INSTALL (`.get.go` + `.get:before`'s
  `--greenbtn`, the same gradient as the page's `button.gbtn`). Labels: INSTALL when this iPhone never installed it, UPDATE (still
  green) when a newer one is signed, INSTALLED (`get done`, grey) when current: the same `mine` logic as before. The row keeps `.up`
  and the red dot (F24) for an update; the blue `upd` is gone from this button since the task wants the green one.
  Dark themes: `.dark .get` comes later in the CSS and greyed the label, so `.dark .ifzr .get.go` sets it back to white; the same
  greying hits every armed INSTALL row in dark, filed as **B3** (low) rather than changed here.
- **The line**: `<small class=rec>Recommended: get update alerts and install more apps</small>`. The version moved after the name
  (`iFizBox 2.4`, grey). Measured in headless Chromium with Apple's Helvetica Neue (what the page's font stack names; fc-match picks
  the copy in ~/.local/share/fonts/apple), the line at 13px is 323px wide; beside the icon there are only 273px at 375pt, so the row is
  a grid (`.ifzr`): icon, name, button on the first row, the line across the whole row (333px) on the second. One line, with an
  ellipsis on narrower screens (320pt) rather than wrapping. I chose this over shrinking the font to ~11px.
- **One tap**: `onclick="return ifzGo(this)"`. `ifzGo` sets `ifzAuto=1`, calls `go("ifizbox")` (synchronous: replaceState + a
  dispatched hashchange), and a second hashchange listener (after `show`) runs `ifzRun()` once when `ifzAuto` is set and the page is
  ifizbox, clearing the flag. Everything happens inside the tap, so Safari still treats `location.href=itms-services…` as user-initiated.
  `ifzGo` clears the flag again afterwards and turns the card's button grey INSTALLED (ifzRun's `mark()` adds `done` but leaves a
  `.go` button's text alone). Coming back to the page later (tab, link, reload of #ifizbox) doesn't run it: the flag is gone.
- Not enrolled: unchanged (the 🔒 that calls `nudge()`).

Tests (test_app.py, after the iFizBox tab asserts): the card has no "Why" and no footer, has the line, the `get go` INSTALL with
`ifzGo(this)`; the green is `--greenbtn`; the script has the once-only flag listener and `ifzGo`; after `/installed` the card is the
grey INSTALLED without `go`. Gate passed locally.

`shots.py` (readme_shots' demo data, viewport 375x667, 3x) wrote `after/`: the card and the page in Classic and OLED Black, and the
page after a tap. Its tap check printed: hash `#ifizbox`, ifzRun ran **1** time, the console open, the card INSTALLED; then
Apps and back to iFizBox: still 1 run, console closed.

Tried and failed: the first layout kept the line under the name only (beside the icon): it measured 323px in 273px and cut off.
The first tap check counted 2 runs: Playwright's `evaluate` called the wrapper function my expression returned; ending the
expression with `;0` fixed the count (not an app bug: the stack showed the second call came from the evaluate).

## Not verified

- **A real iPhone / Safari**: headless Chromium only, no phone in this unattended run. In particular, that iOS Safari shows the
  itms-services install prompt from `ifzRun` when it runs inside the card's click via the dispatched hashchange (it is synchronous in
  the same tap, as the page's own button is, but only a phone can show the prompt).
- **UPDATE and INSTALLED card states on screen**: the demo data has iFizBox as never installed; UPDATE/INSTALLED are covered by the
  template logic and the gate's INSTALLED assert, not by a screenshot.
- **Widths other than 375pt** (e.g. 320pt ellipsis, 430pt) were not shot.
