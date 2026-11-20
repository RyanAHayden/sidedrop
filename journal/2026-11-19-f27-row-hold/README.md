# F27: hold an Apps row for its options; GET's arm-then-confirm by state

## What changed (app.py)

**Server**: `POST /installed/mark` (`mark_app`), fields `name`, `do` (`installed` | `forget`) and `csrf`. `installed` records the
signed IPA's current version in INSTALLED (`data/installed.json`, `{udid: {app: "short/build"}}`), the same thing an INSTALL tap does;
it serves both Mark as Installed and Mark as Updated. `forget` drops the app from this iPhone's entry (Mark as Not Installed). Refused
(403) unless: signed in, a valid device cookie, that iPhone is in the profile (registered), the name is a signed IPA, and `csrf` matches.

CSRF: friends' sessions carry no `csrf` (only the admin's does), so the token is `mark_csrf(udid)`, an HMAC of the device's UDID under
SECRET. The page renders it on the sheet (`#mkSheet data-csrf`). A page drawn for one iPhone can't mark another: the token must match the
device cookie the request carries. The device cookie is also httponly + SameSite=Lax, as before.

**Page**: an iOS 6 UIActionSheet (`.mks` / `.mkp`, default style: blue-grey panel sliding up, white glossy 46px buttons with bold black
titles, dark Cancel, blue pressed state). Only rendered for a registered iPhone. Items by row state (`mkState` / `mkItems`):
- update (`.row.up`): Mark as Updated, Mark as Not Installed
- installed (`.get.done`): Mark as Not Installed
- not recorded: Mark as Installed
- always Cancel (tapping the dim area also cancels)

Hold: pointer events (touch and mouse), 500 ms with less than 10 px of movement and no scroll; the click that ends the hold is eaten in
capture (so the GET/INSTALL link and the first-run hook never see it); `-webkit-touch-callout:none` on unlocked rows so iOS doesn't show
its link callout. The row takes the cell selection (`.row.held`, `var(--select)`) 100 ms into the touch (not when the touch starts on the
button, as a UIKit cell doesn't highlight for its accessory button) and keeps it while the sheet is up. After a mark the page calls the
existing `refreshIn()`, which swaps the Apps tab in from a fresh `/` and recounts the tab badge, so the badge, blue UPDATE and button label
come from the server. Locked (unregistered) rows don't hold. The iFizBox card is a `.row` with a `.get[data-app]` in `#t-apps .g`, so it
gets the same sheet.

**Also (arm-then-confirm)**: `arm()`: UPDATE (`data-arm=UPDATE`) installs on the first tap; INSTALLED arms as a green REINSTALL (second tap
installs); GET still arms as INSTALL. `disarm()` already restores `data-arm`'s label.

## Tests (test_app.py)
- Each mark changes installed.json and the page: Mark as Updated (badge hidden/0, no "Update available", grey INSTALLED button), Not
  Installed (GET), Installed (INSTALLED), and forgetting an update takes it off the tab count.
- Refused: no session, signed in without a registered iPhone, empty/wrong csrf, an unregistered device, this iPhone's csrf with another
  registered iPhone's token and the reverse, a bad action or app name. installed.json is unchanged after each.
- The other registered iPhone marks only its own entry; the sheet isn't rendered for an unregistered phone.
- The iFizBox card: forget gives the green INSTALL back, installed the grey INSTALLED.
- In node: `arm()` for GET / INSTALLED / UPDATE (labels, green, whether it installs on the first tap) and `mkItems(mkState(row))`.

## Checked by hand
`hold.py` here (run: `uv run --no-project --with-requirements requirements.txt --with playwright python -I hold.py <repo> <outdir>`)
serves the page for a fake registered iPhone and holds rows in Chromium with touch emulation: a 200 ms hold opens nothing, 700 ms opens
the sheet with the right items for each state, each mark updated the button and the badge without a reload, Cancel closed it and the row
lost its highlight. `sheet-Beta.png` is the update row's sheet. The page logged `themeMarks is not defined` at load; that was there before
this change (not from F27) and I left it.

## Tried and failed
- Named the hold timer `mkT` and the sheet title element `id=mkT`: the `let` shadowed the element. Renamed the element `mkH`.
- The node test used `subprocess.run`, which the test file stubs for zsign; switched to `Popen` as the theme test does.

## Not verified
- On a real iPhone (iOS Safari / Home Screen app): the hold timing next to a scroll, that `-webkit-touch-callout:none` stops the link
  callout on the GET button, and the haptic. No phone here for this repo; Chromium touch emulation only.
- WebKit rendering of the sheet: I only checked it in Chromium.
