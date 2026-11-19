# F5: Bring over iFizBox's UI improvements

## How I compared
sidedrop's last look ports from iFizBox were on 2026-11-17/18 (pressed art, scroll box, F204 reload bar). I went through
`git log --since=2026-11-17` of `~/repos/iFizBox/web/app/{ios6,style,settings,sources,home}.css` (the brief's path
`~/repos/iFizBox web/app` doesn't exist; it is `~/repos/iFizBox/web/app`) and diffed its rules against sidedrop's inline CSS in `app.py`.

## Ported (all in `app.py`)
- **Nav bar buttons**: 29pt high, line-height 27, padding 0 9, min-width 50, long labels end in "…", and
  `background-origin: border-box` (on the pressed look as well). Without it the gradient tiles into the 1px border and a light line shows along the bottom.
- **Back button**: `inline-block` with line-height 28, so a long label ends in "…" (`text-overflow` did nothing on the old `inline-flex`).
- **Nav title**: bold, shadow .5, long titles end in "…" (`max-width: calc(100vw - 180px)`).
- **Alerts** (iFizBox sources.css, B32): the scrim is one grid column the screen's width, so long text can't push the box off screen.
  The box is 340pt wide (was 284) with padding 16/12/11, navy `rgba(11,27,67,.8)`, a 2px rim and shadow `0 8px 19px .9`. The gloss is
  the curved radial one over the top 31px. Titles are 18/22, messages 16/20, and both wrap anywhere. Buttons are 18pt with a .8 shadow and
  end in "…". The scrim is iFizBox's radial one and fades in over 200 ms. The pop is the iOS bounce: scale 1.15 → .95 → 1.02 → 1 in 360 ms.
- **Spinners** (F166): hold keyframes, one 30° spoke per 1/12 of the cycle, instead of `steps(12)`, which stands still on iOS 15. Used
  by the reload bar's spinner. The busy Changes badge now holds the white 4S UIActivityIndicatorView spokes (iFizBox's
  `--spinner-white`) instead of a spinning border ring.
- **Pressed states**: tiles (Settings and the Apps header) use iFizBox's cell selection `linear-gradient(#85a7e9,#2765db)`, the kit's
  "Button (Matte Blue)", in light and dark. Before, dark tiles never showed it because `.dark .tile` came later and won.
  Table rows now take the same blue with white text and chevron while held: file links (`.g a.row`) and Help rows (`.g details>summary`),
  both added to `PRESS`.
- **Settings rows, row icons** (F205): `.tic` is a flat 29pt tile with 6pt corners, no gloss or shadow. Split/pair tiles put it 7pt from
  the edge with the label 11pt after. The inline gradients became flat colours from iFizBox's rowicons.js palette (orange #f08b1d,
  blue #3f80e0, green #40ae4c, red #e2382f, grey #8c9097). Sign IPA and Help match the Apps header's purple and grey.
- **List subtitles**: `.row small` is 14px #7f7f7f, iFizBox's `.cell-subtitle` (dark: #8b9099).
- **No focus ring** (iFizBox, user 2026-11-18: iOS 6 draws none). The yellow `:focus-visible` outline is gone.
- **`a, img { -webkit-user-drag: none }`** (B24): holding a link row or image no longer lifts WebKit's skewed drag preview.
- **Scroll indicator**: `transition: width .1s` when grabbed, `will-change: transform`.

## Compared, nothing to port
- Tab bar art, badge, switch (size, colours, held knob, drag), nav bar art, grouped table, group header and footer: already the same
  as iFizBox's.
- Red bar button (F218), segmented control, share sheet, banner, undo bar, placeholders, theme preview: sidedrop has no such control.
- Dark palette: iFizBox's default dark is now OLED Black (F198). That changes the whole dark look, not one control, so I filed it as
  **F8** (`later`) instead of doing it here.
- Reload bar spinner art: I kept sidedrop's inline SVG spokes and only fixed the animation.

## Screenshots
`before/` (HEAD 66c9cf3, a temporary worktree) and `after/`. 390px wide at 2x in headless Chromium, light and dark. Playwright's requests
were answered by Flask's test client: logged in as admin, enrolled, three fake apps, profile until Nov 18, 2027.
- `apps-*`, `settings-*`: row icons, tiles, subtitles, bar buttons
- `pressed-*`: Manage tile, Reload bar button and first Help row held (`is-pressed` set by script)
- `alert-*`: the About alert
- `manage-light`: a pushed page's back button

## Tried and failed
- The first run caught the push-permission alert fading in over the About alert and the pressed shot. The script now waits 1.5 s and
  hides every scrim first.

## Not verified
- **On an iPhone**: no device in this unattended run. Not checked: the hold-keyframe spinner actually turning on iOS 15, alert
  bounce timing, `-webkit-user-drag` on a held row.
- **Touch**: pressed looks were set by script, not by a finger. Headless Chromium's touch emulation doesn't cover the `PRESS` handler's
  touchstart/move paths. The handler is unchanged except for the two selectors added to `PRESS`.
- **Alert animations**: screenshots show only the end state.
- **Long back-button labels**: every pushed page's label is short ("Settings"), so the "…" path wasn't shown.
- `test_app.py` passes (gate run on this tree). It checks markup, not CSS.
