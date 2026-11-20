# F20 Settings > Theme like iFizBox's

## What changed
- **Settings > Theme** (`/theme`, a pushed page with the iOS slide, back "Settings"). It copies iFizBox's Settings > Theme
  (screens/settings.js groupPage, modeControl, listPage and themePreview; core/settings.js 'appearance'; settings.css):
  - **Mode**: an iOS 6 segmented control (Automatic / Light / Dark, iFizBox's order), role=radiogroup, with iFizBox's footer.
  - **Themes**: Light and Dark rows, each showing the theme in use and pushing `/theme/light` or `/theme/dark` (back "Theme"):
    the checklist (swatches with iFizBox's colours, the current one ticked), the tone's footer, and a **Preview** of
    sample controls (nav bar with Back and Edit, a small segmented control, GET / INSTALL / UPDATE and the badge, a group with
    an icon row, a switch, a check and a subtitle, a footer). It's inert.
  - **Live preview**: while a Light/Dark list is open, the page shows that tone (`themeTone` in THEME_BOOT's `theme()`), and
    goes back to Mode's tone when the list is popped (a popstate listener, once the layer has left `LS`).
  - Picking a theme stores it and, if that tone isn't showing, switches Mode to it (as F18 and iFizBox's pick()).
  - Storage is unchanged: localStorage `mode` / `lightTheme` / `darkTheme`, the old `dark` key read by THEME_BOOT and removed on
    a pick. The server draws the defaults, and `themeMarks()` moves the checks, the selected segment and the row details to the
    stored choice as soon as the page opens.
  - `/display` (the old name) serves the Theme page too.
- **Segmented control**: SideDrop's own `.seg`, copied from iFizBox's ios6.css `.store-segmented` at settings.css's
  `.settings-segmented` size (44px, 9.5px corners, 15px). Its colours are tokens per palette (`SEG` in app.py): Classic is the kit's,
  the dark palettes use iFizBox's `--dk-seg*` / `--dk-btn-edge` / `--dk-ctl-hi`, Sepia and Solarized `--lt-seg*`. The selected blue is the
  kit's in every palette. It sets `background-origin: border-box` on every gradient.
- **Settings tab**, in iFizBox's order: This iPhone (status rows, now with tiles: status / slots / calendar), Manage or Register and
  iFizBox. Then one group with **Theme** (iFizBox's PAGE_ICONS.theme tile, indigo "contrast") and **Update Alerts** (red "bell").
  Then Help and About (Help now uses the blue "question" tile), the Help group (its three rows get lock / devMode / homeScreen
  tiles), and Sign out last. The tiles come from iFizBox's icons/rowicons.js ROW_ICONS/GLYPHS, copied into `ROW_ICONS`
  (devMode, the dark "terminal" glyph, is our pick). Row labels with a tile are bold, as ios6.css `.cell-label`.
- The Display theme lists (F18's `theme_menu`) are gone from the Settings tab. "Settings > Display" is renamed to Theme in app.py's
  comments and test_app.py. Older journals stay as they were written. README/docs never mentioned Display.

## Decisions (unattended run)
- **Preview inline, not pinned**: iFizBox pins the preview over the bottom half with a draggable divider (F215/F230). SideDrop's
  lists are short (3 and 6 rows), so the preview goes under the list as a "Preview" group. No split pane or drag.
- **Opening a list doesn't store a Mode** (iFizBox's F231 does). It only previews, as iFizBox's F199 did, so browsing the lists
  never changes anyone's saved Mode.
- Labels stay SideDrop's ("Solarized", not iFizBox's "Solarized Light").
- The nav bar, back arrow, push slide, grouped cells, headers, footers, bar buttons, switches and alerts were already F5/F18 copies of
  iFizBox's. I checked their values again (group header 23/9/7px 17px bold, footer 15/19px, table #f7f7f7 / #b7b9bd / 9.5px, the 77x27
  switch, 29px bar buttons with border-box). The only changes are the bold row labels and the 7pt/11pt tile spacing.

## Checks
- test_app.py: the Theme row and its tile in Settings, the tiles on the other rows, the group order. The Theme page: nav title,
  back link, segment values, labels and the checked segment, the Light/Dark rows and details, the footer, `/display`. Each list:
  rows in PALETTES order with the default ticked, no rows of the other tone, the preview, `themePreview("<tone>")`, back to /theme.
  Also 404 for an unknown tone and a redirect when signed out. Every palette has its segmented tokens and swatch. In node (boot
  script + page script, with fake storage and `<html>`), the preview tone on load, picks switching Mode, Mode segments dropping the
  old key, and `themeTone=null` going back. Every Theme page script passes `node --check`. The full gate passes.
- Screenshots (shots.py on readme_shots' demo data, headless Chromium, 3x at 402x874): `before/` (the Settings tab top and bottom in
  Classic and OLED Black) and `after/` (the same, plus Theme and the Light/Dark lists). Zoomed 3x crops are in `after/zoom-*.png`
  (nav, segmented, list, preview, switch). Each `sheet.png` holds the whole set side by side. Looking at the 3x zooms: no light line
  at the bottom of the segments, and the dividers turn the dark blue next to the selected one.
- One bug found in the first after-shots and fixed: the preview's nav bar was pinned to the top of the screen, because the page's
  later `.layer .nav{position:absolute}` won. It's now `.tpv .nav.nav`.

## What failed along the way
- Test: `Markup + str` escaped the str, so I compare `str(row_icon(...))`. The node block's loop variable `k` overwrote a key a later
  test uses, so the loop now uses names of its own.
- First before-shots: the dark run didn't reload (same URL, new hash). shots.py now reloads.

## Not verified
- **A real iPhone / Safari**: headless Chromium only. Not checked: Safari's `:has()` border colouring next to the selected end
  segment (iOS 15.4+), `inert` on the preview (iOS 15.5+, and `pointer-events:none` backs it up), and the edge-swipe pop clearing the
  live preview. There was no phone in this unattended run.
- **Live preview in a browser**: the case where a Light Mode page opens Dark and pops back was only run in node. In Chromium the
  shots used Mode equal to the list's tone. The popstate path that clears `themeTone` was not driven in a real browser.
- **Pressed states** (held segment, held Theme row going blue, the back arrow) were not shot.
- **Other palettes** (Sepia, Solarized, Gunmetal, Midnight, Linen, Nord, Dracula) were not shot on the Theme page. Their segmented
  tokens come straight from iFizBox's values.
- **Full-page fallback** (opening `/theme/dark` straight, without the push) was not shot. It renders through the same page() as other
  pushed screens.
