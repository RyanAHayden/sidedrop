# F18 Themes like iFizBox's

## What changed
- Settings > Display: the Dark Mode switch is gone. In its place are three checkmark lists (role=radiogroup): **Mode** (Light / Dark / Automatic),
  **Light Theme** (Classic, Sepia, Solarized) and **Dark Theme** (OLED Black, Gunmetal, Midnight, Linen, Nord, Dracula). Each theme row has a
  small swatch (its bar colour over its table colour). The checked row turns `--acc`, as on iOS 6.
- `THEME_BOOT` (app.py) replaces the old `theme()` script and runs in `<head>` before the CSS. It sets `<html data-theme data-palette>`, keeps
  the `.dark` class on dark pages (every existing `.dark` rule still keys on it), and sets `meta theme-color` from iFizBox's THEME_COLORS table.
  Storage: `localStorage.mode` / `lightTheme` / `darkTheme`. The old `localStorage.dark` 1/0 is read as Mode Dark/Light until a Mode is picked;
  picking a Mode then removes the old key.
- `PALETTES` (app.py): one string of sidedrop's own CSS variables per palette, with values copied from iFizBox's ios6.css and palettes.css
  (no iFizBox file is imported). `THEMES_CSS` writes them at the end of the main sheet. Classic doubles as `:root` and Gunmetal as `html.dark`.
  Every fixed gunmetal colour in the `.dark` rules (tables, rows, fields, grey buttons, GET, steps, switches, Cydia list, warnings, Manage's
  cert warnings), plus the light chrome that changes (body text, cards, ground, nav bar buttons and their pressed look, the back arrow,
  the Cydia section header, the tab bar), now reads a variable.
- Back arrows: `back_arrow()` recolours sidedrop's own static/back.svg into a data: URL per palette. Classic and Gunmetal keep the static files.

## Decisions (unattended run, nobody asked)
- **Default Mode is Automatic**, not iFizBox's Light. Before this change sidedrop followed the phone unless the switch was used, so
  Automatic keeps everyone's tone the same. Dark pages now default to OLED Black (as the brief asks) instead of Gunmetal.
- Mode is a checkmark list, not iFizBox's segmented control: sidedrop has no segmented control, and the brief asks for checkmark rows.
- Picking a theme of the tone that isn't showing also switches Mode to that tone (iFizBox's F231), even from Automatic, so the pick shows
  at once. There's no live preview pane (iFizBox's F215): not in the brief.
- The kit's colours that iFizBox's light palettes also keep (blue/green buttons, alerts, the black tab bar, status panels) stay as they are
  in Sepia and Solarized.
- Gunmetal keeps sidedrop's own values (5px/7px pinstripe, black status bar), not iFizBox's gunmetal, so it looks exactly as before.

## Checks
- test_app.py: the nine palettes in order, each with its CSS block and Settings row; each palette sets every token its tone's default sets;
  the boot script comes before `<style>`. The boot script also runs in node (vm, with fake localStorage, matchMedia, `<html>` and meta) over
  defaults, migration of the old key (1 and 0, and a picked Mode winning over it), Automatic on light and dark phones, unknown values,
  a dark name in the light slot, and every palette's theme-color. The full gate passes.
- Screenshots (`shots.py`, on readme_shots' demo data): sheet-settings.png, sheet-apps.png and sheet-iphones.png, with one column per theme
  in PALETTES order. The script also checks data-theme, data-palette and theme-color on every page. A first run showed every menu row in
  link colour (the rows are `<a>`), fixed with `.ck{color:var(--text)}`.

## Not verified
- **On a real iPhone / Safari**: only headless Chromium was used. Safari's top-bar tint from theme-color, the Home Screen app's status bar,
  and the `mask` checkmark on old WebKit (iOS 15, which has `-webkit-mask`) were not looked at. The T490/iPhone 7 setup wasn't used in
  this unattended run.
- **Automatic following a live appearance flip** (the matchMedia change listener re-running theme() and themeMarks()): only the boot
  logic was tested, with the flip as an input. The event itself was not fired in a browser.
- **Pressed states in each palette** (held bar buttons, held back arrow in light palettes, held switch knob) were not shot.
- **Pages other than Settings, Apps and iPhones** (Changes, Install steps, the setup splash, Signing, Passwords, Files, Sources, alerts) were
  not shot in every theme. They use the same variables, but some light-only colours there are still fixed kit colours.
