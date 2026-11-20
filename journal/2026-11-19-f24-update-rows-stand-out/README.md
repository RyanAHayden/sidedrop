# F24: Apps page updates stand out

On top of F22's update rows (`.row.up`, UPDATE label, the Apps tab's count):

- **Badge on the icon**: an update row gets `<i class="badge ub" aria-hidden=true>` after its icon (new `ubadge(a)` macro, used in
  `install_list` and the iFizBox row). It reuses the tab bar's `.badge` (iOS 6 red gloss, 2px white ring, shadow) as a 20px dot
  with no number, at the icon's top-right corner (`.row.up .ub`, absolute in the row: left 47px, 7px above the icon). I chose the
  dot over an "Update" pill: the row already says "Update available", and a dot is how the badge reads at a glance on an icon.
  It shows only under `.row.up`, so the install tap (which drops `.up`) hides it, and the script also removes it.
- **Tab bar count**: unchanged. It is still F22's `navR()`, which counts `#t-apps .row.up`: one source of truth, no new counter.
- **Blue UPDATE**: UPDATE buttons get class `upd` (both the file-bringing `<button>` and the plain `<a>`, and the iFizBox row's link).
  `.get.upd` is iFizBox's "Button (Gloss Blue)" (its Done button, `web/app/sources.css .bar-button.done`, also used for
  `.scope-filter.done`): border #1f3f86, top #30363e, `linear-gradient(#79a1f3,#3b71e1 49%,#215fdd 51%,#2361dd)` with
  `background-origin:border-box`; held (`.is-pressed`), its darker `linear-gradient(#5f86d6,#2a5bc0 49%,#164bb8 51%,#184db9)`. Same in
  light and dark, as in iFizBox. The rule is `:not(.go):not(.done):not([aria-expanded=true])`, so tapping UPDATE still arms the green
  INSTALL, an open file-steps button gets the existing sunken look, and once installed it is the grey INSTALLED (the script also drops
  `upd`). GET / INSTALLED / DOWNLOAD (`.get.blue`) are untouched.
- Tests (test_app.py, F24 block after F22's Plain update): the update row has the badge and `get upd`, only one of each on the
  page, the up-to-date Demo row has neither; the blue and pressed CSS and the script's clean-up are present. F22's Plain assertion
  now expects `class="get upd"`.

Screenshots: `shots.py` (readme_shots' demo data, where Trailhead is an update; headless Chromium at 3x) wrote `after/`:
`apps-classic.png` / `apps-oled.png` (1x page) and 3x zooms of the update row, the update row held, an up-to-date row and the tab
bar in each theme. Looked at zoomed: badge sits on the corner over both themes, blue button has no light line along its bottom
border, pressed is visibly darker.

Tried and fixed: the first shot run used `scroll_into_view_if_needed`, which left the Trailhead row under the fixed tab bar, so its
"row" zoom was the tab bar; it now centres the row first.

## Not verified

- **A real iPhone / Safari**: headless Chromium only; no phone was used in this unattended run.
- **iFizBox row with an update** was not rendered (the demo data has iFizBox as GET); it uses the same macro and class, and the
  markup is the same shape, but no screenshot shows it.
- **The file-bringing app as an update** (button + steps) was not rendered either; covered only by the gate's markup asserts.
- **Other dark palettes** than OLED Black (and light ones other than Classic): the blue and the badge use literal colours, not
  theme tokens, so they should look the same, but only those two were shot.
