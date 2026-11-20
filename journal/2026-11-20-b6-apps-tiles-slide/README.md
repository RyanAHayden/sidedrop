# B6: Apps tab tiles slide, like iFizBox's Home

## What changed
- **Help tile** (`onclick="return helpOpen(null,this)"`): `helpOpen(id,from)` no longer calls `go("settings")`. It pushes /help over
  whatever tab is showing, the way iFizBox's Home pushes its Help. Back says that tab's title (SideDrop on Apps) and goes back to it.
  `from` is the tile, so it turns blue while the page loads and fades out on Back, like a Settings row. The Help row on Settings is
  still a `data-push` row, so nothing changed there. `helpOpen("dev")` from the Developer Mode alert pushes over the tab showing and opens that item.
- **Registered tile**: now `href=/this-iphone data-push`. It pushes a new **This iPhone** page (`/this-iphone`, `THIS_IPHONE` in app.py)
  over Apps. The page shows Settings' status rows (Status, Apps Work Until), then Name (the ASC device's name from the saved device list) and Model
  (`device_model`, the same value the version line uses). Without JS it is a full page whose back button goes to `/#apps`. Signed out, it redirects to `/`.
  No other Apps tile jumps with `go()`; iFizBox is left out on purpose, as the brief says.
- **Pages on more than one tab**: before this, every pushed page sat on Settings. Now Apps (and any tab, through helpOpen('dev')) can have its own.
  The new `tabTop(t)` returns the top pushed page of a tab. `open()` and `close()` slide against that page instead of the global top `L`, so Help on Apps
  with Theme still pushed on Settings slides over the Apps tab and says "SideDrop". The data-push click handler checks the open tab's top page.
  Tapping the open tab again goes back to that tab's root with `history.go(-k)`, which also drops any other tab's pages above it in history.
  A form inside a pushed page that isn't the global top falls back to a normal submit, so it can't overwrite another tab's page.

## Checked
- Test gate (`test_app.py`): passes (`ok`). The old asserts on `helpOpen()` and `helpOpen(id)` now expect the new signature. New asserts cover the tile's
  `data-push` href, the absence of `go('settings')` on the page, the /this-iphone page (title, back to `/#apps` "SideDrop", Status and Model rows) and its redirect when signed out.
- Chromium at 390 px (`slide.py` here; run: `uv run --no-project --with-requirements requirements.txt --with playwright python -I slide.py <repo> <outdir>`).
  It samples the page every 70 ms after each tap:
  - Help tile: the layer's left edge went 311 → 91 → 20 → 1 → 0 px, so it slid in from the right. The Settings section was hidden at every sample and the hash stayed on Apps.
    Back said "SideDrop", the layer went 131 → 325 → 375 → 390 and was then removed, and Apps was showing again.
  - Registered tile: the same slide in and out. Rows: Status Registered, Name Sam's iPhone, Model iPhone 15 Pro.
  - Help from Settings: pushed over Settings, Back says "Settings".
  - Theme pushed on Settings, then Help from Apps: Help's Back said "SideDrop" and went back to Apps, and Theme was still on Settings. Tapping Settings again popped Theme.
  - `helpOpen('dev')` on the iFizBox tab: pushed over iFizBox (Back "iFizBox"), with Developer Mode open.
  - No page errors.

## Not verified
- On a real iPhone (Safari, or the Home Screen app with iOS's edge swipe): this session has no phone. Only Chromium touch emulation was checked.
- The "Apps Work Until" row on /this-iphone in the browser: the fake server has no profile, so `stats` is None. The row uses the same template line as Settings' row.
- Forward (redo) after Back on a page pushed from Apps: it reopens on whichever tab is showing, as before. I didn't test it.
