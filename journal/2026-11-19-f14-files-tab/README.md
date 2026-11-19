# F14 Files tab back when there are files

What changed (app.py, test_app.py):

- The Files for Friends list moved off the Apps tab into its own `section.page#t-files` ("Files"). It is drawn
  only when `shared_files()` isn't empty. The rows are the same as before (name, size, `download` link signed
  for 7 days), with the same wget/curl footer.
- The tab bar gets a Files tab between iFizBox and Settings, only when there are files. Its icon is a folder
  silhouette on the same 30×30 viewBox, filled by the shared `#taboff` gradient like the others (the old
  aecf367 tab also used a folder). `.tabs` went from `grid-template-columns:repeat(4,1fr)` to
  `grid-auto-flow:column;grid-auto-columns:1fr`, so the columns follow the number of tabs.
- `#files` works without any JS change: `show()` opens `t-files` when it exists and falls back to Apps when
  there are no files. Old Home Screen links (`#more` and the rest) are untouched.
- Reload (`refreshIn`) swaps the Files tab's list in place along with the others. If the tab appears or goes
  away (the admin uploaded the first file or deleted the last), it reloads the whole page, because the tab bar
  changes.
- Updated the wording on the Manage Files page ("Listed on everyone's Files tab.") and the `FILES` comment.

Tests: no files → the 4 tabs and no `id=t-files`. A file → tabs apps, changes, ifizbox, files, settings; the
file's row is inside `t-files`, not inside `t-apps`.

Tried that failed: the old assert `"t-files" not in html` started matching the new `getElementById("t-files")`
in the Reload script, so it now checks for `id=t-files`.

**Not verified**

- How the 5-tab bar and the folder glyph look on a phone or in a browser. This run has no screenshot step, and
  the iPhone 7 test rig isn't part of an unattended run. Each tab is now 1/5 of the width (64pt on a 320pt
  screen), which is what Cydia's 5-tab bar had, so the labels should fit. That is untested.
- The Reload path where the tab appears or goes away (full reload) and the in-place swap. These are browser
  JS, and the gate only renders HTML.
