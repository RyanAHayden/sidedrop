# TODO — open tasks, in order

### Next

- [ ] **F14** Files tab back in the bottom tab bar when there are files: when the admin has uploaded any Files for Friends (shared_files() non-empty), the tab bar shows a Files tab (iOS 6 tab icon in the same style as the others, e.g. a document/folder glyph) that lists them, as the old Cydia-style Files tab did (git show aecf367 for the original), instead of the Files section on the Apps tab. No files: no tab, and the bar stays as it is now (grid columns follow the number of tabs). #files hash and the Home Screen links keep working. Check: test_app.py: no files -> no Files tab; a file -> the tab and its row, and the Apps tab no longer lists it. | files: app.py, test_app.py | after: F13
### Parked

- [ ] **F8** (follow-up, later) Dark Mode as iFizBox's OLED Black (its default dark palette since F198, 2026-11-18): black ground, bars and tab bar, near-black tables, no pinstripe or emboss; gunmetal (sidedrop's current dark) kept or dropped as the user picks. Token values in ~/repos/iFizBox/web/app/ios6.css html[data-theme=dark]. Left out of F5 because it changes the whole dark look, not one control | files: app.py
