# TODO — open tasks, in order

### Next

- [ ] **F11** iPhones page: no separate 'Disabled' group (user: don't move turned-off iPhones to a different category). F10 split them out (app.py ~1946 'off' list, and the same split in the /admin/devices.json refresh JS). Keep one list in its current order; a turned-off iPhone stays in place with its switch OFF and the row greyed (name and subtitle). Flipping a switch doesn't move the row. Keep the 'N of 100 slots used' footer. Check: test_app.py renders a disabled device in the same group as enabled ones, and the page has no 'Disabled' header. | files: app.py, test_app.py
### Parked

- [ ] **F8** (follow-up, later) Dark Mode as iFizBox's OLED Black (its default dark palette since F198, 2026-11-18): black ground, bars and tab bar, near-black tables, no pinstripe or emboss; gunmetal (sidedrop's current dark) kept or dropped as the user picks. Token values in ~/repos/iFizBox/web/app/ios6.css html[data-theme=dark]. Left out of F5 because it changes the whole dark look, not one control | files: app.py
