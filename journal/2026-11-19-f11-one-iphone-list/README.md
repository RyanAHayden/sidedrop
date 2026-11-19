# F11 iPhones page: one list, no 'Disabled' group

What changed (app.py):
- `DEVICE_LIST` draws every device in one `<div class=g>`; the `on`/`off` split and the `Disabled` header are gone.
  A turned-off row gets `class="row drow off"`, and `.drow.off .dl{opacity:.45}` greys its name and subtitle (the switch
  keeps full opacity, so OFF reads clearly). The "N of 100 slots used" footer is unchanged.
- `device_rows` sorts by added date only (newest first). It used to sort turned-off iPhones last, which would have moved a
  row to the bottom after the list was redrawn from the switch's answer, even without a separate header.
- The /admin/devices.json refresh JS only puts the server's HTML in place, so the split it was said to have went away with
  the template. The switch's handler now greys or ungreys the row the moment it is flipped, and undoes that if Apple fails.

Test (test_app.py): the D1 turn-off answer has no `Disabled</h3>` and greys the row; a new block renders three devices
(enabled, disabled, enabled by added date) and checks one group, newest-first order with the disabled one in the middle,
only that row greyed, and the 3-of-100 footer.

Tried and failed: nothing.

**Not verified**
- How it looks in a browser or on the phone (the grey level, and the instant greying on flip): this was an unattended run
  with no screen check; only the HTML was tested.
