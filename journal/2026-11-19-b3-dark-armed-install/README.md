# B3 Dark themes: armed green INSTALL keeps white text

**Done**
- `app.py`: after `.dark .get{…}` added `.dark .get.go{color:#fff;border-color:#2f7a17}` and
  `.dark .get.go.is-pressed{border-color:#255e12}`. `.dark .get.go` is (0,3,0) so it beats `.dark .get` (0,2,0) wherever it sits;
  the pressed rule matches the light theme's `.get.go.is-pressed` border, which the plain rule would otherwise cover (same specificity, later).
  It sits after F25's `.dark .ifzr .get.go` too, so the iFizBox card's pressed border is right in dark as well (it was always #2f7a17 before).
- Left F25's `.dark .ifzr .get.go` rule in place (now redundant) so as not to touch code outside the task.
- `test_app.py`: asserts both rules are served and the pressed one comes after `.dark .get`.

**Tried and failed**: nothing.

**Not verified**
- Rendering in a real dark-theme browser/phone: no screen in this unattended run; checked by CSS specificity only.
