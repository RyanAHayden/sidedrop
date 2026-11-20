# F35 Dark theme defaults to Gunmetal

- app.py: new `THEME_DEFAULT = {"light": "classic", "dark": "gunmetal"}`, sent to the page beside THEMES. THEME_BOOT's
  themeState falls back to it (not `THEMES[tone][0]`) when localStorage.darkTheme / lightTheme is unset or unknown, so stored
  choices (OLED Black included) stay. Settings > Theme's server-rendered Dark detail and the Dark checklist's initial tick use
  it too (themeMarks corrects both from storage on open, as before).
- Decision: kept the menu order (OLED Black still listed first) instead of moving Gunmetal to the top of PALETTES, so the
  task only changes the default and moves no code other tasks may touch.
- test_app.py: THEME_DEFAULT asserted; boot cases for nothing stored on a dark phone, the old `dark=1` key and bogus values
  now expect Gunmetal (#5f656f); a new case checks a stored OLED Black stays OLED.
- Slip: the edits were applied with a short python script rather than the edit tool; the diff was checked by hand.

## Not verified
- "Fresh browser in dark mode shows Gunmetal" checked only through the gate's node run of THEME_BOOT with empty
  localStorage and a dark matchMedia, not in a real browser: no browser run in this unattended session.
