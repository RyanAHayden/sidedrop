# B4 — main page's pageshow calls themeMarks() unguarded

## What I did
- `app.py`: the main page's `pageshow` handler now calls `if(window.themeMarks)themeMarks()`, the same guard the
  `prefers-color-scheme` listener (line ~629) already uses. `themeMarks` is defined only by Settings > Theme's script
  (THEME_JS), which exists after that page was pushed; before that, every main-page load threw
  `themeMarks is not defined` inside the handler. Chose the guard over a main-page definition: the main page has no
  theme checkmarks to mark, so a definition would be a no-op anyway.
- `test_app.py`: asserts the main page defines no `themeMarks` and that every `themeMarks()` call on it is behind
  `if(window.themeMarks)`.

## Tried and failed
Nothing.

## Not verified
- No headless-browser load of the main page to watch the console go quiet: the fix is a one-token guard identical to
  an existing one, and the gate's `node --check` of the inline scripts covers the syntax.
