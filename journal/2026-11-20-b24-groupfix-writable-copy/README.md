# B24: the group fix's dylib goes to zsign as a writable copy

R2 found every re-sign failing on apps.hayde.in once an app needs the group fix: zsign 1.1.2 signs the `-l` dylib in
place, and `/app/native/groupfix/sidedrop-groupfix.dylib` is root-owned 755 in the image while the app runs as uid 568,
so zsign exits 255 and `resign()` stops at the first such app (Instagram).

## What I did

- `sign_ipa` (app.py): when the plan has a fix, it copies `GROUPFIX_DYLIB` to `.<out>.groupfix/sidedrop-groupfix.dylib`
  beside the signed IPA (a new file, so owned and writable by the app's user) and passes that to `-l`; the copy and its
  folder are removed in the `finally`, failure or not. The copy keeps the dylib's name, since zsign -l names the
  `LC_LOAD_DYLIB` (`@executable_path/sidedrop-groupfix.dylib`, which the committed dylib's test expects) after the file;
  a folder of its own keeps that name without a clash between two signs.
- test_app.py: the fake zsign checks the `-l` path is not the committed file, has its bytes and is writable, then appends
  to it as zsign does; after the signs, the committed dylib's bytes are unchanged and the copy and its folder are gone.

## Tried and failed

- nothing

## Not verified

- A real zsign run with the copy: no zsign on this machine, and a real sign needs the server's P12 and profile. R2
  already signed Instagram right in the live container with a writable copy (see the brief); whether R2's copy kept the
  name is not recorded, so the name is kept here to be safe. The live check is R3's (filed by R2).
- Deploy to apps.hayde.in: the runner publishes after the merge, not this task.
