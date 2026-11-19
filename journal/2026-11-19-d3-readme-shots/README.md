# D3: README screenshots and sections, take 2

## What I did
- **docs/readme_shots.py** rewritten around the old demo data (same fake cert, apps, devices; one more device, Sam's
  iPhone 15, plus invites and made-up source lists in `data/config/`):
  - Captures at the iPhone 18 Pro screen: Playwright on /usr/bin/chromium, 402×874 at 3x, mobile + touch, an iOS 27
    Safari UA, and safe areas 62 top / 34 bottom through a CDP session (`Emulation.setSafeAreaInsetsOverride`). SideDrop's
    pages use `env(safe-area-inset-*)` and `viewport-fit=cover`, so the nav and tab bar sit around the status bar and
    home indicator as on a phone.
  - Frames them with SideDrop's own copy of the framing code from iFizBox's `tools/readme_shots.py` (nothing imported
    from iFizBox): bezel bitmap, the kit's status bar drawn from its vectors and embedded SF Pro, home indicator, the
    toned-down sheen, scaled 0.4 with 24 px side padding (588×1104), as iFizBox does. Finish Black.
  - The kit is read at run time from `--kit`, default `~/repos/iFizBox/ref/apple-ios27/Apple iOS 27 UI Kit.sketch`;
    nothing from it is committed. `--plain` gives rounded screens without it.
  - Crops (`crop-*.png`): an element-bounded clip of the raw 3x capture, scaled 0.4 like the phones' screens, rounded
    corners (12 pt), no bezel. setup (the form filled in with demo values, a fake `AuthKey_DEMOKEY123.p8` picked through
    the real file input), signing (Certificate group with the App ID), sources (the source list form).
  - New shots: passwords, invites (a One-iPhone link made through the real form for "Casey", with a used and an expired
    one listed), files (mid-upload: the page's real upload code with `XMLHttpRequest`/`FormData` replaced by fakes that
    report 62% and 18% and never finish), sources.
  - Raw captures stay in a temp folder removed at exit (atexit, also on errors); only finished PNGs land in docs/img.
  - setup.png (whole phone) dropped: the crop says more and the brief wants crops where a phone is too much.
- **README.md**: Screenshots is now one row of four friend-side phones (`<p align=center>`, 24% each, as iFizBox's
  README) with a one-line caption; What the admin can do is a 3×2 table of phones (iPhones, Signing, Passwords / Invite
  Friends, Files for Friends, App Sources), one short line each; Quick start step 3 shortened to a paragraph plus the
  setup crop; Configuration is three lines plus the signing crop; Apps, sources and files is three bullets plus the
  sources crop. Crops shown at width 239 (half their pixel width, the same for all three).
- **docs/configuration.md** (new): the env table (plus `DATA_DIR`), setting up without an iPhone, `BUNDLE_ID`
  explicit vs wildcard, the data folder, the version line, apps/sources/files in full, GitHub editing and deploy.sh,
  `/sync` for CI, and the Manage details that left the README table (cert warnings, revoke list, `?password=` sign-in,
  device slots, invite paths).

## What failed / snags
- Second run died with `Disk quota exceeded` writing to /tmp (the tmpfs is shared and 80% full of other sessions'
  files). Deleted my two leftover `/tmp/sidedrop-shots-*` folders (a third from 14:21 predates this session, left
  alone), added the atexit cleanup, and ran with `TMPDIR=~/.cache/sidedrop-shots-tmp` (removed after).
- First invites shot scrolled the "One iPhone" header under the nav; scrolled 45 pt less.
- The setup crop first sat inside the white card (white on white in the README); it now takes the card's width
  (`across=`) so the grey page edges show.

## Checks
- Every `docs/img/*.png` linked from README.md exists, and every PNG in docs/img is linked (shell loop).
- `gh api markdown -f mode=gfm` on README.md and docs/configuration.md: renders, both alerts, 2 tables, 15 images,
  mermaid block. Rendered HTML screenshotted locally in Chromium to eyeball the phone rows.
- Images: demo names only (Demo, Alex, Jordan, Sam, Casey, Riley), example.com/example.org domains, `…DEMO…` UDIDs,
  fake team DEMO123456, demo passwords shown only as dots.

## Not verified
- The Apps tab header shows the app's hard-coded author byline "by Ryan Hayden (Fizlo)" (app.py:931). It is the
  product's own credit (same as the GitHub owner in every link), not user data, so it stays in apps.png; the old D2
  shots had it too. If the brief's "nothing personal" was meant to cover it, the script would need to patch that
  string out.
- How GitHub itself lays out the images (only its markdown API output and a local unstyled render were checked; the
  repo page isn't updated until the branch is merged and pushed).
- `--plain` mode and the other bezel finishes weren't run (the kit was present).
