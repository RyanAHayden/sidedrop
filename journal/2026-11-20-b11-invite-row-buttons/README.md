# B11: Invite Friends, the unused One-iPhone row's buttons squished at phone width

## What I did

On an unused row, COPY, SHARE and REVOKE sat beside the name: the name and date wrapped to three lines, and SHARE ran into
REVOKE. Now INVITES_PAGE (app.py) wraps that row (`.irow[data-link]`): the name and date take the full width, and the three
buttons go on a line of their own under them. `.lbtn` gets `display:contents` there, so the row's flex lays out COPY, SHARE and the
REVOKE form together at equal widths with the row's 10px gap. Where the browser has no `navigator.share`, SHARE is hidden and COPY
and REVOKE split the line in half. They keep the same `.act` buttons (blue, grey, red), so the iOS 6 look is unchanged. Used rows
(REVOKE only, no `data-link`) keep the old inline layout, which already looked fine.

A gate check in test_app.py (beside the B-invites page asserts) looks for the three rules.

## Tried and dropped

- `.lbtn{flex:2}` + `form{flex:1}`: gave unequal buttons, and a lopsided COPY/REVOKE when SHARE is hidden.
- `flex:1 1 0` for all three: REVOKE came out 22px narrower. A button's padding and border (22px) set the minimum for its
  flex basis, and the form wrapping REVOKE has neither. A shared basis of 40px makes all three equal.

## Check

A scratch Playwright script (system Chromium, not committed) ran the app with an unused invite "Tyler Beichler" and a used one
"Rhys", at 320 and 375px wide, light and dark, with `navigator.share` stubbed in (as on iOS Safari) and without it:
- 320px: COPY/SHARE/REVOKE 86px each, 10px apart; 375px: 104px each. Without share: 134px / 162px halves.
- Name and date on one line each, nothing clipped, no row or page horizontal overflow (scrollWidth checks).
- The screenshots looked right (the scratch files are not kept).

## Not verified

- On a real iPhone (Safari / Home Screen app): this run has no device. Chromium stood in, with an iPhone-width mobile
  viewport. `display:contents` on a plain div works in iOS Safari 11.1+, so this should match.
- The used-row layout at 320px still wraps a long "Used by … on …" line to three lines beside REVOKE. That's unchanged, and the
  brief says it looks fine.
