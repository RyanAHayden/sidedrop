# B15: Copy Link that really copies, and a page for revoked links

## What happened
The admin revoked a one-iPhone link, made a new one, tapped Copy Link on the `?new=` page and sent the *revoked* link. The likely
cause is the old `lnkCopy`: when `clipboard.writeText` rejected, the fallback ran in the promise's rejection (outside the tap) and
selected the **readonly** `.lnk` input. iOS Safari selects nothing in a readonly input, and `execCommand("copy")` can still return
true, so the button said "Copied" while the clipboard kept the last link copied (the revoked one, from its row's COPY).

## What I did
- `lnkCopy` (INVITES_PAGE, app.py): in the tap, synchronously, an editable hidden textarea holding the link is selected and
  `execCommand("copy")` runs with a `copy` listener that sets exactly that link on `clipboardData`. It counts as Copied only when
  execCommand returned true **and** that listener ran. If not, it tries `clipboard.writeText`. If that also fails the button says
  "Not Copied" / "NOT COPIED" and the link is left selected in an editable box (an input added after the row when the row has none),
  ready for the system Copy. It never says Copied on a guess.
- Revoked or unknown links: revoking now writes a note to `invites-revoked.json` keyed by `sha256("invite:"+token)[:32]` (not the
  token) with the name. `invite_gone_msg()` gives the revoked link "The person who sent this link for Kim turned it off… If they sent
  you a newer link, open that one instead", and an unknown one "SideDrop doesn't know this invite link. Check that the whole link was
  copied". `invite_check` uses it, so `/invite/<tok>`, the revoked guest's session page and registering all say the same thing.
- test_app.py: revoked page text, unknown page text, hash-only note, the guest session's page, and the new copy script's markers.

## Checks
- Gate: `uv run -q --no-project --with-requirements requirements.txt python test_app.py` passes (ok).
- `copytest.py` (this folder) runs the copy script in headless Chromium through Playwright: the clipboard starts holding a stale
  `ULHMz-OLD` link. Copy Link puts the box's link there, and so does the row's COPY. With no `navigator.clipboard`, the copy-event
  path alone works. With `execCommand` faked to return true without copying (the iOS case) and writeText rejecting, the button says
  Not Copied, the link is selected in an editable box, a second tap adds no second box, and the labels come back after 2 s. To run
  it, put the `<script>/* F16, B15` block of INVITES_PAGE in `copy.js.html` beside it.

## Tried and failed
- My first harness run failed on `Object.defineProperty(navigator, "clipboard")` the second time (not configurable). That was a
  harness bug, not an app bug.

## Not verified
- **The manual iPhone run** (make a link, Copy on the `?new=` page, paste in Messages; and row COPY). This was an unattended run with
  nobody to drive the phone and no server reachable from it, so the iOS Safari behaviour is checked only in Chromium, with the iOS
  failure mode faked. Someone needs to do this on an iPhone, ideally iOS 15 and a current iOS, in Safari and in the Home Screen app.
- Whether iOS fires the `copy` event for `execCommand("copy")` from a hidden fixed textarea. This is the documented WebKit behaviour
  for a selected editable field in a user gesture, but I haven't seen it happen on a device. If it doesn't fire, writeText still runs
  and Not Copied is the worst case.
- Links revoked before this change have no note, so they still get the "doesn't know this invite link" page.
