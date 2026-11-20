# F32 — Register step screenshots (blocked)

## What the task needs
Two real screenshots from a current-iOS iPhone (iOS 26/27), cropped and circled like static/sdp1-3.jpg / dev1-3.jpg:
- reg1.jpg: Settings, the **Profile Downloaded** row just under the Apple Account name.
- reg2.jpg: the **Install Profile** sheet for "SideDrop device registration", **Install** circled top-right.
Then show them under the register steps (`enroll_form` `#next`, app.py ~1124) and Help › Register iPhone Didn't Work
(app.py ~2381), as a `REG_STEPS` Markup global beside SDP_STEPS, with a test like the sdp1 ones.

## What I checked
- sdp1-3 and dev1-3 came in with commits 2ed5e0c / fa46d83 from the user's own phone; no raw iPhone captures are in the
  repo, its journals, ~/Pictures (desktop screenshots only) or ~/Downloads (absent).
- The only test phone I can reach is the iPhone 7 (`ssh 7`), iOS 15.8.8, plugged into the T490, not this machine. iOS 15's
  Settings and Install Profile sheet look different from iOS 26/27 (the brief asks for current iOS), so its pictures would
  mislead people.
- Drawing a mock-up of iOS Settings would be invented art, which this project doesn't do (sdp/dev are real captures).

## Decision
No code change: adding `<img>` tags for files that don't exist would show broken images. Blocked until a person supplies
the two screenshots; the wiring is small (above) once they exist.

## Not verified
- Everything: no screenshots could be taken (no current-iOS iPhone reachable from this unattended session).
