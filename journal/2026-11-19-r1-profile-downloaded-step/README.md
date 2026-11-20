# R1 — Is the Profile Downloaded step clear?

## What the step said
Apps tab, Set up this iPhone › 2 Register (`enroll_form`, the `#next` list shown after Register iPhone):
1. Tap Allow, then Close. 2. Open the Settings app. 3. Tap Profile Downloaded near the top.
4. Tap Install, enter your passcode, tap Install again. 5. You'll land back here automatically, registered.
Help › Register iPhone Didn't Work had the same in one line. There is no picture for this step (SDP and Developer Mode have screenshots).

## Read cold against what iOS (15–26) shows
- Safari popup "…trying to download a configuration profile" Ignore/Allow, then "Profile Downloaded — Review the profile in
  the Settings app…" Close: the text matched. Fine.
- "near the top" of Settings: vague. The row is directly under the Apple Account name card. Now says "just under your name".
- No fallback: if the Settings row is missed or gone, the profile is listed under General › VPN & Device Management
  (Downloaded Profile: "SideDrop device registration", our PayloadDisplayName). Added.
- iOS deletes a downloaded profile that is not installed within 8 minutes, so a first-timer who wanders off finds nothing. The
  step now says "within a few minutes"; Help says after 8 minutes register again.
- "Tap Install": Install is a nav-bar button in the top-right corner of the Install Profile sheet; a first-timer looks for a
  button at the bottom. Now says "in the top-right corner".
- "tap Install again": iOS asks a second time for some profiles (unsigned / confirmation sheet) and not always for a signed
  Profile Service payload, so a flat instruction could leave someone waiting for a button that never comes. Now "if iOS asks".
- "You'll land back here": it's Safari reopening on the 301 from /udid; now says so.

## Changed
- `app.py` `enroll_form` `#next` steps and Help's Register iPhone Didn't Work step 2 (wording only, no layout change).
- `test_app.py`: asserts the home page says where each tap is.

## Not verified
- Walking the real flow on a phone: the test iPhone 7 is plugged into the T490, not this machine, it runs iOS 15 (users run
  18–27), and finishing the flow registers a real UDID in the Apple developer account (outward-facing). Wording is from
  iOS's known screens and Apple's documented 8-minute removal, not a fresh walk-through.
- Whether a signed Profile Service install on iOS 26/27 shows a second Install confirmation: hedged as "if iOS asks".
- Picture: none added. A drawn mock of iOS Settings would be invented art; real screenshots (like sdp1–3.jpg) need a
  phone. Filed as a follow-up.
