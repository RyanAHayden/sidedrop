# F29 Settings layout fixes

## What I did
- **Share row** (admin only), under Manage in the same group: `Share`, the `share` row icon, pushes `/admin/invites`
  (Invite Friends: the anyone-link and one-iPhone links, each with Copy Link / Share). Decision: Settings never had a
  page called Share (checked F20/F26 history: the old tiles were Manage/Register, iFizBox, Help, About); the only sharing
  page is Invite Friends, which Manage's Friends group shows with that same share icon, so "Share page" = that page.
  Manage's own Invite Friends row stays.
- **Hint removed**: "Only you see this: you run this SideDrop." is gone; the admin group has no footer.
- **Titles**: the "This iPhone" header is gone (the Status / Apps Work Until group is first and untitled, `.grp`
  gives it the same 23px top margin a header had, footer kept). The admin group is titled **Admin Settings**.
- **Preferences**: Theme and Update Alerts sit under a **Preferences** header (footer kept). Add to Home Screen and
  Help stay untitled groups below.
- **Overscroll**: `#scr:has(>#t-settings:not([hidden])){overscroll-behavior-y:none}` and `#t-settings{min-height:0}`:
  on the Settings tab the scroller no longer rubber-bands (the drag-down showed pinstripes above the first group), and
  a Settings page shorter than the screen no longer gets the 1px extra that makes it scrollable. Other tabs keep the
  bounce and pull-to-reload; Settings loses pull-to-reload (it reloads only the Apps/iFizBox lists anyway).
- Tests: admin Settings has headers [Admin Settings, Preferences], Manage then Share, the Share row's markup, no hint;
  a user's Settings has only Preferences, no Share/Admin Settings, no This iPhone title; the CSS rule is on the page.

## Tried and failed
- nothing

## Not verified
- On a real iPhone: that `overscroll-behavior-y:none` on #scr stops the rubber band in Safari and the Home Screen
  app (needs iOS 16+; `:has` needs 15.4+; on older iOS the bounce simply stays). No phone with a SideDrop session was
  reachable from this unattended run, and no browser screenshot was taken; only the HTML/CSS is checked by the tests.
- The look of the new headers in each theme: not viewed, same `h3.hdr` as every other group header.
