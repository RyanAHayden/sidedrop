# F22: SideDrop serves its own apps; updates show on Home

SideDrop now only serves the apps it signs and hosts (`data/apps/`, the mirrored sources, iFizBox among them).
Updates and installing your own IPAs are iFizBox's job.

## What changed

- **Changes tab removed**: its tab-bar item, the `t-changes` page, the `cyrow` macro and the `.cy*` CSS, the
  `recent` list, the Cydia-style nav (Refresh / Update (n)) with its `upgradeAll`/`upgradeGo` and the `upq` confirm
  alert, the "ask for notifications on the first visit to Changes" hook, and the Apps header's Changes tile. The sync
  no longer writes `.source`/`.date`/`.desc` beside each app (only Changes read them; old ones on disk are ignored).
  An old `#changes` link (a Home Screen bookmark, an earlier push) falls through `show()` to the Apps tab.
- **Signing your own IPA removed**: the `POST /sign` route, the Settings "Sign your own IPA" form (Choose .ipa File,
  paste a link), the Sign IPA tiles on the Apps header and Settings, and `CUSTOM`. Its storage, `signed/custom/`, is
  emptied and removed at start (`drop_old_custom_signs`): those links were 7-day ones and no longer resolve anyway.
  `LINK_TTL` stays: every other signed link (app files, Files) uses it.
- **Files tab kept**: it holds the admin's Files for Friends, not IPAs, so "the Files tab if that's all it holds"
  didn't apply.
- **Home's update rows**: a row whose app has a newer signed version than this iPhone last installed gets
  `class="row up"`, its version line reads "Version 1.3 · Update available", and its button says UPDATE in place of
  GET (it arms to INSTALL like GET, iOS 6 App Store style). This covers the Apps list, Third-party apps and the
  iFizBox row. The red badge moved to the **Apps** tab; the server renders the count and `navR()` recounts
  `#t-apps .row.up` (the spinning busy badge while `/check` runs is kept). An install tap (`mark()`) takes that row's
  `up` class and note off and recounts.
- **Update Alerts** stay; the push's URL is `/#apps` (was `/#changes`), so tapping one opens Home.
- **Text**: the Apps header's second row is Help | About; Settings' tile pair is Manage (or Register) | iFizBox;
  Help's note and About say SideDrop serves the apps listed here and to use iFizBox for your own IPAs and other
  sources; iFizBox's "Updates in one tap" line no longer names Changes. README, docs/configuration.md and
  docs/become-a-distributor.md describe the same; README's screenshot row lost the Changes shot
  (`docs/img/changes.png` deleted, `readme_shots.py` no longer takes it).

## Decisions

- Kept the tab's label **Apps** (the task says "Home"): the tab is `#apps`, titled SideDrop, and README/tests call it
  Apps; renaming would churn every reference for no gain.
- Dropped "Update (n)" (update everything): it was the Changes nav's; rows with files can't be batch-installed anyway,
  and iOS shows one install prompt per link.
- Update rows aren't moved to the top of their group: they're marked in place, as the App Store's Purchased list.

## Tests

Deleted: the custom-signing block (upload and URL both giving a link) and the Changes-tab block. Added (test_app.py,
"F22"): `/sign` is gone (404/405); `drop_old_custom_signs` clears `signed/custom/`; no `#changes`, `'changes'`,
`t-changes`, `/sign`, Sign IPA, Choose .ipa File on the page (signed out and registered); tabs are
Apps, iFizBox, [Files,] Settings; the badge sits on the Apps tab, hidden at 0; an older install makes the row
`row up` with "Version 1.3 · Update available" and UPDATE, and the badge 1; another phone sees no update; installing
clears it; a no-files app's row is an `<a data-arm=UPDATE>` UPDATE link; the push opens `/#apps`.

## Screenshots

Ran `docs/readme_shots.py` (with the iOS 27 kit) again. `apps.png` now scrolls Trailhead's update row into view
(UPDATE, "Version 5.0 · Update available", badge 1 on Apps). The shots that show the tab bar (apps, install,
settings, manage, signing, invites) are committed because the Changes tab left it; `crop-signing.png` changed
only by noise and was put back.

## Tried and failed

- A first version of the no-files update test synced `apps/Plain.ipa` through `resign`; the stubbed zsign always
  writes Demo's IPA, so the signed copy never changed version. The test writes `signed/Plain.ipa` directly instead.

## Not verified

- On an iPhone: the badge's position on the Apps tab, the UPDATE → INSTALL arm and the row losing its note after an
  install tap. No phone in this unattended run; the markup, the counting script and the inline JS's syntax (node
  parse in the gate) are tested.
- A real Update Alert opening `/#apps` from the Home Screen app: needs a registered phone with push on.
