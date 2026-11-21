# B23 Signed apps keep their own app-group folders and keychain

## Earlier session (blocked)

The first session found iFizBox's B211 not on its main yet and blocked (`--after`). iFizBox B211 + B227 landed
on 2026-11-20, so this session copied that approach.

## What I did

- **The fix dylib, SideDrop's own copy**: `native/groupfix/groupfix.m` is iFizBox's `native/groupfix/groupfix.m` (main
  3326d76e). Only the config file name changed (`sidedrop-groupfix.plist`), plus the header comments. The folder
  (`Library/AppGroups/<group>/`), the suite (`ifizbox.appgroup.<group>`) and the keychain stripping are unchanged on
  purpose: one app signed by SideDrop and later by iFizBox's signer (same identity) finds the same data.
  `native/groupfix/build.sh` builds it with this machine's `~/.local/share/ios-sdk/iPhoneOS27.1.sdk`, clang and
  rustup's ld64.lld into `native/groupfix/sidedrop-groupfix.dylib` (committed, with `.source-sha256`; the
  python:3.13-slim image has no iOS toolchain). The install name is `@executable_path/sidedrop-groupfix.dylib`,
  because zsign 1.1.2's `-l` copies the dylib to the .app's top level and loads it from there. Checked with the
  real zsign: `LC_LOAD_DYLIB @executable_path/sidedrop-groupfix.dylib`. The `legacy` code stays, but SideDrop never
  sets it: it never mapped groups to a profile group before, so there is nothing to copy in.
- **app.py**: `macho_entitlements` (iFizBox's `entitlementsRead` in Python: thin or fat, first 64-bit slice, XML
  entitlements slot; seeks inside the zip member, never reads a whole 100 MB executable), `ipa_entitlements`
  (CFBundleExecutable's entitlements), `group_fix_plan` (the original's groups the profile lacks, target "", keychain
  when the original named keychain groups). `sign_ipa` writes `sidedrop-groupfix.plist` into the .app through
  `retarget`'s `extra` and adds `-l native/groupfix/sidedrop-groupfix.dylib` to zsign. Never into iFizBox's own IPA
  (as iFizBox's signers do). `app_entitlements` now sets `keychain-access-groups = [TEAM.<kept bundle ID>, appid]`
  (de-duplicated under a wildcard). The profile's own app groups stay as they were (zsign uses our `-e` plist, which
  is the profile's entitlements).
- **Dockerfile** copies the dylib to `/app/native/groupfix/`.
- **test_app.py**: the reader on a real zsign-signed arm64 executable (`fixtures/groupfix-probe.ipa`, 72 KB:
  an empty `main` built with the iOS SDK and signed ad hoc by zsign 1.1.2 with two groups and a keychain group;
  force-added because `.gitignore` has `*.ipa`), and on built thin and fat Mach-Os, unsigned and damaged ones; the
  plan; sign_ipa's `-l`, the config's place and content, the kept profile groups, the keychain groups; nothing for
  Demo (no entitlements) and iFizBox; the committed dylib matching groupfix.m and reading the config name this
  signer writes; the Dockerfile COPY. The explicit-App-ID test's keychain assertion was updated to the new rule.
- **docs/developer-account.md**: "How apps are signed" corrected (each app's own keychain group), and a new "Keep your
  apps' data" section: same team, same App ID, bundle IDs kept; a new App ID or team means delete and reinstall;
  the group fix; extensions not covered; making the profile again after an App ID change.

## Checks run

- End to end with the image's zsign (v1.1.2 musl static, same sha256 as the Dockerfile) and a throwaway CA,
  certificate and CMS-signed profile: `sign_ipa` on the fixture gave the config in the .app, the dylib injected
  and sealed in CodeResources, and entitlements `keychain-access-groups [TEAM.com.example.probe,
  TEAM.com.me.sideload]` with the profile's group kept.
- **On the iPhone 15 Pro (iOS 27)**, with iFizBox's `tools/resignprobe/build.sh` (probe `sd` and `sd2` with WIPE=1,
  bundle IDs `com.ryha.ifizbox.probe.sd/.sd2`), signed by this branch's `sign_ipa` (scratch wrapper; SideDrop's real
  cert.p12 repacked by `p12_repacked` as the server does, `sidedrop-adhoc.mobileprovision`, BUNDLE_ID
  com.ryha.sideload), installed `--as-is` with `tools/ui-15.sh` under lock B23-sidedrop. Report pulled the way
  `run.sh` does, but without its screenshots (they write into iFizBox's ref/):

  | Step | doc | prefs | orig. group folder | orig. group suite | profile group | keychain plain / AFU / orig / seed |
  |---|---|---|---|---|---|---|
  | SideDrop's signer (this branch), first launches | kept | kept | kept (`Library/AppGroups/...`) | kept | kept | kept, all in `TEAM.com.ryha.ifizbox.probe.sd` |
  | re-signed with the other profile for the same App ID (RSideload), installed over it | kept | kept | kept | kept | kept | kept |
  | another app under the same App ID (sd2) clears its keychain at first launch | sd2's wipe found nothing of sd's (-25300 for each) | | | | | |
  | sd after that | kept | kept | kept | kept | kept | kept |

  The main-branch "before" rows are in iFizBox's journal/2026-11-20-b227-resign-data/notes.md (SideDrop's signer
  without the fix: original group FAIL nil, keychain original/seed FAIL -34018; the shared keychain deleted). The
  probe apps were uninstalled afterwards and the lock released.
- Spec review (fresh subagent on the diff and brief): no functional bugs. Fixed: the groupfix.m comment on the
  default keychain group (it described the old application-identifier rule; the dylib bytes didn't change, only
  the source hash), the stale journal, and docs on extensions not getting the fix.
- Gate: `test_app.py` passes. The `KeyError: 'Entitlements'` tracebacks in its output come from an existing test
  with a junk profile; main prints the same 3.

## What went wrong on the way

- zsign 1.1.2 signing a .app folder zips the folder holding `Payload/`. With `-o` inside that folder it zipped its
  own output, which grew to 218 GB in two minutes before I killed it (by the pid holding the file) and deleted it.
  SideDrop isn't affected: it signs .ipa files (zsign unpacks them into `-t`).
- My throwaway certificate first failed in zsign ("Unknown issuer hash ... no usable CA chain"): it needs the
  issuer in the p12. SideDrop's real p12 is RC2 (B1), so the scratch wrapper repacks it as the server does.

## Deploy

deploy.sh runs from cron on the NAS and redeploys whenever origin/main moves, so the runner's merge deploys B23 to
apps.hayde.in without a hand step. Filed R2 (after B23) to check the live image has the dylib and that an
app installed from it carries the fix.

## Not verified

- **The live deploy on apps.hayde.in**: it happens after the merge, which is after this session; filed as a
  follow-up check.
- **RyukGram/Instagram itself**: not signed or run. The probe reproduces its stores (original app group, its
  suite, keychain groups), but Instagram's own code paths (Meta's shared family-login keychain items, extensions)
  were not exercised.
- **App extensions**: the dylib goes into the main executable only (zsign `-l`, as iFizBox's signers). An extension
  reading the original group still gets nil. zsign's `-P` would inject into extensions too, but iFizBox doesn't,
  and that isn't checked on a device, so it's not used.
- **The docker image build** (`docker build`): not run here. The COPY path is checked by test_app.py, and the
  dylib is committed.
