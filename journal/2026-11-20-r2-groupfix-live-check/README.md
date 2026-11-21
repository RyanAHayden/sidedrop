# R2: B23's group fix on apps.hayde.in

Checked on the live server (truenas-scale, container `ix-sidedrop-sidedrop-1`) after the B23 merge.

## Result

The deploy worked, but **signing with the group fix fails on the server**. Filed B24 (critical).

| Check | Result |
|---|---|
| deploy.sh's cron (every 5 min, `/mnt/SSD/sidedrop/repo/deploy.sh`) redeployed main | yes: `SIDEDROP_COMMIT` went from b51aa78 to d4f641a at 18:25 PST (02:25 UTC) |
| `/app/native/groupfix/sidedrop-groupfix.dylib` exists | yes, 72496 bytes, sha256 45638bf8…, the same as the committed file |
| App ID capabilities changed / profile needs making again | no: heal_signing ran at container start and logged nothing (it logs "making the ad hoc profile again" or "couldn't check the App ID" otherwise); profile left alone (2026-11-21 00:29 UTC) |
| A live signed IPA for an app with original groups holds the fix | **no**: `/data/signed/com.burbn.instagram.ipa` (RyukGram) was signed at 00:29 UTC, before the deploy, and resign() redoes a copy only when the IPA or profile is newer. It has no groupfix files, and its keychain-access-groups is `[S8NFX3A2LT.com.ryha.sideload]` |
| The deployed code can sign it with the fix | **no**: `sign_ipa` → zsign exit 255, `Invalid dylib file! Not a valid Mach-O format. /app/native/groupfix/sidedrop-groupfix.dylib` |

### Why zsign fails

zsign 1.1.2 signs the `-l` dylib **in place**. Its verbose output shows `SignFile: sidedrop-groupfix.dylib`, then
`No enough CodeSignature space (now: 720, need: 6054). Realloc CodeSignature space... Success!`. In the image the dylib is
owned by root, mode 755, and the app runs as uid 568, so zsign can't open it for writing. It then reports that as an
invalid Mach-O. B23's local checks ran zsign as the file's owner, which is why they passed.

With a copy of the same dylib in a writable folder (`/data/r2tmp`, `DYLIB=` override in a scratch script), the
deployed app.py's steps (retarget + zsign) signed Instagram in 6.3 s, and the output held what R2 asks for:

- `Payload/Instagram.app/sidedrop-groupfix.dylib` and `Payload/Instagram.app/sidedrop-groupfix.plist`
- config `{groups: [group.com.burbn.instagram, group.com.facebook.family, group.com.burbn.family], keychain: True, target: ""}`
- the executable loads `@executable_path/sidedrop-groupfix.dylib` (zsign: `InjectDylib ... Success!`)
- keychain-access-groups `[S8NFX3A2LT.com.burbn.instagram, S8NFX3A2LT.com.ryha.sideload]`; application-identifier
  `S8NFX3A2LT.com.ryha.sideload`; the profile's five `group.com.ryha.sideload.N` groups kept

So the fix itself is right. Only the read-only file breaks it.

### What it breaks (B24)

`resign()` signs `apps/*.ipa` in sorted order, and `com.burbn.instagram` comes first. The next resign raises there, so
no app after it is signed. A resign happens on a registration (new profile, every app signed again), a new Instagram
build from its source, or an upload. Nothing triggered one while I checked. The live signed copies are still the
pre-B23 ones, so nothing is broken for users yet.

### Found on the way (B25, B26)

- **B25 (critical)**: the CalledProcessError text holds zsign's whole command line, P12 password included. index()
  shows `str(e)` on the page, and the background resigns print it to the container log. My test run printed it
  to my own terminal. I did not copy it anywhere, and it is not in this journal.
- **B26**: a deploy that changes signing never redoes signed copies, so B23 reaches no live IPA until a registration.
- **R3**: run this check again after B24 and B26 deploy.

## What I did not do

- I did not replace the live `/data/signed/*.ipa` with my test-signed copy. The server's own code can't sign with
  the fix yet, so a hand-placed copy would be undone, or would fail, at the next resign. It would also leave the
  live copies mixed. B24 then B26 put the fix there the normal way.
- I did not change app.py or the Dockerfile: R2's files are journal/**. The fix is B24.
- Temp files removed afterwards: `/data/r2tmp`, `/tmp/r2*.py` in the container and on the NAS.

## Tried that failed

- The first test sign used `app.sign_ipa` as it is → the zsign 255 above, with `-q` hiding why. Running the same steps
  without `-q` showed the message.
- `run plan add … --files journal/**` unquoted: the shell expanded the glob and the runner refused it. Quoted, it was added.

## Not verified

- **Install on a phone**: the test-signed Instagram was not installed or run. No device is reachable from this
  session for it, and the copy was deleted. B23's device check (iPhone 15 Pro, resignprobe) covers the dylib's
  behaviour.
- **Other apps with original groups** (Discord, YouTube…): only Instagram was signed. It is the app the task names,
  and the failure happens before any app-specific step.
- **The page error after a failed resign**: inferred from `index()`'s code (`error = str(e)`), not seen live, because
  causing it would have shown the password on the live page.
