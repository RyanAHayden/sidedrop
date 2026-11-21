# R3: B23's group fix on apps.hayde.in, checked again after B24 and B26

Live server: truenas-scale (`ssh truenas`, user truenas_admin, `sudo -n docker`), container `ix-sidedrop-sidedrop-1`.

## Result

**Pass.** The live signed Instagram now holds the group fix, and the deploy signed every app again without error.

| Check | Result |
|---|---|
| B24 and B26 deployed | When R3 started, live was at 99e85d7 (B24) and main at 30b05d3 (B26, merged 02:43 UTC). deploy.sh's cron redeployed at 02:45 UTC: `SIDEDROP_COMMIT=30b05d3` |
| The signed copies are signed again | yes, with nothing triggering it by hand: the sync loop's `resign_logged()` at start found no signer stamps and logged `resign: signed 8 apps in 65.5s` (02:46:13 UTC). Every `/data/signed/*.ipa` has a new mtime and a `.<name>.signer` beside it |
| `Payload/Instagram.app/sidedrop-groupfix.dylib`, `sidedrop-groupfix.plist` in `/data/signed/com.burbn.instagram.ipa` | both present; config `{groups: [group.com.burbn.instagram, group.com.facebook.family, group.com.burbn.family], keychain: True, target: ''}` |
| Its executable loads `@executable_path/sidedrop-groupfix.dylib` | yes (LC_LOAD_DYLIB in the executable) |
| keychain-access-groups | `[S8NFX3A2LT.com.burbn.instagram, S8NFX3A2LT.com.ryha.sideload]`; application-identifier `S8NFX3A2LT.com.ryha.sideload`; the five `group.com.ryha.sideload.N` app groups kept |
| `/app/native/groupfix/sidedrop-groupfix.dylib` unchanged | sha256 45638bf8728fc8e4…fc3dbfe8, the same as the committed file; mtime 02:25:02 UTC, before the 02:45 container start, so the sign did not write to it (B24's writable copy). Instagram's stamp reads `1 45638bf8…` |
| No resign error in the log | none: the log since the start holds only gunicorn's start lines, the resign line and requests. No `.groupfix` folder left in `/data/signed` |

How: a read-only Python script piped into `docker exec -i … python -` that opens the IPA with zipfile, reads the
executable's load commands and the entitlements blob from its code signature, and hashes the dylib. Nothing was
written on the server.

## Tried that failed

- `ssh truenas-scale` (my login name, no key): `Permission denied (publickey)`. The host alias `truenas`
  (`~/sync/ssh/ssh_hosts`, user truenas_admin) works and has `sudo -n docker`.
- `git log` in `/mnt/SSD/sidedrop/repo` as truenas_admin: "dubious ownership" (the clone is root's); `sudo -n git` works.

## Not verified

- **Install and run on a phone**: the live Instagram was not installed or opened, so keychain/app group access at
  run time is not seen here. No device is reachable from this session; B23's device check (iPhone 15 Pro,
  resignprobe) covers the dylib's behaviour.
- **Other apps with original groups** (YouTube, Discord): signed again without error, but their contents were
  not inspected. The task names Instagram only.
