# B23 Signed apps keep their own app-group folders and keychain

## What I did

- Read the brief: "Same fix as iFizBox B211 (wait until it is on iFizBox's main and copy its approach)".
- Checked iFizBox (`~/repos/iFizBox`, 2026-11-20): `git log main` has only the plan commit that filed B211
  (bfbb9748); its plan/TODO.md still lists `- [ ] **B211**` open; branch `task/B211` exists but
  `git log main..task/B211` is empty. No iFizBox slot is working on it right now (worktrees s1 R46, s2 T59, s3 B209).
- So the approach to copy (the fix dylib: how it is built, what it hooks, where the stable folder lives,
  how the original group IDs are read) does not exist yet. Blocked B23 instead of inventing a second design,
  as the brief asks. No code changed.

## Notes for the session that picks this up

- SideDrop signs with the static musl zsign 1.1.2 in the Dockerfile (`app.py` `app_entitlements`, the
  `zsign ... -m PROFILE` call near line 358). The dylib needs an arm64 iOS build; the python:3.13-slim image
  has no iOS toolchain, so either ship a prebuilt dylib (built the way B211 builds its own) in the repo or add a
  build stage to the Dockerfile.

## Not verified

- Everything in the task: nothing was built, because what it copies is not on iFizBox's main yet.
