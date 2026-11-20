# B17 Registering an iPhone answers at once

## What I did

- `register()` (POST /udid and the guest path /udid/<name>/g/<tok>/<sid>) still does invite_check, the Apple device add,
  `regen_profile()` and invite_use in the request (and save_product stays in the route), but no longer re-signs. It calls
  `resign_later()`, which starts `resign_bg_loop()` in a daemon thread: `with lock: resign(force=True)`. A registration
  that comes in while one runs sets `resign_bg["again"]`, and the loop runs exactly one more forced resign after it.
  Failures are caught and logged in one line ("re-signing after a registration failed: …"), and the state still clears.
- **Registration has its own lock now** (`reg_lock`, not `lock`). The brief said "under lock as now". But with
  register() also holding `lock`, a second registration that arrived during a resign waited for the whole resign, which is
  the spinner this task removes (my first test caught it). The resign still runs under `lock`. `resign_all()` now
  takes `reg_lock` around its own `regen_profile()`, so two profile rebuilds never run at Apple at once. Lock order is
  always lock → reg_lock (register never takes `lock`), so no deadlock. `regen_profile()` now writes the profile to
  `profile….part` and renames it into place, so a resign that is running reads the old profile or the new one, never a
  half-written file. When a resign reads the old profile part way through, the "again" run signs everything once more.
- `resign()` prints one line each time it signs something: `resign: signed N apps in X.Xs (forced)`.
- Apps page: `signing_now()` lists the signed IPAs older than the profile, and only while a background resign is pending.
  Those rows show a grey `<span class="get sgn">Signing…</span>` instead of GET/INSTALL/UPDATE, and so do Home's iFizBox
  card and the iFizBox page's Install button (disabled, "Signing…"). The page had no signing state, so this is new,
  but there is no new polling: `/` skips its own `resign()` while a background one is pending (otherwise the page would
  wait on `lock`, which is the spinner again). The page's existing `checkNow()` POSTs `/check`, which waits on `lock` in
  `resign_and_notify()` until the resign is done. Its stamp then differs, and `refreshIn()` swaps in the normal rows.
- README: step 2/3 of "how it works" says the signing runs in the background and the rows read Signing… until it's done.
- Tests (test_app.py, end of file, a fresh `boot()` on its own data folder): friend path 301 within 5s while `resign` is
  blocked on an Event; the iPhone is already at Apple and in the profile; Apps shows Demo as Signing… with no
  itms-services link; a second registration during it answers at once and queues exactly one more forced resign; after
  release, the rows are normal (GET + itms-services). Guest path: same 301 while blocked, and the invite is used up in
  the request. A resign that raises still clears the background state. The older register tests now call `bg_idle()`
  after a registration, so they read what the background resign signed instead of racing it.

## Tried and failed

- First version kept `with lock:` in register(): the second-registration test blocked for the full gate wait (10s).
  That's why reg_lock exists (above).

## Not verified

- On a real iPhone, iOS's spinner after Install profile now returns quickly. I couldn't check it: the test phone isn't
  reachable from an unattended run, and no real App Store Connect account or zsign runs in tests.
- How the Signing… button looks on a device (only its CSS was written, next to the other `.get` states). No screenshot
  was taken.
- That the open page flips from Signing… to normal by itself: that relies on the existing `checkNow()` → `/check` (which
  blocks on `lock` until the resign ends) → `refreshIn()`. No browser test drove it. The server side (the page renders
  normal rows once the resign ends) is tested.
