# F15: version lines like iFizBox's

## What I did

- `app.py`:
  - `PRODUCTS` (`products.json` in the data folder, `{udid: PRODUCT}`) and `save_product()`. `/udid/<name>` saves
    `attrs["PRODUCT"]` before `register()`. I left `register()` itself alone, because its signature is shared with tests.
  - `device_model(udid)` returns the saved PRODUCT. For iPhones registered before F15 it falls back to an
    `iPhoneN,M` in the cached ASC device's name (`devices.json`, which is what Manage fetches). Then Apple's `model`
    (e.g. "iPhone 14 Pro"). Then plain `iPhone`. It never asks Apple during a page load.
  - `read_commit()` / `COMMIT`: `SIDEDROP_COMMIT`, else `git rev-parse --short HEAD` in the app's folder, else `""`, and
    then there is no commit line. It uses `Popen`, not `subprocess.run`, because test_app.py stubs `subprocess.run`
    (for zsign) and the stub crashed on the git call. `BUILD` is unchanged.
  - `VERSION_FOOT` and `version_foot()`: `<p class=ver data-m=MODEL>MODEL, sidedrop</p>` then `<p class="ver vc">COMMIT</p>`.
    The UDID comes from `?enrolled=` or the device cookie, and only counts if it is in the profile. Otherwise the
    phone is unregistered and gets `iPhone`. `page()` passes it as `vfoot` to the body and to `PAGE`. It sits at the
    bottom of `#t-apps`, of `#t-settings` (under Sign out), and in the About alert (under the stats line).
  - `VERSION_JS`, added after `PAGE` in `page()`: on DOMContentLoaded it rewrites each `.ver[data-m]` to
    `MODEL, iOS X.Y[.Z], sidedrop (lang)`. It uses iFizBox's `iosFromUserAgent` regex and `navigator.language`
    lowercased. If the UA has no iOS, the iOS part is left out.
  - CSS: `.ver` copies iFizBox's `.home-version` (13px/16px, centred, `--head` colour, emboss). The commit line is
    pulled up and at .8 opacity. Inside `.alert` the lines inherit the alert's white text.
- `Dockerfile`: `ARG COMMIT=` and `ENV SIDEDROP_COMMIT=$COMMIT`. `deploy.sh`: `--build-arg COMMIT="$(git rev-parse --short HEAD)"`.
- `compose.yaml`: `build.args.COMMIT: "${SIDEDROP_COMMIT:-}"`. Compose can't run a command in an interpolation, so
  the user sets `SIDEDROP_COMMIT=$(git rev-parse --short HEAD)` on the command line. I added one line about this to the README.
- `test_app.py`: `read_commit()` uses `SIDEDROP_COMMIT`. A registered phone's page has the PRODUCT line plus the commit
  three times (Apps, Settings, About). A signed-out `?enrolled=` page still has it in About. An unregistered phone gets
  `iPhone`. The fallbacks are the name's PRODUCT, then the ASC model, then `iPhone`. With no commit there is no second line.

## Tried and failed

- `subprocess.run` for git broke the gate's second `boot()`, because the zsign stub assumes `-e`. Switched to `Popen`.

## Checked

- The gate passes.
- node: the UA regex gives `iOS 18.1` for `CPU iPhone OS 18_1`, `iOS 15.8.4` for `15_8_4`, and nothing for a desktop UA.
- Headless Chromium with an iOS 18.1 UA (`apps-foot.png`): the Apps tab ends with "iPhone, iOS 18.1, sidedrop (en-us)"
  and "9dc9923".

## Not verified

- On a real iPhone, in Safari or the Home Screen app: not run (no phone in this unattended session).
- The About alert's look. In the screenshot I unhid it by editing the HTML, so it is caught mid-fade. Its two lines
  are there, but I didn't judge their contrast in the open alert.
- `docker build` with the new ARG, and deploy.sh on the NAS: not run here. No Docker build in the task's scope, and
  the NAS picks it up on its next cron after merge.
- Dark theme colours of `.ver`: they use the same `--head`/`--emboss` variables as `.ftr`, but I didn't take a screenshot.
