# F17: rename to SideDrop, and copy about what it's for

## What I did
- **Name**: every name a person sees is now `SideDrop`. In `app.py` that covers the `<title>`, `og:title`/`og:site_name`, `apple-mobile-web-app-title`,
  the nav, the Apps tab's `data-title` and "Welcome to SideDrop", About, the F15 version line (server and JS), "Open SideDrop from there"
  (twice), the push prompt, the iFizBox install console, `page()`'s default title, the "from SideDrop" source on Changes, the setup splash
  (its intro and "Set Up SideDrop"), the manual steps, LIMIT_ERR, "SideDrop's certificate" in the picker, the "Couldn't reach SideDrop"
  errors (Manage iPhones, Files upload), the Files upload note, the manifest `name`/`short_name`, the mobileconfig `PayloadOrganization`/
  `PayloadDisplayName` and its download filename, and the App ID name SideDrop gives Apple when it makes one. README.md and both docs say
  SideDrop in their prose too.
- **Copy**: one line, used for the meta and og descriptions and the manifest (which gained a `description`): "Share an Apple developer account
  with friends and sideload apps." Short and plain, and it reads right both to the owner and to a friend opening a shared link. Variations
  of it go where each reader is:
  - Apps header (friends): a footnote under the tiles, "Sideload apps on your iPhone with a friend's Apple developer account." I kept the
    F7 header (Welcome / by …) as it was, because a third line in it would have pushed the icon out of line.
  - About: "SideDrop shares one Apple developer account with friends, so everyone can sideload apps. Register your iPhone once in Safari, then tap GET."
  - Setup splash (the owner): "Welcome to SideDrop. Share your Apple developer account and help your friends sideload apps. …", which is the brief's line.
  - Register step: "This adds your iPhone to the shared developer account, so the apps here can be signed for it." comes before the old re-register hint.
  - Help: a footnote under its group (`id=helpNote`) about the friend's certificate and Developer Mode.
  - Sign-in page, only when setup is already done (a new server keeps its default-password hint): "SideDrop shares an Apple developer account
    with friends so they can sideload apps. The friend who sent you the link has the password." I added this beyond the brief's list because
    the sign-in page is the first thing a friend sees.
  - README intro and the distributor guide's opening use the brief's line.
- **Kept lowercase** (identifiers): repo, `sidedrop:latest`, TrueNAS app, compose service (`--to sidedrop:8080`, `logs sidedrop`), `SIDEDROP_*`
  env vars, `PayloadIdentifier` `sidedrop.udid`, `PROFILE_NAME` default `sidedrop adhoc` (it looks up the existing Apple profile by name, so
  changing it would make a second profile on every deployment), the CSR/p12 CN and friendly name, `PUBLIC_URL` examples, and the
  **default password `sidedrop`**. That last one is something a person types, but it's a credential that the docs, `.env.example` and
  existing half-set-up servers all expect. A capitalised password would be easy to mistype, too. The README now lists what stays lowercase and why.
- **Art**: `icon.svg`/`icon.png` have no words and keep the F6 amber arrow, so I left them alone. `static/og.png` had "sidedrop" in its nav and
  title and the old tagline, so I redrew those with `og.py` here (`python og.py static/og.png`). It paints the old words out with copies of
  the card's own background: the nav gradient is the same in every column and the pinstripes the same in every row. It then draws "SideDrop"
  and the new two-line tagline in Liberation Sans, at the sizes, positions and colours measured from the old card (title #14161a with a white
  line under it, tagline #4c566c bold). The tagline shrank from 42 to 38 px so it fits.
- **Tests** (`test_app.py`): the old string checks now use SideDrop, and new asserts check the title, nav, About, the description (meta + og),
  og:site_name, the header line, About copy, register copy, Help note, the sign-in line, the manifest name/short_name/description, the
  mobileconfig display name/organization, and that `PayloadIdentifier` is still `sidedrop.udid`. There's also a grep-style assert: the
  signed-in Apps page has no `sidedrop` except `sidedrop.udid` and `/static/` paths.

## Checks
- Gate: `uv run -q --no-project --with-requirements requirements.txt python test_app.py` prints `ok`.
- `grep -rn sidedrop app.py README.md docs .env.example`: only the identifiers listed above (and two code comments) are left.
- Screenshots: headless Chromium, 390×844 at 2×, from `ui.py` here (`python ui.py <repo> <dir> friend|setup`, with a scratch data folder and
  Apple stubbed):
  - `apps.png`: the Apps tab, not registered.
  - `about.png`: About.
  - `setup.png`: the first-run setup splash.
  - `apps-register.png`: the register step.
  - `help.png`: the Help note.
  - `signin.png`: the sign-in page.
  - I also looked at the new `static/og.png` at full size.

## Tried and failed
- The first og.py guessed the old tagline's ink height (42 px) instead of measuring it (39 px). I measured the rows and fixed it before saving.

## Not verified
- Real iPhone: the Home Screen name from the manifest and `apple-mobile-web-app-title`, and the profile's name in Settings → Profile
  Downloaded. Not checked because this unattended run has no device session and must not deploy. Phones that already added the Home Screen icon
  keep the name "sidedrop" until they add it again. iOS reads the title only when the icon is added.
- Link previews (iMessage, Discord) with the new og.png and description: they need a deploy, and their caches keep the old card for a while.
- Dark mode screenshots: not taken. The copy changes use existing `.ftr`/`small` styles that dark mode already covers.
- Manage pages rendered in a browser: not screenshotted. Their only name strings ("SideDrop's certificate", "Couldn't reach SideDrop",
  the Files note) are covered by test asserts or are plain text swaps.
