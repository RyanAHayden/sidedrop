# Configuration reference

The README covers the usual setup: `PUBLIC_URL` in `.env`, then the setup screen on your iPhone. This page has the
rest: every `.env` variable, the App ID choice, the data folder, editing from GitHub and auto-updating apps.

## `.env`

Copy `.env.example`. Only `PUBLIC_URL` is required; the setup screen covers the rest. Anything set in `.env` wins over
the setup screen, and with `PASSWORD` set there is no setup screen.

| Variable | What it is |
| --- | --- |
| `PUBLIC_URL` | The site's `https://` address, as iPhones reach it. |
| `PASSWORD` / `ADMIN_PASSWORD` | The friends' and the admin password. Set here, the setup screen is skipped. Manage → Passwords can override them until `.env` changes. |
| `SECRET_KEY` | Signs sessions and links. Empty: made once and kept in `data/secret.key`. |
| `ASC_KEY_ID` / `ASC_ISSUER_ID` | The App Store Connect API key's IDs (the key itself is `data/asc.p8`). |
| `BUNDLE_ID` | The App ID every app is signed under ([below](#bundle_id)). |
| `P12_PASSWORD` | The password of `data/cert.p12`, if you brought your own. |
| `SYNC_TOKEN` | Lets CI call `POST /sync` after a release ([below](#auto-updating-apps-from-github-releases)). |
| `PROFILE_CERT_DIR` | A folder with `fullchain.pem` and `privkey.pem`; the registration profile is then signed and iOS shows it as Verified. |
| `DATA_DIR` | Where Compose mounts the data folder from (default `./data`). It must be owned by UID 568. |

### Setting it up without an iPhone

Put `asc.p8` and `cert.p12` in the data folder and fill in `PASSWORD`, `ADMIN_PASSWORD`, `ASC_KEY_ID`,
`ASC_ISSUER_ID`, `BUNDLE_ID` and `P12_PASSWORD` in `.env`.

## `BUNDLE_ID`

Either an explicit App ID with Push Notifications, such as `com.you.sideload` (recommended: apps keep their own
bundle ID in Info.plist and only the entitlements carry the App ID, so push works; SideDrop gives the App ID every
capability Apple's API accepts, listed in [developer-account.md](developer-account.md#capabilities), and makes the
profile again when it adds one), or a wildcard such as `com.you.*`, which
re-IDs apps outside it (`com.other.game` becomes `com.you.game`) and can't carry entitlements like push. Apps signed
under a wildcard install again as separate apps after a switch.

## The data folder

```
asc.p8          App Store Connect API key (role Admin; App Manager on the manual path)
cert.p12        Apple Distribution certificate + private key, made by SideDrop or yours
apps/*.ipa      unsigned or dev-signed IPAs to share
appfiles/<app>/ files listed under that app's Install button (labels.txt: "file = label" per line)
files/          Files for Friends, uploaded on Manage
config/         Manage's edits of the source lists
```

`signed/`, `adhoc.mobileprovision`, `setup.json`, `secret.key` and the JSON state files are generated.

The grey version line at the bottom of Apps and Settings shows the commit the image was built from, when built with
`SIDEDROP_COMMIT=$(git rev-parse --short HEAD) docker compose up -d --build`.

## Apps, sources and files

- **Your IPAs**: drop them in `data/apps/`; they're signed on the next page load.
- **AltStore sources**: list source URLs in `mirror-sources.txt`; their apps are downloaded, signed and listed, and
  checked hourly and on page load (at most once a minute).
- **Other people's apps**: `third-party-sources.txt`, a source URL followed by the bundle IDs to take from it (none
  means all); listed under **Third-party apps**.
- **iFizBox**: `https://ifizbox.com/source.json` is in `mirror-sources.txt`. It's signed with your `cert.p12`, its
  password, the ad hoc profile and the sources in `ifizbox-sources.txt`, which it imports on first launch, so friends
  never pick a certificate or add a source.
- **App files**: files in `data/appfiles/<ipa name>/` show under that app's Install button, with signed links that
  last 7 days, work without a login and can be resumed.
- **Sign IPA**: a signed-in friend's own IPA, kept in `signed/custom/` for 7 days.

Manage → App Sources and Manage → iFizBox edit the source lists and iFizBox's settings; those edits are kept in
`data/config/` and win over the repo's files until **Use Default**.

## Editing from GitHub and `deploy.sh`

These repo files can be edited on github.com; a server running `deploy.sh` picks up changes within 5 minutes (edits
made on Manage win over them): `ifizbox-sources.txt`, `mirror-sources.txt`, `third-party-sources.txt`, and `app.py`
for everything else, including page text. `deploy.sh` is a pull-deploy for a TrueNAS custom app named `sidedrop`: run
it from cron in a clone of this repo; it rebuilds `sidedrop:latest` and redeploys only when `main` changed (`-f` deploys
right away).

## Auto-updating apps from GitHub releases

Point `mirror-sources.txt` at each repo's release asset, not a GitHub Pages copy (Pages adds build time and a 10-minute
CDN cache). To have new releases signed before anyone opens the page, set `SYNC_TOKEN` and have CI call `POST /sync`
after a release, for example as the last step of the workflow that publishes your AltStore source:

```yaml
      - run: curl -fsS -X POST -H "Authorization: Bearer $T" https://sidedrop.example.com/sync || echo "SideDrop unreachable, it'll catch up on its own"
        env: { T: "${{ secrets.SIDEDROP_SYNC_TOKEN }}" }
```

Store `SYNC_TOKEN` from the server's `.env` as that repo's `SIDEDROP_SYNC_TOKEN` secret (`gh secret set
SIDEDROP_SYNC_TOKEN`). `/sync` returns 202 right away and works in the background; 403 without the token.

## Manage, in more detail

Sign in with the admin password instead of the friends' one, on the sign-in screen or as
`?password=<admin password>`, and **Settings → Manage** appears.

- **iPhones**: Apple has no API to delete a device. Turning one off takes it out of the profile so its apps stop
  opening, but its slot only frees up at renewal.
- **Signing**: replace the API key, have Apple make a new certificate (if the account already has the most Apple
  allows, it lists them and you pick one to revoke; SideDrop never revokes one itself), or upload your own `cert.p12`
  under **Manual**. A new certificate gets a new profile and every app is signed again. Manage warns at the top when
  the certificate expires within 30 days, is revoked (Apple's OCSP), isn't in the API key's account, the profile was
  made for another certificate, or `BUNDLE_ID` is missing or lacks Push. A `cert.p12` that can't sign (wrong password,
  no private key, not Apple Distribution, or expired) is refused.
- **Passwords**: a change signs out every iPhone signed in with the old one, and old `?password=` links stop working.
- **Invite Friends**: **Anyone with the link** (`/join/<token>`) signs in without the password; **Make New Link** or
  a password change stops it. A **One iPhone** link (`/invite/<token>`) registers exactly one iPhone, so a shared link
  can't fill the account; unused ones expire after 7 days.
- **Files for Friends**: signed links work without a login (`wget`, `curl`) for 7 days. Uploads keep going while you
  use the rest of SideDrop.
