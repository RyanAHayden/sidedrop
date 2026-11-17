# sidedrop

A password-protected site for sharing ad hoc iOS apps and large files with friends.

1. A friend opens the site in Safari, types the password, turns off Stolen Device Protection (the page walks through it with screenshots from `static/`) and taps **Register iPhone**. They install the profile it downloads.
2. iOS sends the server the phone's UDID. The server registers the device with Apple, regenerates the ad hoc profile and re-signs every app.
3. Safari comes back to the site, where they tap **Install**.

Under **Sign your own IPA**, a logged-in friend can drop an IPA or paste a link to one and get an install link signed with the same profile (stored in `signed/custom/`, deleted after 7 days). A **Feather** menu links to the Feather on-device signer. Feather's own repo is in `mirror-sources.txt`, so a signed Feather install shows up there, next to the sources in `feather-sources.txt` with a **Copy sources** button.

Files in `appfiles/<ipa name>/` (e.g. `appfiles/io.github.fizl0.hst/`) are listed under that app's Install button instead, with the same kind of signed link.

Files placed in `files/` show up as download links. The links are signed, last 7 days, work without a login (so `wget`/`curl` can use them) and can be resumed.

## Editing on GitHub

These files can be edited on github.com. The NAS picks up changes within 5 minutes:

- `feather-sources.txt`: sources shown in the Feather menu, one URL per line
- `mirror-sources.txt`: AltStore sources whose apps are downloaded, signed and listed
- `third-party-sources.txt`: the same for other people's apps, listed under **Third-party apps**; a URL, then the bundle IDs to take from it (none = all)
- `app.py`: everything else, including page text

`deploy.sh` runs from a TrueNAS cron job every 5 minutes, in a clone at `/mnt/SSD/sidedrop/repo` that uses a read-only deploy key. It rebuilds and redeploys only when `main` has changed. To deploy right away: `ssh truenas sudo /mnt/SSD/sidedrop/repo/deploy.sh -f`.

## Setup

Everything lives in one data folder (`/mnt/SSD/sidedrop` in `compose.yaml`), which must be owned by UID 568:

```
asc.p8          App Store Connect API key (Users and Access → Integrations → Keys, role Admin or App Manager)
cert.p12        Apple Distribution certificate + private key (export from Keychain, or openssl)
apps/*.ipa      unsigned or dev-signed IPAs to share (or list AltStore sources in mirror-sources.txt)
files/          anything you want downloadable
```

`signed/` and `adhoc.mobileprovision` are generated.

Copy `.env.example` to `.env` and fill it in. `BUNDLE_ID` must be a wildcard App ID that already exists in the developer portal, such as `com.you.*`. One profile then covers every app: apps whose bundle ID falls outside it are re-IDed at signing (`com.other.game` becomes `com.you.game`). Apps that need entitlements like push or App Groups won't work this way.

```
docker compose up -d --build
```

**HTTPS with a real certificate is required.** iOS won't install profiles or apps over plain HTTP or with a self-signed cert. Put the site behind a reverse proxy, Cloudflare Tunnel or `tailscale funnel 8080`, and set `PUBLIC_URL` to match.

## Limits

- Apple allows 100 iPhones per developer account per membership year. Removing a device only frees its slot at renewal.
- Ad hoc apps stop launching when the distribution certificate expires (1 year).
- Ad hoc apps need Developer Mode turned on, once per phone (iOS 16+; only App Store, TestFlight and enterprise apps are exempt). The page explains how.
- Download speed is capped by your home upload bandwidth. Cloudflare's free plan won't cache files this large.

## Test

```
python test_app.py
```

## Auto-updating apps from GitHub releases

List AltStore source URLs in `mirror-sources.txt`. sidedrop checks them hourly and on page load (at most once a minute), and downloads any new version into `apps/`. Point it at each repo's release asset, not a GitHub Pages copy: release assets update the moment a release is published, while Pages adds build time and a 10-minute CDN cache.

To have new releases downloaded and signed before anyone opens the page, set `SYNC_TOKEN` and have CI call `POST /sync` after a release. For the FIZL0 apps, add this as the last step of `FIZL0/apps` `.github/workflows/source.yml`, which the apps' release scripts already trigger:

```yaml
      - run: curl -fsS -X POST -H "Authorization: Bearer $T" https://sidedrop.example.com/sync || echo "sidedrop unreachable, it'll catch up on its own"
        env: { T: "${{ secrets.SIDEDROP_SYNC_TOKEN }}" }
```

Then store the token as a repo secret. The token is in `/mnt/SSD/sidedrop/.env` on the NAS:

```
ssh truenas sudo grep ^SYNC_TOKEN= /mnt/SSD/sidedrop/.env | cut -d= -f2 | gh secret set SIDEDROP_SYNC_TOKEN -R FIZL0/apps
```

`/sync` returns 202 right away and does the work in the background. It returns 403 without the token.
