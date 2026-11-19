# SideDrop

Share your Apple developer account and help your friends sideload apps. SideDrop is a password-protected site: friends register their iPhones with your account, and every app on it is signed for them.

1. A friend opens the site in Safari, types the password, turns off Stolen Device Protection (the page walks through it with screenshots from `static/`) and taps **Register iPhone**. They install the profile it downloads.
2. iOS sends the server the phone's UDID. The server registers the device with Apple, regenerates the ad hoc profile and re-signs every app.
3. Safari comes back to the site, where they tap **Install**.

Under **Sign your own IPA**, a logged-in friend can drop an IPA or paste a link to one and get an install link signed with the same profile (stored in `signed/custom/`, deleted after 7 days).

The **iFizBox** tab installs iFizBox (`https://ifizbox.com/source.json` in `mirror-sources.txt`) and says why to use it; the iFizBox row on **Apps** opens it and starts the install. It is signed with `cert.p12`, its password and the ad hoc profile inside it (`ifizbox-identity.plist`) and the sources in `ifizbox-sources.txt` (`web/transfer.link`), which it imports on first launch, so friends never have to pick a certificate or add a source. Anyone who installs it can pull the certificate out of the app. The install shows ifizbox.com's progress page, which follows iOS fetching the manifest and the app (`/install/<token>`).

Files in `appfiles/<ipa name>/` (e.g. `appfiles/io.github.fizl0.hst/`) are listed under that app's Install button. The links are signed, last 7 days, work without a login (so `wget`/`curl` can use them) and can be resumed.

The **Changes** tab lists apps by release date, Cydia style. Tapping INSTALL records that version for the phone (in `installed.json`), so newer versions show there under **Available Updates**, with a badge on the tab and an **Update** button that installs them all.

## Editing on GitHub

These files can be edited on github.com; a server running `deploy.sh` picks up changes within 5 minutes (the sources can also be changed on **Manage**, which then wins over the repo, below):

- `ifizbox-sources.txt`: the sources iFizBox starts with, one URL per line
- `mirror-sources.txt`: AltStore sources whose apps are downloaded, signed and listed
- `third-party-sources.txt`: the same for other people's apps, listed under **Third-party apps**; a URL, then the bundle IDs to take from it (none = all)
- `app.py`: everything else, including page text

`deploy.sh` is a pull-deploy for a TrueNAS custom app named `sidedrop`: run it from cron every few minutes in a clone of this repo. It rebuilds the `sidedrop:latest` image and redeploys only when `main` has changed; `deploy.sh -f` deploys right away.

The name people see is SideDrop. The lowercase `sidedrop` stays wherever a deployment or an installed iPhone depends on it: the repo, the Docker image and TrueNAS app, the `SIDEDROP_*` variables, the profile identifier `sidedrop.udid`, the ad hoc profile name (`PROFILE_NAME`) and the default password.

## Setup

Running SideDrop for your own friends for the first time? [docs/become-a-distributor.md](docs/become-a-distributor.md) goes from the Apple account through Docker Compose and HTTPS to the setup screen on your iPhone.

New to the developer account? [docs/developer-account.md](docs/developer-account.md): join the program, make one App Store Connect API key (role Admin) and upload it; SideDrop makes the certificate and the App ID with Push itself. Its **Manual setup** section makes them by hand instead, for a key that can't make certificates.

Everything lives in one data folder (`./data`, or `DATA_DIR`, in `compose.yaml`), which must be owned by UID 568:

```
asc.p8          App Store Connect API key (Users and Access → Integrations → Keys, role Admin; App Manager on the manual path)
cert.p12        Apple Distribution certificate + private key: made by SideDrop through the API, or yours (Keychain, openssl)
apps/*.ipa      unsigned or dev-signed IPAs to share (or list AltStore sources in mirror-sources.txt)
```

`signed/` and `adhoc.mobileprovision` are generated, and so are `setup.json` (the setup screen below) and `secret.key` (when `SECRET_KEY` is empty).

Copy `.env.example` to `.env` and set `PUBLIC_URL`. The rest can stay empty and be set up on your iPhone:

1. Start the server and open the site. While no password is set, sign in with the default password, **`sidedrop`**. It opens only the setup screen.
2. Set the password for friends and the admin password (they're saved hashed in `setup.json` in the data folder).
3. Tap **Choose API Key** and pick `AuthKey_<Key ID>.p8`, loose or in a `.zip` with a text file holding the Issuer ID. The Key ID comes from the `.p8`'s name and the Issuer ID from a UUID in the text file; check or fill in both, and the App ID (`BUNDLE_ID`).
4. **Save**. SideDrop makes the App ID if the account lacks it (explicit: with Push, App Groups and Associated Domains), makes a private key and CSR, has Apple issue an Apple Distribution certificate (`POST /v1/certificates`) and saves `cert.p12` with a random password in `setup.json`. If the account already has the most distribution certificates Apple allows, it lists them (name, made, expires) and the admin picks one to revoke, warned that apps signed with it anywhere stop opening; it never revokes one itself. Apple refuses certificates to keys without the Admin role, and the screen says so. Everything goes into the data folder, so it survives restarts, and the default password stops working.

**Manual setup** on the same screen takes today's files instead: `cert.p12` and a `password.txt` with its password (or type it), loose or in a `.zip`; the `.p12`'s password is tried from the text file. SideDrop then makes nothing with the key.

Anything set in `.env` wins over the setup screen, and with `PASSWORD` set there is no setup screen, so a server can be configured without an iPhone: put `asc.p8` and `cert.p12` in the data folder and fill in `.env`. An empty `SECRET_KEY` is made once and kept in `secret.key` in the data folder.

`BUNDLE_ID` can be a wildcard App ID, such as `com.you.*` (SideDrop makes it when it makes the certificate; on the manual path it must already exist in the developer portal). One profile then covers every app: apps whose bundle ID falls outside it are re-IDed at signing (`com.other.game` becomes `com.you.game`). Apps that need entitlements like push or App Groups won't work this way.

Or set `BUNDLE_ID` to an explicit App ID with Push Notifications (plus App Groups and Associated Domains) turned on, such as `com.you.sideload`. Every app is then signed under that one App ID but keeps its own bundle ID in Info.plist, which iOS doesn't check against the profile and registers for push with, so apps like YouTube get their developer's notifications. Apps signed under a wildcard before install again as separate apps; delete the old copies.

```
docker compose up -d --build
```

The grey version line at the bottom of Apps and Settings shows the commit when the image was built with it (the image has no `.git`): `SIDEDROP_COMMIT=$(git rev-parse --short HEAD) docker compose up -d --build`. `deploy.sh` passes it itself.

**HTTPS with a real certificate is required.** iOS won't install profiles or apps over plain HTTP or with a self-signed cert. Put the site behind a reverse proxy, Cloudflare Tunnel or `tailscale funnel 8080`, and set `PUBLIC_URL` to match.

With an admin password (from the setup screen or `ADMIN_PASSWORD`), sign in with it instead of the friends' password, on the sign-in screen or as `?password=<admin password>`, and **Settings → Manage** appears. Friends never see it. It can:

- list the account's iPhones with when each was added and last used, and disable or re-enable them. Apple has no API to delete a device: disabling takes it out of the profile so its apps stop opening, but its slot only frees up at renewal.
- upload **Files for friends**, listed under **Files** on everyone's Apps tab (kept in `files/` in the data folder; signed links like the app files). Picking files starts uploading them in the background, each with a progress row; leaving the page doesn't stop them.
- edit `mirror-sources.txt`, `third-party-sources.txt`, iFizBox's starting sources and its settings (a JSON object it imports on first launch). Edits are saved in `config/` in the data folder and win over the repo's files, which stay the defaults; **Use Default** goes back to them.
- replace the API key (**Choose API Key**), have Apple make a new certificate (**Make New Certificate**, with the same revoke list when the account is full), or upload your own under **Manual setup**. A new certificate gets a new profile and every app is signed again. A changed App ID is made if the account lacks it.
- change the friends' and the admin password (**Passwords**). A change signs out every iPhone signed in with the old password (old `?password=` links stop working too); the admin making it stays signed in. A password set in `.env` can be changed here as well, after a warning: the new one is saved hashed in `setup.json` as an override, with a hash of the `.env` value it replaced. If `.env` later holds a different value, `.env` wins again and the override is dropped; **Use .env Password** drops it by hand.
- make invite links (**Invite Friends**), each with Copy Link and Share. **Anyone with the link** (`/join/<token>`) signs in like the friends' password without holding it: it's signed with the friends' password version, so a password change with **Sign Out Everyone** stops old links, and **Make New Link** does too (sessions already made with it stay). A **One iPhone** link (`/invite/<token>`, optional name, kept in `invites.json`, unused ones expire after 7 days) signs a browser in as a guest who can register one iPhone: the first UDID uses it up and a second is refused, so a shared link can't fill the account. Afterwards it only signs in on that iPhone (its device cookie, or the browser session that registered it, which the Home Screen app copies when added). Guests install apps like friends but get 403 on Manage. The page lists these links as Not used, Used by (iPhone, date) or Expired; **Revoke** signs the guest out and leaves the iPhone registered (turn it off on iPhones).
- warn about the certificate at the top of the page: expiring within 30 days, revoked (Apple's OCSP), not in the account the API key belongs to, the ad hoc profile made for another certificate, `BUNDLE_ID` missing from the account or, if explicit, without Push Notifications. Apple's answers are kept for an hour. The same problems are logged at startup.

The setup screen and Manage refuse a `cert.p12` that can't sign: a wrong password, no private key in it, not an Apple Distribution certificate (a development one, say), or already expired.

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

List AltStore source URLs in `mirror-sources.txt`. SideDrop checks them hourly and on page load (at most once a minute), and downloads any new version into `apps/`. Point it at each repo's release asset, not a GitHub Pages copy: release assets update the moment a release is published, while Pages adds build time and a 10-minute CDN cache.

To have new releases downloaded and signed before anyone opens the page, set `SYNC_TOKEN` and have CI call `POST /sync` after a release. For example, as the last step of the workflow that publishes your AltStore source:

```yaml
      - run: curl -fsS -X POST -H "Authorization: Bearer $T" https://sidedrop.example.com/sync || echo "SideDrop unreachable, it'll catch up on its own"
        env: { T: "${{ secrets.SIDEDROP_SYNC_TOKEN }}" }
```

Then store `SYNC_TOKEN` from the server's `.env` as that repo's `SIDEDROP_SYNC_TOKEN` secret (`gh secret set SIDEDROP_SYNC_TOKEN`).

`/sync` returns 202 right away and does the work in the background. It returns 403 without the token.
