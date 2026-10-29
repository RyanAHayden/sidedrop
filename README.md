# sidedrop

A password-protected site for sharing ad hoc iOS apps and large files with friends.

1. A friend opens the site in Safari, types the password and taps **Register iPhone**. They install the profile it downloads.
2. iOS sends the server the phone's UDID. The server registers the device with Apple, regenerates the ad hoc profile and re-signs every app.
3. Safari comes back to the site, where they tap **Install**.

Files placed in `files/` show up as download links. The links are signed, last 7 days, work without a login (so `wget`/`curl` can use them) and can be resumed.

## Setup

Everything lives in one data folder (`/mnt/SSD/sidedrop` in `compose.yaml`), which must be owned by UID 568:

```
asc.p8          App Store Connect API key (Users and Access → Integrations → Keys, role Admin or App Manager)
cert.p12        Apple Distribution certificate + private key (export from Keychain, or openssl)
apps/*.ipa      unsigned or dev-signed IPAs to share
files/          anything you want downloadable
```

`signed/` and `adhoc.mobileprovision` are generated.

Copy `.env.example` to `.env` and fill it in. `BUNDLE_ID` must already exist in the developer portal. A wildcard such as `com.you.*` lets one profile cover every app, as long as the apps don't need entitlements like push or App Groups.

```
docker compose up -d --build
```

**HTTPS with a real certificate is required.** iOS won't install profiles or apps over plain HTTP or with a self-signed cert. Put the site behind a reverse proxy, Cloudflare Tunnel or `tailscale funnel 8080`, and set `PUBLIC_URL` to match.

## Limits

- Apple allows 100 iPhones per developer account per membership year. Removing a device only frees its slot at renewal.
- Ad hoc apps stop launching when the distribution certificate expires (1 year).
- Download speed is capped by your home upload bandwidth. Cloudflare's free plan won't cache files this large.

## Test

```
python test_app.py
```
