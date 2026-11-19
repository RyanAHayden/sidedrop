# Run your own SideDrop for friends

SideDrop shares your Apple developer account so your friends can sideload apps. This guide is for someone who
wants to run it for their own friends on their own server. It takes an
evening: most of it is Apple's paperwork, then a few minutes with Docker and a few on your iPhone.

You need:

- an Apple Developer Program membership ($99 a year)
- a computer that stays on (a home server, a NAS or a small VPS) with Docker and Docker Compose
- a domain name, or a free Cloudflare Tunnel or Tailscale Funnel address, for HTTPS
- your iPhone, for the first-run setup

## 1. Get an Apple Developer account

Two things, both in [developer-account.md](developer-account.md):

1. Join the Apple Developer Program (its step 1).
2. Make one App Store Connect API key with the **Admin** role (its step 2).

That's all you make by hand. When you're done you have:

| File or value | What it is |
| --- | --- |
| `AuthKey_<Key ID>.p8` | the App Store Connect API key; SideDrop uses it to make the certificate and App ID and to register iPhones |
| Issuer ID | shown above the list of API keys |
| App ID | the one you want, e.g. `com.yourname.sideload` (SideDrop makes it with Push) or `com.yourname.*` |

Put the key somewhere your iPhone can reach it, such as iCloud Drive, ideally in one `.zip` with a text file that
holds the Issuer ID:

```
apikey.zip
├── AuthKey_ABC123DEFG.p8
└── issuer.txt       the Issuer ID (a UUID)
```

Rather not give SideDrop an Admin key? Follow that guide's [Manual setup](developer-account.md#manual-setup)
instead: you make the certificate and App ID yourself, and add `cert.p12` and a `password.txt` with its password
under **Manual setup** in step 4 below.

## 2. Deploy with Docker Compose

On the server:

```sh
git clone https://github.com/<you>/sidedrop.git   # your fork, or the original
cd sidedrop
cp .env.example .env
mkdir -p data
sudo chown 568:568 data
```

The container runs as UID 568. If Docker creates `data/` itself it is owned by root, and SideDrop can't save
anything, so make it and `chown` it first.

Edit `.env` and set only `PUBLIC_URL` to the HTTPS address friends will open, e.g.
`PUBLIC_URL=https://apps.example.com`. Leave everything else empty; your iPhone fills it in.

```sh
docker compose up -d --build
```

SideDrop now listens on port 8080 on the server, over plain HTTP.

## 3. Put it behind HTTPS

iOS installs profiles and apps only over HTTPS with a real, trusted certificate. Plain HTTP, a self-signed
certificate or a bare IP address won't work. Pick one of these:

**Caddy (your own domain).** Point the domain's DNS at the server, open ports 80 and 443, and add a
`compose.override.yaml` next to `compose.yaml`:

```yaml
services:
  caddy:
    image: caddy:2
    restart: unless-stopped
    ports: ["80:80", "443:443"]
    command: caddy reverse-proxy --from apps.example.com --to sidedrop:8080
    volumes: ["caddy:/data"]
volumes:
  caddy:
```

`docker compose up -d` starts both. Caddy gets a Let's Encrypt certificate by itself. Any reverse proxy you already
run (nginx, Nginx Proxy Manager, Traefik) works the same way: send the domain to port 8080. Allow large uploads
and long requests: IPAs can be hundreds of MB, and the first signing can take minutes.

**Cloudflare Tunnel (no open ports).** In Cloudflare Zero Trust, make a tunnel, run its `cloudflared` on the server,
and route a hostname to `http://localhost:8080`. Cloudflare's free plan caps uploads at 100 MB, so big IPAs have to
go into `data/apps/` or come from a source rather than through **Sign your own IPA**.

**Tailscale Funnel (no domain).** `tailscale funnel 8080` gives you an `https://<machine>.<tailnet>.ts.net`
address that anyone can open.

Whichever you pick, `PUBLIC_URL` in `.env` must be exactly that address. If you change it, run
`docker compose up -d --force-recreate sidedrop` so the container picks it up. Open it in a browser: you should see the SideDrop sign-in page with
a padlock.

## 4. First-run setup on your iPhone

Do this right after deploying. Until it's done, anyone who finds the site can set it up with the default password.

1. Open `PUBLIC_URL` in Safari and sign in with the default password, **`sidedrop`**. It opens only the setup
   screen.
2. Choose a **password for friends** and a different **admin password** (8 characters or more; long passphrases are
   better). Both are saved hashed in `data/setup.json`.
3. Tap **Choose API Key** and pick `apikey.zip` (or the `.p8` alone). The Key ID is read from the `.p8`'s name and
   the Issuer ID from the text file. Check them, or type them in.
4. Fill in the **App ID** from step 1, e.g. `com.yourname.sideload`.
5. Tap **Save**. SideDrop makes the App ID (with Push) if your account lacks it, has Apple make an Apple
   Distribution certificate, and saves it as `data/cert.p12` with a random password. The default password stops
   working, and you're signed in.

If something is wrong (a key without the Admin role, a missing App ID), the screen says so. Files that were fine are
kept, so you don't need to pick them again. If your account already has as many distribution certificates as Apple
allows, the screen lists them: pick one you no longer use to revoke, and Save again. Apps signed with it stop opening
wherever they were signed, so SideDrop never picks one for you.

## 5. Register your own iPhone first

Before you invite anyone, go through it yourself as a friend would. Sign in with the friends' password, turn off
Stolen Device Protection, tap **Register iPhone**, install the profile, then install an app. Turn on Developer
Mode when iOS asks for it. If the app opens, SideDrop is working.

With the admin password, **Settings → Manage** lists every registered iPhone and can turn one off.

## 6. Add apps and invite friends

- Put `.ipa` files in `data/apps/`, or list AltStore sources in `mirror-sources.txt` (your own apps) and
  `third-party-sources.txt` (other people's). Changing the `*-sources.txt` files needs a rebuild:
  `docker compose up -d --build`.
- Send friends the address and the friends' password. They follow the same steps as you did in step 5.

## Keeping it running

- `git pull && docker compose up -d --build` updates SideDrop. `deploy.sh` does this from cron, but it is written for
  a TrueNAS custom app; on plain Docker, a cron job running those two commands does the same.
- Back up `data/`: it holds your certificate, the API key, the passwords and the list of registered iPhones.
- Each year: renew the membership, then tap **Settings → Manage → Make New Certificate** before the old certificate
  expires (on the manual path, make one yourself and upload it there). Apps stop opening when it does. iPhone slots
  (100 a year) free up at renewal.
- To change the passwords or signing files after setup, edit `.env` (it wins over the setup screen) and recreate the container as above, or
  delete `data/setup.json` to see the setup screen again. That also brings back the default password until you save,
  so do it right away.

## When it doesn't work

- **The sign-in page won't load over HTTPS, or iOS says the profile can't be installed**: the certificate isn't
  trusted, or `PUBLIC_URL` doesn't match the address you opened.
- **The container keeps restarting, or setup won't save**: `data/` isn't owned by UID 568
  (`sudo chown -R 568:568 data`). `docker compose logs sidedrop` shows the error.
- **Setup says the key needs the Admin role**: Apple refuses certificates to App Manager keys. Make an Admin key, or
  use the manual setup.
- **Register iPhone fails**: the API key's role must be Admin (or App Manager on the manual path), and the Key ID and
  Issuer ID must belong to it.
- Signing, installing and notifications: see [developer-account.md](developer-account.md#when-it-doesnt-work).
