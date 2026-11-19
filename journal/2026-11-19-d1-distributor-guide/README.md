# D1: "Run your own sidedrop" guide

## Decision: guide only

sidedrop already has everything a new distributor needs. F1 added the first-run setup on the phone (default
password `sidedrop`, then the passwords, signing files and App ID are saved in the data folder). `compose.yaml`
builds and runs the app, and `docs/developer-account.md` covers the Apple side. The one rough spot is that Docker
creates a missing `./data` as root, while the image runs as UID 568. The guide handles it with
`mkdir data && sudo chown 568:568 data` before the first `up`. No code change, and nothing filed: a doc step covers it.

## What I did

- `docs/become-a-distributor.md`, a new file in six steps:
  1. The Apple account, linking developer-account.md steps 1–4. It skips that guide's step 5 because the phone
     setup does it, and suggests a `signing.zip` with `password.txt` holding the p12 password and the Issuer ID.
  2. Clone, `.env` with only `PUBLIC_URL`, chown `data/`, `docker compose up -d --build`.
  3. HTTPS: Caddy through a `compose.override.yaml`, Cloudflare Tunnel (with its 100 MB upload cap), or Tailscale
     Funnel.
  4. First-run setup on the iPhone. I checked each step against `setup()` in app.py: 8-character minimum,
     different passwords, files guessed from the zip, files that were fine kept on error, signed in after Save.
  5. Register your own iPhone first.
  6. Add apps and invite friends.
  Then upkeep (updates, backups, yearly certificate, redoing setup by deleting `setup.json`) and troubleshooting.
- README Setup: one line linking the guide.

## Tried that failed

Nothing.

## Not verified

- I did not run the Caddy `compose.override.yaml` or `caddy reverse-proxy --from … --to sidedrop:8080`: there is no
  public domain or open ports in this unattended run. The snippet follows Caddy's documented CLI and image.
- I did not test that `docker compose up -d --force-recreate` picks up a changed `.env`. The flag recreates the
  container whatever compose decides, and the guide says to use it for that reason.
- I did not run the whole flow end to end: no Apple account, phone or domain here. Cloudflare Tunnel and Tailscale
  Funnel steps come from their documentation and were not tried.
- The claim that a root-owned `data/` breaks saving follows from `USER 568:568` in the Dockerfile. I did not run it.
