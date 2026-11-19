# D2: README and repo page redone with the readme skill

## What I did
- Ran the `readme` skill in direct mode (no interview). Unattended, so its Phase 4 approval gate and the overwrite
  question were decided here: README.md is overwritten in place (the old one is in git), English only, no
  `.readme-checkpoint-*.md` files left in the repo (the skill deletes them at the end anyway; I kept the analysis in
  my head rather than writing them into the worktree, so nothing stray could be committed).
- **README.md** rebuilt around what SideDrop is: centred icon, title, one-line pitch, static badges (the repo is
  private, so shields' repo badges would 404), three hero shots, a NOTE about ad hoc limits and the shared
  certificate, contents, What it is (the three registration steps, then the tabs), a Mermaid flow (marked
  experimental, per the skill), Screenshots (a 4×2 table, each phone-sized image with a bold caption under it, like
  iFizBox's More screenshots), Quick start (API key → `docker compose` → the first-run splash with the default password
  → register your own iPhone), What the admin can do (one table row per Manage page), Configuration (`.env` table,
  `BUNDLE_ID` explicit vs wildcard, the data folder), Apps/sources/files (incl. GitHub editing, `deploy.sh`, `/sync`),
  Limits, Development (test gate, screenshot command, layout), License. Links to docs/developer-account.md and
  docs/become-a-distributor.md in the Quick start, the TIP and the layout table. All facts from the old README were
  kept or tightened; cross-checked against app.py (env names, `DEFAULT_PASSWORD`, invite paths, Manage pages,
  labels.txt format `file = label`, UID 568, port 8080).
- **docs/readme_shots.py**: makes the 8 screenshots. It imports app.py with demo env, stubs `asc`, `regen_profile`,
  `sign_ipa` (copy) and the cert checks, writes a self-signed fake "Apple Distribution: Demo Developer (DEMO123456)"
  p12, six tiny fake IPAs with SVG data-URI icons (iFizBox uses its public icon from ~/repos/iFizBox if present),
  four fake devices with `00008xxx-000DEMO…` UDIDs, an older Trailhead installed (so Changes has an update), a file
  beside Retro Arcade, a Files-for-Friends file. Serves on 127.0.0.1 with werkzeug and shoots with Playwright on
  /usr/bin/chromium at 390×844 @3x, iPhone UA. The setup splash needs `ENV_SET` empty at import, so the script
  re-runs itself in a fresh process with `setup` for that one.
- **docs/img/**: apps, changes, install, settings, manage, iphones, signing, setup (1170×2532 PNGs, 2.2 MB total).
- **GitHub repo page** (as RyanAHayden via `GH_TOKEN=$(gh auth token -u RyanAHayden)`): description "Share your Apple
  developer account: friends register their iPhone once and install the apps you share, ad hoc signed for them.
  Self-hosted, Docker Compose." and topics ios, sideloading, sideload, ipa, ad-hoc, app-store-connect, altstore,
  code-signing, flask, docker-compose, self-hosted. Read back with `gh repo view`: both set.

## What failed on the way
- First run: the notifications prompt (`pushAsk`, shown on #changes) covered the page and blocked the GET click.
  Fixed with an init script setting `localStorage.pushAsked=1`.
- Toggling `A.PASSWORD = ""` at runtime for the splash wasn't enough: the splash hides every field `.env` set
  (`ENV_SET`, computed at import), so it showed no password fields and an open Manual setup. Hence the second process.
- `labels.txt` first written as `name: label`; the format is `name = label`.

## Checks
- Every `src`/`href`/`](…)` target in README.md exists (script over the links: 12 ok, 0 missing); the anchors match
  headings.
- Looked at all 8 images: only demo data (example.com, DEMO IDs, made-up names Alex/Jordan/"Demo iPhone"). The one
  real name visible is the app's own hard-coded credit "by Ryan Hayden (Fizlo)" on the Apps header, which is the
  project's public author line, not server data.

## Not verified
- How the README renders on github.com (Mermaid block, the image table, alerts): not previewed, since the repo is
  private and I didn't push anything but through `agent-runner done`. Check the repo page after the merge.
- The Quick start commands were not run end to end (`docker compose up` with a real Apple key): no Apple account in
  an unattended run. They match compose.yaml, Dockerfile and the previous README.
- No LICENSE file exists; the License section says none is chosen yet rather than inventing one.
