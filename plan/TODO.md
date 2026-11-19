# TODO — open tasks, in order

### Next

- [ ] **D2** Redo the README and the repo page with the readme skill (~/.claude/skills or the 'readme' skill: run it in direct mode, no interview), for SideDrop (after the rename task): what it is (share your developer certificate, friends register their iPhone once and install your apps), screenshots like iFizBox's README (~/repos/iFizBox/README.md and docs/img/: phone-sized PNGs with a caption each) taken from a local run with headless Chromium at 390x844 and demo data (a few apps, a registered device; nothing from the real server, no real names, domains or UDIDs) into docs/img/: Apps, Changes, an app install, Settings, Manage, iPhones, Signing, the setup splash. Then the quick start (docker compose, the first-run splash, the API key), what the admin can do, limits, and links to docs/developer-account.md. Also set the GitHub repo's description and topics to match (gh repo edit as RyanAHayden, not FIZL0: GH_TOKEN=$(gh auth token -u RyanAHayden)). Check: every image the README links exists; no secrets or personal data in the images. | files: README.md, docs/** | after: F17 — reopened: F17 landed
### Parked

- [ ] **F8** (follow-up, later) Dark Mode as iFizBox's OLED Black (its default dark palette since F198, 2026-11-18): black ground, bars and tab bar, near-black tables, no pinstripe or emboss; gunmetal (sidedrop's current dark) kept or dropped as the user picks. Token values in ~/repos/iFizBox/web/app/ios6.css html[data-theme=dark]. Left out of F5 because it changes the whole dark look, not one control | files: app.py
