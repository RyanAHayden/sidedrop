# F30: setup and invite links open straight into setting up the iPhone

## What I did

- The setup links a person is given, and what each did before:
  - the friends' `?password=` link
  - **Anyone with the link** (`/join/<token>`)
  - the **One iPhone** invite (`/invite/<token>`)

  Each signed the browser in and redirected to `/`: Home with **Set up this iPhone** folded, so the person had to find
  and tap the tile.
- Now they redirect to `SETUP_LINK = "/?go=setup"`. With `go=setup` and an unregistered iPhone, `home()` draws
  `#setup` unhidden and the tile `aria-expanded=true`. Step 1 (Stolen Device Protection, `<details open>`) is first.
  If this browser already ticked step 1 (`localStorage.sdp`), the existing script folds it and step 2 is ready, as on
  any other load. A registered iPhone has no setup panel, so the parameter does nothing there.
- The page's script swaps `?go=setup` out of the address bar (`history.replaceState` to `/` plus the hash). That way a
  Home Screen icon added afterwards, or a reload, is plain `/`. The manifest's `start_url` is `/` anyway.
- `refreshIn()` (pull to reload, and every refresh after marking an install) replaces `#t-apps` with a fresh `/`, which
  draws the steps folded. It now reopens them if they were open. Before this change, steps opened by hand also folded
  on a pull to reload.
- Decisions:
  - The admin's own `?password=` link still goes to `/`. It's the admin's sign-in, not a link given to someone to set
    up a phone, and several tests rely on it.
  - The typed password form (POST `/login`) still goes to `/`. The task is about links. A friend typing the password
    still sees the orange **Set up this iPhone** tile.
  - A friend or the admin already signed in who opens a join or invite link goes to `/?go=setup` too. They stay who
    they are, as F16 decided, but see what the link shows.
- test_app.py:
  - The redirect locations in the old link and invite tests are now `/?go=setup`.
  - A new F30 block: in a fresh client, each of the three link kinds lands, following redirects, on `/?go=setup` with
    the panel open and step 1 before step 2. A later plain `/` has it folded. The page carries the `replaceState`. The
    admin link stays on `/`. A registered iPhone's `/?go=setup` has no panel.

## Tried and failed

- The first edit added a second `aria-expanded` attribute to the tile instead of changing the first. HTML keeps the
  first one, so it would have stayed `false`. I caught it before running anything and changed the existing attribute.

## Not verified

- I didn't try it in a real browser or on an iPhone. No phone or browser automation is part of this unattended run,
  and the gate is Flask's test client, which runs no JavaScript. Not checked:
  - that `replaceState` cleans the address bar in iOS Safari;
  - that the open panel sits in view under the header tiles without scrolling (I added no scroll);
  - that the panel stays open after a pull to reload.

  The server-side half (the panel drawn open) is what the tests check.
