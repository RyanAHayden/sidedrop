# T1 docs/readme_shots.py after C2

C2 removed install tracking, update rows and web push, so `docs/readme_shots.py` crashed on `A.INSTALLED` and would
then have failed on the `#t-apps .row.up` scroll.

What changed in `docs/readme_shots.py`:
- dropped the `A.INSTALLED` seed (the demo iPhone now only gets SEEN, FIRST_RUN and its product);
- dropped the scroll to Trailhead's update row: the Apps shot is the top of the tab (welcome card, iFizBox card,
  the first apps with GET);
- dropped the `localStorage.pushAsked` init script (no notifications prompt exists any more);
- recaptioned apps.png "every app, one tap to install" (was "your apps and their updates").

Ran the script with the iOS 27 kit from ~/repos/iFizBox and /usr/bin/chromium: all of docs/img was rewritten. apps.png
now shows only GET / INSTALL buttons, no UPDATE row or badge (looked at it). install.png, settings.png, manage.png,
invites.png and crop-signing.png also changed bytes: they follow the current app and today's dates (the
invite link is random each run); looked at install.png and settings.png, both fine. Kept them all, since they are what
the script makes now.

Nothing failed along the way.

**Not verified**: manage.png, invites.png and crop-signing.png were not opened one by one after regenerating (only
byte changes seen; same script, no code touching them changed). README.md's alt texts were not edited (outside this
task's files); they already say nothing of updates.
