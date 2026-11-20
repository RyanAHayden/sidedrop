# B13: GitHub tile links to the repo

The GitHub tile on the welcome screen (app.py:1161) now links to https://github.com/RyanAHayden/sidedrop instead of the
profile. The "by Ryan Hayden (Fizlo)" byline on line 1159 still links to https://github.com/RyanAHayden. grep confirms
both hrefs.

The first gate run failed: test_app.py:105 (F17) asserts no lowercase "sidedrop" appears in the page, since the visible
name is "SideDrop". The repo URL is in an href, not text a person reads, so the test now strips that exact href before
checking, the same way it already exempts `sidedrop.udid` and `/static/` paths. I also added a B13 assert that the tile
links to the repo and the byline still links to the profile.

**Not verified**: the welcome screen wasn't opened in a browser or on a phone; it's a one-attribute href change, and the
test gate covers the rest.
